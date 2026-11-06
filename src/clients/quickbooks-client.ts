import dotenv from "dotenv";
import QuickBooks from "node-quickbooks";
import OAuthClient from "intuit-oauth";
import http from 'http';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import open from 'open';
import {
  armOAuthTimeout,
  assertSandboxEnvironment,
  failClosed,
  OAUTH_CALLBACK_TIMEOUT_MS,
  OAUTH_LOOPBACK_HOSTS,
  OAUTH_PORT,
  OAUTH_REDIRECT_URI,
  isLocalhostCallbackHost,
  isLoopbackRemoteAddress,
  readAndApplyTokenFile,
  SANDBOX_API_HOST,
  SANDBOX_ENVIRONMENT,
  statesMatch,
} from "./sandbox-policy.js";
import { withTokenLock } from "./token-lock.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Where the server reads .env at startup and persists rotated refresh tokens.
// Defaults to the installed module's ../../.env (dist/clients/ -> package root)
// so a host-spawned server with an unrelated cwd still finds it. Override with
// QUICKBOOKS_TOKEN_STORE_PATH (an absolute path) to point at a WRITABLE location.
// This is required whenever the module itself lives on a read-only filesystem —
// containers with a read-only root, Nix/immutable installs (see #63, where the
// default path can't be written) — and lets a per-tenant host keep each
// connection's rotated token in its own isolated path.
//
// NOTE: this value is resolved BEFORE dotenv loads the file below, so the
// override only takes effect when set in the host process env (e.g. the MCP
// server config's env block) — setting it inside .env has no effect. It must
// be absolute: a relative path would resolve against the host app's working
// directory, which is unpredictable (the exact failure the module-relative
// default exists to avoid).
const tokenStorePathOverride = process.env.QUICKBOOKS_TOKEN_STORE_PATH?.trim();
if (tokenStorePathOverride && !path.isAbsolute(tokenStorePathOverride)) {
  failClosed(
    `QUICKBOOKS_TOKEN_STORE_PATH must be an absolute path, got "${tokenStorePathOverride}"`
  );
}
const TOKEN_STORE_PATH =
  tokenStorePathOverride || path.join(__dirname, '..', '..', '.env');

// Refuse a non-sandbox process environment before the token file is read, so
// the file cannot change a production request into a startup.
try {
  assertSandboxEnvironment(process.env.QUICKBOOKS_ENVIRONMENT, 'the process environment');
} catch (err) {
  failClosed(err instanceof Error ? err.message : String(err));
}

// The token file may supply rotated credentials. It may not change the host
// or the tool policy. dotenv override:true used to let the file replace
// QUICKBOOKS_ENVIRONMENT and QUICKBOOKS_DISABLE_* after those had been read.
try {
  const raw = fs.readFileSync(TOKEN_STORE_PATH, 'utf8');
  if (typeof raw === 'string') {
    readAndApplyTokenFile(
      raw,
      process.env,
      (source) => dotenv.parse(source),
      `token file ${TOKEN_STORE_PATH}`
    );
  }
} catch (err) {
  const code = (err as NodeJS.ErrnoException)?.code;
  if (code === 'ENOENT') {
    /* No token file yet. Process environment was already checked. */
  } else if (code === 'QBO_SANDBOX_REQUIRED' || err instanceof Error && err.name === 'SandboxRefusal') {
    failClosed(err instanceof Error ? err.message : String(err));
  } else if (err instanceof Error && err.message.startsWith('Refusing to start')) {
    failClosed(err.message);
  } else if (code) {
    failClosed(`Refusing to start: cannot read token file ${TOKEN_STORE_PATH} (${code}).`);
  } else {
    throw err;
  }
}

process.env.QUICKBOOKS_ENVIRONMENT = SANDBOX_ENVIRONMENT;

const client_id = process.env.QUICKBOOKS_CLIENT_ID;
const client_secret = process.env.QUICKBOOKS_CLIENT_SECRET;
const refresh_token = process.env.QUICKBOOKS_REFRESH_TOKEN;
const realm_id = process.env.QUICKBOOKS_REALM_ID;
const environment = SANDBOX_ENVIRONMENT;
const redirect_uri = process.env.QUICKBOOKS_REDIRECT_URI || OAUTH_REDIRECT_URI;

if (!client_id || !client_secret || !redirect_uri) {
  failClosed(
    "QUICKBOOKS_CLIENT_ID and QUICKBOOKS_CLIENT_SECRET must be set in the process environment or the token file. Refusing to start."
  );
}

// ── QuickbooksClient ─────────────────────────────────────────────────────────
// Exported so handlers can call QuickbooksClient.getInstance() directly,
// which checks token freshness on every invocation rather than only at startup.

export class QuickbooksClient {
  private readonly clientId: string;
  private readonly clientSecret: string;
  private refreshToken?: string;
  private realmId?: string;
  private readonly environment: string;
  private accessToken?: string;
  private accessTokenExpiry?: Date;
  private quickbooksInstance?: QuickBooks;
  private oauthClient: OAuthClient;
  private isAuthenticating: boolean = false;
  private redirectUri: string;

  // Refresh 5 minutes before actual expiry to avoid edge cases
  private static readonly TOKEN_REFRESH_BUFFER_MS = 5 * 60 * 1000;

  // Shared in-flight refresh promise so that concurrent callers all await the
  // same network request rather than racing to use (and rotate) the refresh
  // token simultaneously.
  private refreshInFlight?: Promise<{ access_token: string; expires_in: number }>;

  // Shared in-flight authenticate promise. Guards the cold-start path so two
  // concurrent first callers cannot both pass the freshness check and both
  // invoke startOAuthFlow() / rebuild the QuickBooks instance.
  private authInFlight?: Promise<QuickBooks>;

  constructor(config: {
    clientId: string;
    clientSecret: string;
    refreshToken?: string;
    realmId?: string;
    environment: string;
    redirectUri: string;
  }) {
    if (config.environment !== SANDBOX_ENVIRONMENT) {
      throw new Error(
        `Refusing to construct QuickbooksClient for environment ${JSON.stringify(config.environment)}. ` +
          `This sandbox fork only uses ${SANDBOX_API_HOST}.`
      );
    }
    this.clientId = config.clientId;
    this.clientSecret = config.clientSecret;
    this.refreshToken = config.refreshToken;
    this.realmId = config.realmId;
    this.environment = SANDBOX_ENVIRONMENT;
    this.redirectUri = config.redirectUri;
    this.oauthClient = new OAuthClient({
      clientId: this.clientId,
      clientSecret: this.clientSecret,
      environment: this.environment,
      redirectUri: this.redirectUri,
    });
  }

  private isTokenExpiredOrExpiringSoon(): boolean {
    if (!this.accessToken || !this.accessTokenExpiry) return true;
    return this.accessTokenExpiry <= new Date(Date.now() + QuickbooksClient.TOKEN_REFRESH_BUFFER_MS);
  }

  // Read the refresh token currently persisted in the token store (.env by
  // default, or QUICKBOOKS_TOKEN_STORE_PATH). Used to pick up a rotation
  // performed by a SIBLING process before we attempt our own refresh: a host
  // may spawn this server more than once against the same store (e.g.
  // Claude Desktop and Claude Code simultaneously), and Intuit invalidates the
  // previous refresh token on every rotation — so a token loaded into memory at
  // startup can be silently superseded on disk by another process.
  private readPersistedRefreshToken(): string | undefined {
    try {
      // Parse with dotenv itself so the value is normalized identically to how
      // the in-memory token was loaded at startup — surrounding quotes stripped,
      // inline comments removed, optional `export ` prefix handled. A naive
      // slice would keep quotes/comments and could poison a valid token with a
      // value that only looks different.
      const parsed = dotenv.parse(fs.readFileSync(TOKEN_STORE_PATH));
      const value = parsed.QUICKBOOKS_REFRESH_TOKEN?.trim();
      return value || undefined;
    } catch {
      return undefined;
    }
  }

  // Distinguish a genuinely dead refresh token (revoked, expired, or rotated
  // out — Intuit answers HTTP 400 invalid_grant, or 401) from a transient
  // failure (5xx, 429, network timeout). Only the former warrants telling the
  // operator to re-authorize; a transient failure must stay retryable so it
  // self-heals. Conservative: anything not clearly an auth-invalidation is
  // treated as transient, so an outage never produces a false "re-authorize"
  // alarm.
  //
  // NOTE on shape: intuit-oauth 4.x does NOT surface invalid_grant in a tidy
  // field. Verified empirically against v4.2.1 — on a rejected refresh token
  // the error's message/error is the axios string "Request failed with status
  // code 400", error_description is "", authResponse.response is "" and
  // authResponse.status is a function returning undefined. So the reliably
  // available signal is the HTTP status embedded in that message; we also check
  // any structured fields in case a future version populates them.
  private isAuthInvalidation(error: unknown): boolean {
    // Walk the error's cause chain (bounded) so a wrapped error still classifies
    // correctly regardless of how many layers deep the real signal sits — our
    // own wrapper adds one level, and some axios versions attach a `cause`.
    let cur: unknown = error;
    for (let depth = 0; depth < 4 && cur != null; depth++) {
      if (this.classifyOneError(cur)) return true;
      cur = (cur as { cause?: unknown }).cause;
    }
    return false;
  }

  // Classify a SINGLE error object (no cause traversal — the caller walks the
  // chain). Returns true only for a genuine auth-invalidation.
  private classifyOneError(raw: unknown): boolean {
    const asObj = raw && typeof raw === "object" ? (raw as Record<string, unknown>) : null;

    // Explicit OAuth error fields, when populated.
    const errField = String(asObj?.error ?? "").toLowerCase();
    const errDesc = String(asObj?.error_description ?? "").toLowerCase();
    if (errField.includes("invalid_grant") || errDesc.includes("invalid_grant")) return true;

    // Numeric HTTP status from whichever field carries it (incl. intuit-oauth's
    // authResponse.status() accessor).
    let status: number | undefined;
    const ar = asObj?.authResponse as { status?: unknown; response?: { status?: unknown } } | undefined;
    if (ar) {
      if (typeof ar.status === "function") {
        try {
          const s = Number((ar.status as () => unknown)());
          if (!Number.isNaN(s)) status = s;
        } catch {
          /* accessor threw — fall through to message parsing */
        }
      } else if (typeof ar.status === "number") {
        status = ar.status;
      }
      if (status === undefined && ar.response && typeof ar.response.status === "number") {
        status = ar.response.status;
      }
    }
    if (status === undefined && typeof asObj?.status === "number") status = asObj.status as number;

    // Fallback: parse the axios-style message ("Request failed with status code
    // NNN") — the only signal intuit-oauth 4.x reliably exposes on invalid_grant
    // (its response body is discarded). The \b prevents a 4-digit number from
    // matching its 3-digit prefix.
    const message = (raw instanceof Error ? raw.message : String(raw ?? "")).toLowerCase();
    if (message.includes("invalid_grant")) return true;
    if (status === undefined) {
      const m = message.match(/status code (\d{3})\b/);
      if (m) status = Number(m[1]);
    }

    return status === 400 || status === 401;
  }

  // Single refresh network call. Returns the widened token object — the
  // intuit-oauth type declarations omit refresh_token, x_refresh_token_expires_in,
  // token_type, realmId, etc.
  private async performRefresh(refreshToken: string): Promise<{
    access_token: string;
    expires_in?: number;
    refresh_token?: string;
    x_refresh_token_expires_in?: number;
  }> {
    const authResponse = await this.oauthClient.refreshUsingToken(refreshToken);
    return authResponse.token as unknown as {
      access_token: string;
      expires_in?: number;
      refresh_token?: string;
      x_refresh_token_expires_in?: number;
    };
  }

  private assertSandbox(action: string): void {
    if (this.environment !== SANDBOX_ENVIRONMENT) {
      throw new Error(
        `Refusing to ${action}: this sandbox fork only contacts ${SANDBOX_API_HOST}.`
      );
    }
  }

  private async startOAuthFlow(): Promise<void> {
    this.assertSandbox('start QuickBooks OAuth');

    if (this.isAuthenticating) {
      return;
    }

    this.isAuthenticating = true;
    const port = OAUTH_PORT;

    // Intuit's developer UI accepts http://localhost:8000/callback and rejects
    // an IP literal. The sockets below are still loopback-only. The flow
    // ignores QUICKBOOKS_REDIRECT_URI so authorize and token exchange match.
    const flowClient = new OAuthClient({
      clientId: this.clientId,
      clientSecret: this.clientSecret,
      environment: SANDBOX_ENVIRONMENT,
      redirectUri: OAUTH_REDIRECT_URI,
    });

    return new Promise((resolve, reject) => {
      let settled = false;
      let cancelTimeout: () => void = () => {};
      const settle = (fn: () => void) => {
        if (settled) return;
        settled = true;
        cancelTimeout();
        fn();
      };

      // Guard against duplicate /callback requests. localhost may connect to
      // 127.0.0.1 and ::1, so the same code can arrive twice. Exchanging it
      // twice trips Intuit's replay protection and REVOKES the first tokens
      // (RFC 6749 §4.1.2). Only the first callback may exchange the code.
      let codeExchangeStarted = false;

      // Random per-run value, not guessable from the public repo. Bound to this
      // authorize request and checked against every callback before we exchange
      // anything, so a stranger who gets their own valid code for this client_id
      // (client IDs aren't secret) can't hijack the callback and have their
      // tokens written into our .env instead of ours.
      const expectedState = crypto.randomBytes(24).toString('hex');

      const servers: http.Server[] = [];
      const closeServers = () => {
        for (const openServer of servers) {
          try { openServer.close(); } catch { /* already closed */ }
        }
      };

      // Create temporary servers for the OAuth callback. One handler is shared.
      const onRequest = async (req: http.IncomingMessage, res: http.ServerResponse) => {
        const callbackPath = req.url?.split('?')[0] ?? '';
        console.log(`[auth-server] ${req.method} ${callbackPath}`);

        // Respond to anything that isn't /callback so diagnostic probes (curl,
        // favicon requests, etc.) don't hang the server.
        if (!req.url?.startsWith('/callback')) {
          res.writeHead(404, { 'Content-Type': 'text/plain' });
          res.end('Not Found. Waiting for QuickBooks OAuth callback at /callback');
          return;
        }

        // The socket must be loopback, and the Host header must be the
        // registered hostname. An IP Host or a public Host is rejected even
        // if it reached a loopback socket.
        if (!isLoopbackRemoteAddress(req.socket?.remoteAddress) || !isLocalhostCallbackHost(req.headers?.host)) {
          console.error('[auth-server] Rejected callback that was not addressed to localhost on a loopback socket');
          res.writeHead(403, { 'Content-Type': 'text/plain' });
          res.end('Forbidden.');
          return;
        }

        // Reject any callback whose state doesn't match this run's authorize
        // request, before touching codeExchangeStarted, so a spoofed/scanner
        // hit can't consume the one-shot exchange lock and lock out the real
        // callback that follows it.
        const incomingState = new URL(req.url, OAUTH_REDIRECT_URI).searchParams.get('state');
        if (!statesMatch(expectedState, incomingState)) {
          console.error('[auth-server] Rejected callback with mismatched or missing state');
          res.writeHead(400, { 'Content-Type': 'text/plain' });
          res.end('Invalid or missing state parameter.');
          return;
        }

        // A duplicate callback for the same code must NOT be exchanged again, or
        // Intuit revokes the token minted by the first hit. `codeExchangeStarted`
        // is set synchronously before the first `await`, so the second request's
        // handler observes it and bails out here.
        if (codeExchangeStarted) {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end('<html><body style="font-family:Arial;text-align:center;margin-top:20vh"><h2>Processing… you can close this window.</h2></body></html>');
          return;
        }
        codeExchangeStarted = true;

        {
          try {
            const response = await flowClient.createToken(req.url);
            const tokens = response.token;

            // Save tokens under the same file lock used for refresh rotation.
            this.refreshToken = tokens.refresh_token;
            this.realmId = tokens.realmId;
            await withTokenLock(TOKEN_STORE_PATH, async () => {
              this.saveTokensToEnv();
            });

            // Send success response
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(`
              <html>
                <body style="
                  display: flex;
                  flex-direction: column;
                  justify-content: center;
                  align-items: center;
                  height: 100vh;
                  margin: 0;
                  font-family: Arial, sans-serif;
                  background-color: #f5f5f5;
                ">
                  <h2 style="color: #2E8B57;">✓ Successfully connected to QuickBooks!</h2>
                  <p>You can close this window now.</p>
                </body>
              </html>
            `);

            // Close server after a short delay
            setTimeout(() => {
              settle(() => {
                closeServers();
                this.isAuthenticating = false;
                resolve();
              });
            }, 1000);
          } catch (error) {
            console.error('Error during token creation:', error);
            res.writeHead(500, { 'Content-Type': 'text/html' });
            res.end(`
              <html>
                <body style="
                  display: flex;
                  flex-direction: column;
                  justify-content: center;
                  align-items: center;
                  height: 100vh;
                  margin: 0;
                  font-family: Arial, sans-serif;
                  background-color: #fff0f0;
                ">
                  <h2 style="color: #d32f2f;">Error connecting to QuickBooks</h2>
                  <p>Please check the console for more details.</p>
                </body>
              </html>
            `);
            settle(() => {
              this.isAuthenticating = false;
              reject(error);
            });
          }
        }
      };

      cancelTimeout = armOAuthTimeout(() => {
        settle(() => {
          this.isAuthenticating = false;
          closeServers();
          reject(new Error(
            `QuickBooks sandbox OAuth timed out after ${OAUTH_CALLBACK_TIMEOUT_MS}ms ` +
              `waiting for ${OAUTH_REDIRECT_URI}.`
          ));
        });
      });

      let announced = false;
      const announce = async () => {
        if (announced || settled) return;
        announced = true;
        const authUri = flowClient.authorizeUri({
          scope: [OAuthClient.scopes.Accounting as string],
          state: expectedState
        }).toString();

        console.log('\n=== QuickBooks Authorization ===');
        console.log('Open this URL in a browser to authorize:\n');
        console.log(authUri);
        console.log('\nWaiting for callback...\n');

        try {
          await open(authUri);
        } catch {
          // Headless environment — user will open the URL manually
        }
      };

      // Loopback sockets only. Do not bind "::" or 0.0.0.0. localhost in the
      // redirect may resolve to either address; both listeners share one handler.
      for (const host of OAUTH_LOOPBACK_HOSTS) {
        const server = http.createServer(onRequest);
        servers.push(server);
        server.on('error', (error: NodeJS.ErrnoException) => {
          const ipv6Unavailable = host === '::1'
            && (error.code === 'EAFNOSUPPORT' || error.code === 'EADDRNOTAVAIL' || error.code === 'EINVAL');
          if (ipv6Unavailable) {
            console.error(`[auth-server] IPv6 loopback is unavailable (${error.code}). Continuing on 127.0.0.1.`);
            return;
          }
          console.error('Server error:', error);
          settle(() => {
            closeServers();
            this.isAuthenticating = false;
            reject(error);
          });
        });
        server.listen(port, host, () => {
          const addr = server.address();
          console.log(`[auth-server] Listening on ${typeof addr === 'string' ? addr : `${addr?.address}:${addr?.port}`} (family: ${typeof addr === 'object' ? addr?.family : 'n/a'})`);
          void announce();
        });
      }
    });
  }

  private saveTokensToEnv(): void {
    const tokenPath = TOKEN_STORE_PATH;
    const envContent = fs.existsSync(tokenPath) ? fs.readFileSync(tokenPath, 'utf-8') : '';
    const envLines = envContent.split('\n');

    const updateEnvVar = (name: string, value: string) => {
      const index = envLines.findIndex(line => line.startsWith(`${name}=`));
      if (index !== -1) {
        envLines[index] = `${name}=${value}`;
      } else {
        envLines.push(`${name}=${value}`);
      }
    };

    if (this.refreshToken) updateEnvVar('QUICKBOOKS_REFRESH_TOKEN', this.refreshToken);
    if (this.realmId) updateEnvVar('QUICKBOOKS_REALM_ID', this.realmId);

    const newContent = envLines.join('\n');
    // Resolve a symlink to its target, then rename a temp file onto that
    // target. Renaming onto the symlink path would replace the link itself.
    const destination = this.resolveTokenDestination(tokenPath);
    const tmpPath = `${destination}.tmp.${process.pid}`;
    try {
      fs.writeFileSync(tmpPath, newContent, { mode: 0o600 });
      fs.renameSync(tmpPath, destination);
    } catch (err) {
      try { fs.unlinkSync(tmpPath); } catch { /* best effort */ }
      throw err;
    }
  }

  private resolveTokenDestination(tokenPath: string): string {
    if (!this.isSymbolicLink(tokenPath)) return tokenPath;
    try {
      return fs.realpathSync(tokenPath);
    } catch (e: any) {
      if (e?.code === 'ENOENT') {
        // Dangling symlink. readlinkSync may return a relative target, which
        // must be resolved against the link's directory, not the process cwd.
        const linkTarget = fs.readlinkSync(tokenPath);
        return path.isAbsolute(linkTarget)
          ? linkTarget
          : path.resolve(path.dirname(tokenPath), linkTarget);
      }
      throw e;
    }
  }

  private isSymbolicLink(filePath: string): boolean {
    try {
      return fs.lstatSync(filePath).isSymbolicLink();
    } catch {
      return false;
    }
  }

  async refreshAccessToken() {
    this.assertSandbox('refresh a QuickBooks access token');
    if (!this.refreshToken) {
      await this.startOAuthFlow();

      // Verify we have a refresh token after OAuth flow
      if (!this.refreshToken) {
        throw new Error('Failed to obtain refresh token from OAuth flow');
      }
    }

    if (this.refreshInFlight) {
      return this.refreshInFlight;
    }

    this.refreshInFlight = (async () => {
      try {
        return await withTokenLock(TOKEN_STORE_PATH, async () => {
        // Multi-process rotation-race fix. The lock is held for this refresh
        // and its persist. The in-memory token is used first and .env is
        // consulted only after that token is rejected — so a valid token,
        // including one this process just rotated but could not persist, is
        // never proactively discarded. A sibling process sharing this .env may
        // have rotated the token (Intuit invalidates the prior one on
        // rotation); if the freshly-persisted disk value differs, retry once
        // with it, turning a concurrent-rotation loss into a success rather
        // than a spurious "token dead".
        let token;
        try {
          token = await this.performRefresh(this.refreshToken!);
        } catch (firstErr) {
          // Only consult disk when OUR token was actually rejected: a rejection
          // (invalid_grant/400/401) may mean a sibling rotated it, so the disk
          // value is worth a retry. A transient error (5xx/429/network) says
          // nothing about token validity — swapping the in-memory token for a
          // possibly-stale disk value on a mere blip could discard a valid
          // (e.g. rotated-but-unpersisted) token, so rethrow and let the caller
          // retry with the token intact.
          if (!this.isAuthInvalidation(firstErr)) {
            throw firstErr;
          }
          const latest = this.readPersistedRefreshToken();
          if (latest && latest !== this.refreshToken) {
            this.refreshToken = latest;
            token = await this.performRefresh(latest);
          } else {
            throw firstErr;
          }
        }

        this.accessToken = token.access_token;

        const expiresIn = token.expires_in || 3600;
        this.accessTokenExpiry = new Date(Date.now() + expiresIn * 1000);

        // Intuit rotates the refresh token (typically every ~24h). When a new
        // one is issued we MUST persist it — the old value in .env becomes
        // stale and will eventually stop working, silently breaking refresh.
        const newRefreshToken = token.refresh_token;
        if (newRefreshToken && newRefreshToken !== this.refreshToken) {
          this.refreshToken = newRefreshToken;
          try {
            this.saveTokensToEnv();
            console.error('[qbo-client] Refresh token rotated and persisted to .env');
          } catch (persistErr) {
            // Don't fail the whole refresh just because we couldn't write to
            // disk; the in-memory token is still valid for this process.
            console.error('[qbo-client] Failed to persist rotated refresh token:', persistErr);
          }
        }

        // Surface the refresh token's own remaining lifetime for observability.
        // Intuit's refresh tokens last 100 days; warn when under 14 days.
        const refreshExpiresIn = token.x_refresh_token_expires_in;
        if (typeof refreshExpiresIn === 'number' && refreshExpiresIn < 14 * 24 * 3600) {
          const days = Math.round(refreshExpiresIn / 86400);
          console.error(
            `[qbo-client] WARNING: refresh token expires in ~${days} day(s). ` +
              'Re-run `npm run auth` against the sandbox company before it expires.'
          );
        }

        return {
          access_token: this.accessToken!,
          expires_in: expiresIn,
        };
        });
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        // Preserve the original error as `cause` so the caller can classify it
        // (auth-invalidation vs transient) without re-parsing the message.
        // Assigned rather than passed to the constructor so this compiles
        // regardless of the configured TS lib target.
        const wrapped = new Error(`Failed to refresh Quickbooks token: ${message}`);
        (wrapped as Error & { cause?: unknown }).cause = error;
        throw wrapped;
      } finally {
        this.refreshInFlight = undefined;
      }
    })();

    return this.refreshInFlight;
  }

  async authenticate(): Promise<QuickBooks> {
    if (this.authInFlight) {
      return this.authInFlight;
    }

    this.authInFlight = (async () => {
      try {
        this.assertSandbox('authenticate to QuickBooks');
        if (!this.refreshToken || !this.realmId) {
          await this.startOAuthFlow();

          // Verify we have both tokens after OAuth flow
          if (!this.refreshToken || !this.realmId) {
            throw new Error('Failed to obtain required tokens from OAuth flow');
          }
        }

        // Silently refresh if token is expired or expiring soon
        if (this.isTokenExpiredOrExpiringSoon()) {
          try {
            await this.refreshAccessToken();
          } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            // A transient failure (Intuit 5xx/429, network blip) says nothing
            // about token validity. In BOTH environments, rethrow it as-is so
            // the caller sees a retryable error and the preserved in-memory
            // token self-heals on the next request. Never discard a valid token
            // or launch a browser flow over a temporary outage.
            if (!this.isAuthInvalidation(error)) {
              throw error;
            }
            // The refresh token is dead. This fork has no production re-auth
            // path and will not contact the production accounting host.
            this.assertSandbox('recover a rejected QuickBooks refresh token');
            console.error(`[qbo-client] Refresh token rejected (${message}); falling back to interactive sandbox OAuth`);
            this.refreshToken = undefined;
            this.accessToken = undefined;
            this.accessTokenExpiry = undefined;
            // With no refresh token, refreshAccessToken() starts the OAuth
            // flow and then exchanges the newly obtained refresh token.
            await this.refreshAccessToken();
          }
        }

        // Always rebuild with the current fresh access token
        this.quickbooksInstance = new QuickBooks(
          this.clientId,
          this.clientSecret,
          this.accessToken!,
          false, // no token secret for OAuth 2.0
          this.realmId!,
          true, // sandbox host only; production is not a fallback
          false, // debug?
          null,  // minor version
          '2.0', // oauth version
          this.refreshToken
        );

        return this.quickbooksInstance;
      } finally {
        this.authInFlight = undefined;
      }
    })();

    return this.authInFlight;
  }

  // ── Called by every handler on every request ─────────────────────────────
  // Checks token freshness on each invocation so handlers stay functional
  // across 60-minute token boundaries without server restarts.
  static async getInstance(): Promise<QuickBooks> {
    if (quickbooksClient.isTokenExpiredOrExpiringSoon()) {
      await quickbooksClient.authenticate();
    }
    if (!quickbooksClient.quickbooksInstance) {
      await quickbooksClient.authenticate();
    }
    return quickbooksClient.quickbooksInstance!;
  }

  // Static counterpart to getInstance() — returns raw OAuth credentials for
  // handlers that need to call QBO endpoints not wrapped by node-quickbooks
  // (e.g. POST /upload for binary attachments). Ensures token freshness on
  // every invocation, same as getInstance().
  static async getAuthCredentials(): Promise<{ accessToken: string; realmId: string; isSandbox: boolean }> {
    if (quickbooksClient.isTokenExpiredOrExpiringSoon() || !quickbooksClient.accessToken) {
      await quickbooksClient.authenticate();
    }
    if (!quickbooksClient.accessToken || !quickbooksClient.realmId) {
      throw new Error('Quickbooks not authenticated');
    }
    quickbooksClient.assertSandbox('return QuickBooks credentials');
    return {
      accessToken: quickbooksClient.accessToken,
      realmId: quickbooksClient.realmId,
      isSandbox: true,
    };
  }

  getQuickbooks() {
    if (!this.quickbooksInstance) {
      throw new Error('Quickbooks not authenticated. Call authenticate() first');
    }
    return this.quickbooksInstance;
  }
}

export const quickbooksClient = new QuickbooksClient({
  clientId: client_id,
  clientSecret: client_secret,
  refreshToken: refresh_token,
  realmId: realm_id,
  environment: environment,
  redirectUri: redirect_uri,
});
