import { timingSafeEqual } from "crypto";

/**
 * Hard sandbox policy for this fork.
 *
 * Process environment and the token file may supply credentials. They cannot
 * select a QuickBooks host, and they cannot register mutating tools.
 * Anything other than an unset environment or the exact string "sandbox"
 * refuses to start. There is no production fallback.
 */

export const SANDBOX_ENVIRONMENT = "sandbox";
export const SANDBOX_API_HOST = "sandbox-quickbooks.api.intuit.com";
export const OAUTH_BIND_HOST = "127.0.0.1";
export const OAUTH_PORT = 8000;
export const OAUTH_REDIRECT_URI = `http://${OAUTH_BIND_HOST}:${OAUTH_PORT}/callback`;
export const OAUTH_CALLBACK_TIMEOUT_MS = 5 * 60 * 1000;

/** Credential keys the token file may set. Security policy keys are absent on purpose. */
export const TOKEN_FILE_KEYS = [
  "QUICKBOOKS_CLIENT_ID",
  "QUICKBOOKS_CLIENT_SECRET",
  "QUICKBOOKS_REFRESH_TOKEN",
  "QUICKBOOKS_REALM_ID",
  "QUICKBOOKS_REDIRECT_URI",
] as const;

export class SandboxRefusal extends Error {
  readonly code = "QBO_SANDBOX_REQUIRED";

  constructor(message: string) {
    super(message);
    this.name = "SandboxRefusal";
  }
}

export function failClosed(message: string): never {
  console.error(message);
  process.exit(1);
}

/**
 * Unset and the exact string "sandbox" are the only accepted values.
 * Empty strings, casing variants, "prod", and "production" are refused.
 */
export function assertSandboxEnvironment(value: string | undefined, source: string): void {
  if (value === undefined || value === SANDBOX_ENVIRONMENT) return;
  throw new SandboxRefusal(
    `Refusing to start: ${source} set QUICKBOOKS_ENVIRONMENT to ${JSON.stringify(value)}. ` +
      `This sandbox fork accepts only an unset value or the exact string "sandbox". ` +
      `Production, casing variants, and typos are disabled.`
  );
}

export function readAndApplyTokenFile(
  raw: string,
  env: NodeJS.ProcessEnv,
  parse: (source: string) => Record<string, string>,
  sourceLabel: string
): void {
  const parsed = parse(raw);
  if (Object.prototype.hasOwnProperty.call(parsed, "QUICKBOOKS_ENVIRONMENT")) {
    assertSandboxEnvironment(parsed.QUICKBOOKS_ENVIRONMENT, sourceLabel);
  }
  for (const key of TOKEN_FILE_KEYS) {
    if (!Object.prototype.hasOwnProperty.call(parsed, key)) continue;
    const value = parsed[key];
    if (typeof value !== "string") continue;
    const trimmed = value.trim();
    if (!trimmed) continue;
    env[key] = trimmed;
  }
}

export function statesMatch(expected: string, incoming: string | null): boolean {
  if (incoming === null) return false;
  const expectedBuf = Buffer.from(expected);
  const incomingBuf = Buffer.from(incoming);
  if (expectedBuf.length !== incomingBuf.length) return false;
  return timingSafeEqual(expectedBuf, incomingBuf);
}

/** Loopback OAuth deadline. The timer does not keep a finished process alive. */
export function armOAuthTimeout(onTimeout: () => void, ms: number = OAUTH_CALLBACK_TIMEOUT_MS): () => void {
  const timer = setTimeout(onTimeout, ms);
  timer.unref();
  return () => clearTimeout(timer);
}
