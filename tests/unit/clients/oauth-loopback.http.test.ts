/**
 * Real loopback HTTP, fake Intuit tokens. Proves the registered redirect is
 * http://localhost:8000/callback and that both 127.0.0.1 and ::1 accept it
 * only when the Host header is that hostname.
 */
import http from "node:http";
import { jest } from "@jest/globals";

process.env.QUICKBOOKS_CLIENT_ID = "placeholder-client-id";
process.env.QUICKBOOKS_CLIENT_SECRET = "placeholder-client-secret";
process.env.QUICKBOOKS_REFRESH_TOKEN = "placeholder-refresh-token";
process.env.QUICKBOOKS_REALM_ID = "placeholder-realm";
process.env.QUICKBOOKS_ENVIRONMENT = "sandbox";
process.env.QUICKBOOKS_REDIRECT_URI = "https://example.invalid/callback";
process.env.QUICKBOOKS_TOKEN_STORE_PATH = "/tmp/qbo-oauth-loopback-does-not-exist.env";

jest.unstable_mockModule("dotenv", () => ({
  default: { config: jest.fn(), parse: jest.fn(() => ({})) },
}));

const refreshDispatch = jest.fn<(token: string) => Promise<unknown>>();
const createTokenDispatch = jest.fn<(url: string) => Promise<unknown>>();
let authorizeUrl = "";

jest.unstable_mockModule("intuit-oauth", () => {
  class MockOAuthClient {
    static scopes = { Accounting: "com.intuit.quickbooks.accounting" };
    cfg: Record<string, unknown>;
    refreshUsingToken = jest.fn((token: string) => refreshDispatch(token));
    createToken = jest.fn((url: string) => createTokenDispatch(url));
    authorizeUri = jest.fn((params: { state: string }) => {
      const redirect = String(this.cfg.redirectUri);
      authorizeUrl = `https://appcenter.intuit.com/connect/oauth2?redirect_uri=${encodeURIComponent(redirect)}&state=${params.state}`;
      return authorizeUrl;
    });
    constructor(cfg: Record<string, unknown>) {
      this.cfg = cfg;
    }
  }
  return { default: MockOAuthClient };
});

jest.unstable_mockModule("node-quickbooks", () => ({
  default: class MockQuickBooks {
    constructor(..._args: unknown[]) {}
  },
}));
jest.unstable_mockModule("open", () => ({ default: jest.fn(async () => undefined) }));
jest.unstable_mockModule("fs", () => ({
  default: {
    readFileSync: jest.fn(() => {
      throw Object.assign(new Error("ENOENT"), { code: "ENOENT" });
    }),
    existsSync: jest.fn(() => false),
    writeFileSync: jest.fn(),
    renameSync: jest.fn(),
    unlinkSync: jest.fn(),
    lstatSync: jest.fn(() => ({ isSymbolicLink: () => false })),
  },
}));

const { quickbooksClient } = await import("../../../src/clients/quickbooks-client");

function request(options: http.RequestOptions): Promise<{ status: number }> {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      res.resume();
      res.on("end", () => resolve({ status: res.statusCode ?? 0 }));
    });
    req.on("error", reject);
    req.end();
  });
}

async function waitForListener(): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < 3000) {
    try {
      await request({
        host: "127.0.0.1",
        port: 8000,
        path: "/health",
        headers: { Host: "localhost:8000" },
      });
      return;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
  }
  throw new Error("loopback callback listener did not start");
}

describe("sandbox OAuth loopback HTTP", () => {
  it("exchanges one fake code for localhost on IPv4 and IPv6, and rejects an IP Host", async () => {
    refreshDispatch
      .mockRejectedValueOnce(new Error("invalid_grant"))
      .mockResolvedValue({
        token: { access_token: "placeholder-access", expires_in: 3600, refresh_token: "placeholder-refresh-token" },
      });
    createTokenDispatch.mockResolvedValue({
      token: { refresh_token: "placeholder-refresh-from-flow", realmId: "placeholder-realm" },
    });
    (quickbooksClient as unknown as { accessTokenExpiry?: Date }).accessTokenExpiry = new Date(0);

    const authPromise = quickbooksClient.authenticate();
    await waitForListener();

    const redirect = new URL(authorizeUrl).searchParams.get("redirect_uri");
    const state = new URL(authorizeUrl).searchParams.get("state");
    expect(redirect).toBe("http://localhost:8000/callback");
    expect(state).toEqual(expect.stringMatching(/^[0-9a-f]{48}$/));

    const ipHost = await request({
      host: "127.0.0.1",
      port: 8000,
      path: `/callback?code=fake-code&state=${state}`,
      headers: { Host: "127.0.0.1:8000" },
    });
    expect(ipHost.status).toBe(403);
    expect(createTokenDispatch).not.toHaveBeenCalled();

    const ipv4 = await request({
      host: "127.0.0.1",
      port: 8000,
      path: `/callback?code=fake-code&state=${state}`,
      headers: { Host: "localhost:8000" },
    });
    expect(ipv4.status).toBe(200);
    expect(createTokenDispatch).toHaveBeenCalledTimes(1);
    expect(createTokenDispatch).toHaveBeenCalledWith(`/callback?code=fake-code&state=${state}`);

    const ipv6 = await request({
      host: "::1",
      port: 8000,
      family: 6,
      path: `/callback?code=fake-code&state=${state}`,
      headers: { Host: "localhost:8000" },
    });
    expect(ipv6.status).toBe(200);
    expect(createTokenDispatch).toHaveBeenCalledTimes(1);

    await authPromise;
  }, 15000);
});
