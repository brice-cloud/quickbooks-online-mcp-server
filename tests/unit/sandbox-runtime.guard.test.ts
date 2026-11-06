/**
 * Starts the compiled server with fake credentials and a network fence.
 * Build dist before this file runs (npm run build). No Intuit calls.
 */
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "@jest/globals";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const entry = path.join(root, "dist", "index.js");
const clientEntry = path.join(root, "dist", "clients", "quickbooks-client.js");
const fence = path.join(root, "tests", "fixtures", "block-net.mjs");
const temps: string[] = [];

function tempFile(contents: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "qbo-guard-"));
  temps.push(dir);
  const file = path.join(dir, "token.env");
  fs.writeFileSync(file, contents, { mode: 0o600 });
  return file;
}

function childEnv(extra: Record<string, string | undefined>): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const key of ["PATH", "HOME", "USER", "TMPDIR", "LANG"]) {
    if (process.env[key]) env[key] = process.env[key];
  }
  for (const [key, value] of Object.entries(extra)) {
    if (value !== undefined) env[key] = value;
  }
  return env;
}

function runNode(args: string[], env: NodeJS.ProcessEnv): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ["--import", fence, ...args], {
      cwd: root,
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => child.kill("SIGKILL"), 8000);
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });
  });
}

afterEach(() => {
  while (temps.length) fs.rmSync(temps.pop()!, { recursive: true, force: true });
});

const baseCreds = {
  QUICKBOOKS_CLIENT_ID: "placeholder-client-id",
  QUICKBOOKS_CLIENT_SECRET: "placeholder-client-secret",
  QUICKBOOKS_REFRESH_TOKEN: "placeholder-refresh-token",
  QUICKBOOKS_REALM_ID: "placeholder-realm",
};

describe("compiled sandbox fork startup", () => {
  it("refuses production, casing variants, a production token file, a relative token path, and missing credentials", async () => {
    expect(fs.existsSync(clientEntry)).toBe(true);

    const productionEnv = await runNode([clientEntry], childEnv({
      ...baseCreds,
      QUICKBOOKS_ENVIRONMENT: "production",
    }));
    expect(productionEnv.code).toBe(1);
    expect(productionEnv.stderr).toMatch(/exact string "sandbox"/);
    expect(productionEnv.stderr).not.toMatch(/BLOCKED_/);

    const sandboxCaps = await runNode([clientEntry], childEnv({
      ...baseCreds,
      QUICKBOOKS_ENVIRONMENT: "SANDBOX",
    }));
    expect(sandboxCaps.code).toBe(1);
    expect(sandboxCaps.stderr).toMatch(/Refusing to start/);
    expect(sandboxCaps.stderr).not.toMatch(/BLOCKED_/);

    const tokenFile = tempFile(
      [
        "QUICKBOOKS_ENVIRONMENT=production",
        "QUICKBOOKS_CLIENT_ID=placeholder-client-id",
        "QUICKBOOKS_CLIENT_SECRET=placeholder-client-secret",
        "QUICKBOOKS_DISABLE_WRITE=false",
      ].join("\n")
    );
    const fileOverride = await runNode([clientEntry], childEnv({
      ...baseCreds,
      QUICKBOOKS_ENVIRONMENT: "sandbox",
      QUICKBOOKS_TOKEN_STORE_PATH: tokenFile,
    }));
    expect(fileOverride.code).toBe(1);
    expect(fileOverride.stderr).toMatch(/token file/);
    expect(fileOverride.stderr).toMatch(/production/);
    expect(fileOverride.stderr).not.toMatch(/BLOCKED_/);

    const relative = await runNode([clientEntry], childEnv({
      ...baseCreds,
      QUICKBOOKS_ENVIRONMENT: "sandbox",
      QUICKBOOKS_TOKEN_STORE_PATH: "relative.env",
    }));
    expect(relative.code).toBe(1);
    expect(relative.stderr).toMatch(/absolute path/);
    expect(relative.stderr).not.toMatch(/BLOCKED_/);

    const missing = await runNode([clientEntry], childEnv({
      QUICKBOOKS_ENVIRONMENT: "sandbox",
    }));
    expect(missing.code).toBe(1);
    expect(missing.stderr).toMatch(/QUICKBOOKS_CLIENT_ID and QUICKBOOKS_CLIENT_SECRET/);
    expect(missing.stderr).not.toMatch(/BLOCKED_/);
  });

  it("lists only allowlisted read tools when flags and the token file try to enable writes", async () => {
    const tokenFile = tempFile(
      [
        "QUICKBOOKS_CLIENT_ID=placeholder-from-file",
        "QUICKBOOKS_CLIENT_SECRET=placeholder-secret-from-file",
        "QUICKBOOKS_REFRESH_TOKEN=placeholder-refresh-from-file",
        "QUICKBOOKS_REALM_ID=placeholder-realm-from-file",
        "QUICKBOOKS_ENVIRONMENT=sandbox",
        "QUICKBOOKS_DISABLE_WRITE=false",
        "QUICKBOOKS_DISABLE_UPDATE=false",
        "QUICKBOOKS_DISABLE_DELETE=false",
        "QBO_PDF_OUTPUT_DIR=/tmp/qbo-should-not-be-taken-from-the-token-file",
      ].join("\n")
    );
    const child = spawn(process.execPath, ["--import", fence, entry], {
      cwd: root,
      env: childEnv({
        QUICKBOOKS_CLIENT_ID: "placeholder-client-id",
        QUICKBOOKS_CLIENT_SECRET: "placeholder-client-secret",
        QUICKBOOKS_ENVIRONMENT: "sandbox",
        QUICKBOOKS_REFRESH_TOKEN: "placeholder-refresh-token",
        QUICKBOOKS_REALM_ID: "placeholder-realm",
        QUICKBOOKS_DISABLE_WRITE: "false",
        QUICKBOOKS_DISABLE_UPDATE: "false",
        QUICKBOOKS_DISABLE_DELETE: "false",
        QUICKBOOKS_TOKEN_STORE_PATH: tokenFile,
      }),
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stderr = "";
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    const lines = createInterface({ input: child.stdout });
    const listed = new Promise<string[]>((resolve, reject) => {
      const timer = setTimeout(() => {
        child.kill("SIGKILL");
        reject(new Error(`tools/list timed out\n${stderr}`));
      }, 8000);
      lines.on("line", (line) => {
        const message = JSON.parse(line) as { id?: number; result?: { tools?: { name: string }[] } };
        if (message.id === 2) {
          clearTimeout(timer);
          resolve((message.result?.tools ?? []).map((tool) => tool.name));
        }
      });
      child.on("close", (code) => {
        clearTimeout(timer);
        reject(new Error(`server exited ${code}\n${stderr}`));
      });
    });
    const send = (payload: unknown) => child.stdin.write(`${JSON.stringify(payload)}\n`);
    send({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: { name: "sandbox-guard", version: "0" },
      },
    });
    send({ jsonrpc: "2.0", method: "notifications/initialized" });
    send({ jsonrpc: "2.0", id: 2, method: "tools/list" });

    const names = await listed;
    child.kill("SIGKILL");
    expect(stderr).not.toMatch(/BLOCKED_/);
    expect(names.length).toBeGreaterThan(0);
    expect(names.filter((name) => /^(create_|create-|update_|update-|delete_|delete-)/.test(name))).toEqual([]);
    expect(names).not.toContain("create_deposit");
    expect(names).not.toContain("create_payment");
    expect(names).not.toContain("create_transfer");
    expect(names).not.toContain("update_company_info");
    expect(names).not.toContain("delete_customer");
    expect(names).toContain("get_deposit");
    expect(names).toContain("search_deposits");
    expect(names).toContain("get_customer");
    expect(names).toContain("get_balance_sheet");
    expect(names.filter((name) => /match|bank/i.test(name))).toEqual([]);
  });
});
