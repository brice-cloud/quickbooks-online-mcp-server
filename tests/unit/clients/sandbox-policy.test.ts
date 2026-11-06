import { afterEach, describe, expect, it, jest } from "@jest/globals";
import {
  armOAuthTimeout,
  assertSandboxEnvironment,
  failClosed,
  OAUTH_CALLBACK_TIMEOUT_MS,
  readAndApplyTokenFile,
  statesMatch,
} from "../../../src/clients/sandbox-policy";

describe("assertSandboxEnvironment", () => {
  it("accepts unset and the exact sandbox string", () => {
    expect(() => assertSandboxEnvironment(undefined, "process environment")).not.toThrow();
    expect(() => assertSandboxEnvironment("sandbox", "process environment")).not.toThrow();
  });

  it.each(["production", "Production", "SANDBOX", "Sandbox", "prod", "sandbox ", ""])(
    "refuses %j",
    (value) => {
      expect(() => assertSandboxEnvironment(value, "token file /tmp/t.env")).toThrow(
        /exact string "sandbox"/
      );
    }
  );
});

describe("readAndApplyTokenFile", () => {
  const parse = (source: string) => {
    const out: Record<string, string> = {};
    for (const line of source.split("\n")) {
      const idx = line.indexOf("=");
      if (idx === -1) continue;
      out[line.slice(0, idx)] = line.slice(idx + 1);
    }
    return out;
  };

  it("copies credential keys and ignores policy keys", () => {
    const env: NodeJS.ProcessEnv = {
      QUICKBOOKS_DISABLE_WRITE: "true",
      QBO_PDF_OUTPUT_DIR: "",
    };
    readAndApplyTokenFile(
      [
        "QUICKBOOKS_CLIENT_ID=file-client",
        "QUICKBOOKS_CLIENT_SECRET=file-secret",
        "QUICKBOOKS_REFRESH_TOKEN=file-refresh",
        "QUICKBOOKS_REALM_ID=file-realm",
        "QUICKBOOKS_REDIRECT_URI=http://127.0.0.1:8000/callback",
        "QUICKBOOKS_ENVIRONMENT=sandbox",
        "QUICKBOOKS_DISABLE_WRITE=false",
        "QUICKBOOKS_DISABLE_UPDATE=false",
        "QUICKBOOKS_DISABLE_DELETE=false",
        "QBO_PDF_OUTPUT_DIR=/tmp/from-file",
        "QUICKBOOKS_TOKEN_STORE_PATH=/tmp/elsewhere.env",
        "QUICKBOOKS_CLIENT_ID_EMPTY=",
      ].join("\n"),
      env,
      parse,
      "token file"
    );
    expect(env.QUICKBOOKS_CLIENT_ID).toBe("file-client");
    expect(env.QUICKBOOKS_CLIENT_SECRET).toBe("file-secret");
    expect(env.QUICKBOOKS_REFRESH_TOKEN).toBe("file-refresh");
    expect(env.QUICKBOOKS_REALM_ID).toBe("file-realm");
    expect(env.QUICKBOOKS_REDIRECT_URI).toBe("http://127.0.0.1:8000/callback");
    expect(env.QUICKBOOKS_ENVIRONMENT).toBeUndefined();
    expect(env.QUICKBOOKS_DISABLE_WRITE).toBe("true");
    expect(env.QBO_PDF_OUTPUT_DIR).toBe("");
    expect(env.QUICKBOOKS_TOKEN_STORE_PATH).toBeUndefined();
  });

  it("does not apply a production environment or the credentials beside it", () => {
    const env: NodeJS.ProcessEnv = { QUICKBOOKS_CLIENT_ID: "from-process" };
    expect(() =>
      readAndApplyTokenFile(
        "QUICKBOOKS_ENVIRONMENT=production\nQUICKBOOKS_CLIENT_ID=from-file\n",
        env,
        parse,
        "token file /tmp/t.env"
      )
    ).toThrow(/Refusing to start/);
    expect(env.QUICKBOOKS_CLIENT_ID).toBe("from-process");
  });

  it("skips non-string credential values", () => {
    const env: NodeJS.ProcessEnv = {};
    readAndApplyTokenFile(
      "ignored",
      env,
      () => ({ QUICKBOOKS_CLIENT_ID: 1 as unknown as string, QUICKBOOKS_REFRESH_TOKEN: "ok" }),
      "token file"
    );
    expect(env.QUICKBOOKS_CLIENT_ID).toBeUndefined();
    expect(env.QUICKBOOKS_REFRESH_TOKEN).toBe("ok");
  });

  it("skips blank credential values", () => {
    const env: NodeJS.ProcessEnv = { QUICKBOOKS_REFRESH_TOKEN: "keep-me" };
    readAndApplyTokenFile("QUICKBOOKS_REFRESH_TOKEN=   \n", env, parse, "token file");
    expect(env.QUICKBOOKS_REFRESH_TOKEN).toBe("keep-me");
  });
});

describe("statesMatch", () => {
  it("matches equal states and rejects missing, short, and different states", () => {
    expect(statesMatch("abc", "abc")).toBe(true);
    expect(statesMatch("abc", null)).toBe(false);
    expect(statesMatch("abc", "ab")).toBe(false);
    expect(statesMatch("abc", "abd")).toBe(false);
  });
});

describe("armOAuthTimeout", () => {
  afterEach(() => {
    jest.useRealTimers();
  });

  it("fires the default five-minute deadline and can be cancelled", () => {
    jest.useFakeTimers();
    const onTimeout = jest.fn();
    const cancel = armOAuthTimeout(onTimeout);
    jest.advanceTimersByTime(OAUTH_CALLBACK_TIMEOUT_MS - 1);
    expect(onTimeout).not.toHaveBeenCalled();
    cancel();
    jest.advanceTimersByTime(2);
    expect(onTimeout).not.toHaveBeenCalled();
  });

  it("fires when the deadline elapses", () => {
    jest.useFakeTimers();
    const onTimeout = jest.fn();
    armOAuthTimeout(onTimeout, 25);
    jest.advanceTimersByTime(25);
    expect(onTimeout).toHaveBeenCalledTimes(1);
  });
});

describe("failClosed", () => {
  it("prints the message and exits 1", () => {
    const exit = jest.spyOn(process, "exit").mockImplementation(((code?: number) => {
      throw new Error(`exit ${code}`);
    }) as never);
    const error = jest.spyOn(console, "error").mockImplementation(() => {});
    expect(() => failClosed("refusing")).toThrow("exit 1");
    expect(exit).toHaveBeenCalledWith(1);
    expect(error).toHaveBeenCalledWith("refusing");
    exit.mockRestore();
    error.mockRestore();
  });
});
