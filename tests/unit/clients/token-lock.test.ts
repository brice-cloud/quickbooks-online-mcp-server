import fs from "fs";
import os from "os";
import path from "path";
import { afterEach, describe, expect, it } from "@jest/globals";
import { acquireTokenLock, releaseTokenLock, withTokenLock } from "../../../src/clients/token-lock";

const dirs: string[] = [];

function tempStore(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "qbo-lock-"));
  dirs.push(dir);
  return path.join(dir, "tokens.env");
}

afterEach(() => {
  while (dirs.length) {
    fs.rmSync(dirs.pop()!, { recursive: true, force: true });
  }
});

describe("token lock", () => {
  it("acquires and releases a real lock file", async () => {
    const store = tempStore();
    const lockPath = await acquireTokenLock(store);
    expect(fs.existsSync(lockPath)).toBe(true);
    expect(lockPath).toBe(`${store}.lock`);
    releaseTokenLock(lockPath);
    expect(fs.existsSync(lockPath)).toBe(false);
  });

  it("replaces a stale lock and then acquires", async () => {
    const store = tempStore();
    fs.writeFileSync(`${store}.lock`, "old\n", { flag: "wx", mode: 0o600 });
    const old = new Date(Date.now() - 60_000);
    fs.utimesSync(`${store}.lock`, old, old);
    const lockPath = await acquireTokenLock(store);
    expect(lockPath).toBe(`${store}.lock`);
    releaseTokenLock(lockPath);
  });

  it("waits for the holder to release instead of taking a fresh lock", async () => {
    const store = tempStore();
    const first = await acquireTokenLock(store);
    let entered = false;
    const second = acquireTokenLock(store).then((lockPath) => {
      entered = true;
      return lockPath;
    });
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(entered).toBe(false);
    releaseTokenLock(first);
    await expect(second).resolves.toBe(`${store}.lock`);
    releaseTokenLock(`${store}.lock`);
  });

  it("retries when the lock disappears between exist and stat", async () => {
    let writes = 0;
    const lockPath = await acquireTokenLock("/tmp/qbo-injected.env", {
      writeFileSync: () => {
        writes += 1;
        if (writes === 1) {
          const error = new Error("exists") as NodeJS.ErrnoException;
          error.code = "EEXIST";
          throw error;
        }
      },
      statSync: () => {
        throw new Error("gone");
      },
      unlinkSync: () => {},
      sleep: async () => {},
    });
    expect(lockPath).toBe("/tmp/qbo-injected.env.lock");
    expect(writes).toBe(2);
  });

  it("times out while a fresh lock is held", async () => {
    let clock = 0;
    await expect(
      acquireTokenLock("/tmp/qbo-timeout.env", {
        writeFileSync: () => {
          const error = new Error("exists") as NodeJS.ErrnoException;
          error.code = "EEXIST";
          throw error;
        },
        statSync: () => ({ mtimeMs: 0 }),
        unlinkSync: () => {},
        now: () => {
          clock += 1000;
          return clock;
        },
        sleep: async () => {},
        staleMs: 10_000,
        timeoutMs: 2_000,
      })
    ).rejects.toThrow(/Timed out waiting/);
  });

  it("rethrows lock errors that are not contention", async () => {
    await expect(
      acquireTokenLock("/tmp/qbo-eacces.env", {
        writeFileSync: () => {
          const error = new Error("denied") as NodeJS.ErrnoException;
          error.code = "EACCES";
          throw error;
        },
      })
    ).rejects.toThrow("denied");
  });

  it("ignores a release of a missing lock", () => {
    expect(() =>
      releaseTokenLock("/tmp/qbo-missing.lock", () => {
        throw new Error("already gone");
      })
    ).not.toThrow();
  });

  it("releases the lock when the critical section throws", async () => {
    const store = tempStore();
    const seen: string[] = [];
    await expect(
      withTokenLock(
        store,
        async () => {
          throw new Error("refresh failed");
        },
        {
          unlinkSync: (lockPath) => {
            seen.push(lockPath);
          },
        }
      )
    ).rejects.toThrow("refresh failed");
    expect(seen).toEqual([`${store}.lock`]);
  });

  it("runs the critical section while holding the default lock", async () => {
    const store = tempStore();
    const value = await withTokenLock(store, async () => 7);
    expect(value).toBe(7);
    expect(fs.existsSync(`${store}.lock`)).toBe(false);
  });
});
