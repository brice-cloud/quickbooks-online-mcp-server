import fs from "fs";

/**
 * Exclusive lock beside the token file.
 *
 * Intuit invalidates a refresh token when it is rotated. Two processes that
 * refresh the same file can strand the new token. The lock is held across
 * one refresh and its persist. It is a local file lock, not a distributed lock.
 */

export type TokenLockOptions = {
  writeFileSync?: (path: string, data: string, options: { flag: string; mode: number }) => void;
  statSync?: (path: string) => { mtimeMs: number };
  unlinkSync?: (path: string) => void;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
  staleMs?: number;
  timeoutMs?: number;
};

const DEFAULT_STALE_MS = 30_000;
const DEFAULT_TIMEOUT_MS = 15_000;

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, ms);
    timer.unref();
  });
}

export async function acquireTokenLock(storePath: string, options: TokenLockOptions = {}): Promise<string> {
  const writeFileSync = options.writeFileSync ?? fs.writeFileSync;
  const statSync = options.statSync ?? fs.statSync;
  const unlinkSync = options.unlinkSync ?? fs.unlinkSync;
  const now = options.now ?? Date.now;
  const sleep = options.sleep ?? defaultSleep;
  const staleMs = options.staleMs ?? DEFAULT_STALE_MS;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const lockPath = `${storePath}.lock`;
  const started = now();

  for (;;) {
    try {
      writeFileSync(lockPath, `${process.pid}\n`, { flag: "wx", mode: 0o600 });
      return lockPath;
    } catch (err) {
      const code = (err as NodeJS.ErrnoException)?.code;
      if (code !== "EEXIST") throw err;
      let stole = false;
      try {
        const stat = statSync(lockPath);
        if (now() - stat.mtimeMs > staleMs) {
          unlinkSync(lockPath);
          stole = true;
        }
      } catch {
        stole = true;
      }
      if (stole) continue;
      if (now() - started > timeoutMs) {
        throw new Error(`Timed out waiting for the QuickBooks token-store lock at ${lockPath}`);
      }
      await sleep(50);
    }
  }
}

export function releaseTokenLock(lockPath: string, unlinkSync: (path: string) => void = fs.unlinkSync): void {
  try {
    unlinkSync(lockPath);
  } catch {
    /* The lock file is already gone. The next acquirer may proceed. */
  }
}

export async function withTokenLock<T>(storePath: string, fn: () => Promise<T>, options?: TokenLockOptions): Promise<T> {
  const lockPath = await acquireTokenLock(storePath, options);
  try {
    return await fn();
  } finally {
    releaseTokenLock(lockPath, options?.unlinkSync);
  }
}
