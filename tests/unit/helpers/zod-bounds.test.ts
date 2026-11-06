import { describe, expect, it } from "@jest/globals";
import { z } from "zod";

/**
 * GHSA-mrhx-c7xc-m3w5 is fixed in Zod 4.6.6. The published patch checks
 * .max()/.length() before walking elements. These assertions lock that
 * behavior and keep ordinary validation strict.
 */
describe("Zod 4.6.7 size bounds", () => {
  it("rejects an oversized invalid array on the size check", () => {
    const schema = z.array(z.string()).max(10);
    const input = Array.from({ length: 5000 }, () => 1);
    const started = Date.now();
    const result = schema.safeParse(input);
    const elapsed = Date.now() - started;

    expect(result.success).toBe(false);
    if (result.success) return;
    expect(result.error.issues.map((issue) => issue.code)).toEqual(["too_big"]);
    expect(elapsed).toBeLessThan(1000);
  });

  it("still accepts an in-bound array and rejects a bad element", () => {
    const schema = z.array(z.string().min(1)).max(3);
    expect(schema.safeParse(["a", "b"]).success).toBe(true);
    const empty = schema.safeParse(["a", ""]);
    expect(empty.success).toBe(false);
    if (!empty.success) {
      expect(empty.error.issues.some((issue) => issue.code === "too_small")).toBe(true);
    }
    const tooMany = schema.safeParse(["a", "b", "c", "d"]);
    expect(tooMany.success).toBe(false);
    if (!tooMany.success) {
      expect(tooMany.error.issues.map((issue) => issue.code)).toContain("too_big");
    }
  });

  it("keeps record values strict about the key type", () => {
    const schema = z.record(z.string(), z.any());
    expect(schema.safeParse({ name: "placeholder", nested: { ok: true } }).success).toBe(true);
    expect(schema.safeParse(["not-a-record"]).success).toBe(false);
    expect(z.string().min(1).safeParse("").success).toBe(false);
  });
});
