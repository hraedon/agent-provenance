import { expect, test, describe } from "bun:test";
import { mkdtempSync, rmSync, readFileSync, existsSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  extractFiles,
  safeSessionId,
  stateDir,
  markDegraded,
  createSessionMap,
  summarizeResult,
} from "./index.js";

// Each describe block gets its own fresh tmp root so tests are isolated.
function freshRoot() {
  return mkdtempSync(join(tmpdir(), "cairn-test-"));
}

describe("extractFiles", () => {
  test("collects single-path keys", () => {
    expect(extractFiles({ filePath: "/a/b.py" })).toEqual(["/a/b.py"]);
    expect(extractFiles({ path: "/x" })).toEqual(["/x"]);
    expect(extractFiles({ file: "/y" })).toEqual(["/y"]);
  });

  test("collects files array, ignoring non-strings", () => {
    expect(extractFiles({ files: ["/1", "/2", 3, null, "/4"] })).toEqual([
      "/1",
      "/2",
      "/4",
    ]);
  });

  test("collects files as a single string", () => {
    expect(extractFiles({ files: "/single" })).toEqual(["/single"]);
  });

  test("returns empty for missing/odd args", () => {
    expect(extractFiles({})).toEqual([]);
    expect(extractFiles(undefined)).toEqual([]);
    expect(extractFiles(null)).toEqual([]);
    expect(extractFiles("not an object")).toEqual([]);
  });

  test("ignores non-string single-path values", () => {
    expect(extractFiles({ filePath: 42, path: { no: true } })).toEqual([]);
  });
});

describe("safeSessionId", () => {
  test("passes through already-safe ids", () => {
    expect(safeSessionId("ses_abc-123.txt")).toBe("ses_abc-123.txt");
  });

  test("replaces path separators and shell metacharacters", () => {
    // Dots are preserved (matches Claude Code hook regex); separators and
    // metacharacters become "_".  Note "ses_.._evil" is still a single safe
    // directory name — the ".." is bounded by underscores, not a traversal.
    expect(safeSessionId("ses/../evil")).toBe("ses_.._evil");
    expect(safeSessionId("a;b|c`d$e")).toBe("a_b_c_d_e");
    expect(safeSessionId("ses/with space")).toBe("ses_with_space");
  });

  test("coerces non-strings", () => {
    expect(safeSessionId(12345)).toBe("12345");
  });
});

describe("stateDir", () => {
  test("creates the directory and sanitizes the session id", () => {
    const root = freshRoot();
    try {
      const dir = stateDir("ses/../x", root);
      expect(existsSync(dir)).toBe(true);
      // The traversal segments are neutralized by safeSessionId ("/" → "_").
      expect(dir.endsWith(join("ses_.._x"))).toBe(true);
      const st = statSync(dir);
      expect(st.isDirectory()).toBe(true);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("is idempotent across calls", () => {
    const root = freshRoot();
    try {
      const a = stateDir("sess", root);
      const b = stateDir("sess", root);
      expect(a).toBe(b);
      expect(existsSync(a)).toBe(true);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

describe("markDegraded", () => {
  test("appends one JSONL record per call with the expected fields", () => {
    const root = freshRoot();
    try {
      markDegraded("sess", "post", "bridge call failed for Edit end", root);
      markDegraded("sess", "pre", "bridge call failed for Write begin", root);

      const log = readFileSync(join(root, "sess", "degradation.log"), "utf8")
        .trim()
        .split("\n");
      expect(log).toHaveLength(2);

      const first = JSON.parse(log[0]);
      expect(first.action).toBe("post");
      expect(first.detail).toContain("Edit");
      expect(first.ts).toBeTruthy();
      // ISO timestamp must round-trip.
      expect(new Date(first.ts).toString()).not.toBe("Invalid Date");

      const second = JSON.parse(log[1]);
      expect(second.action).toBe("pre");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("writes per-session logs (no cross-session bleed)", () => {
    const root = freshRoot();
    try {
      markDegraded("sessA", "post", "A failure", root);
      markDegraded("sessB", "pre", "B failure", root);

      const aLog = join(root, safeSessionId("sessA"), "degradation.log");
      const bLog = join(root, safeSessionId("sessB"), "degradation.log");
      expect(existsSync(aLog)).toBe(true);
      expect(existsSync(bLog)).toBe(true);

      const aEntry = JSON.parse(readFileSync(aLog, "utf8").trim());
      const bEntry = JSON.parse(readFileSync(bLog, "utf8").trim());
      expect(aEntry.detail).toBe("A failure");
      expect(bEntry.detail).toBe("B failure");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

describe("summarizeResult", () => {
  test("passes through a numeric exit_code and stringifies non-string stdout", () => {
    expect(summarizeResult({ exit_code: 2, x: 1 })).toEqual({
      exit_code: 2,
      stdout: '{"exit_code":2,"x":1}',
    });
  });

  test("defaults exit_code to 0 when absent or non-numeric", () => {
    expect(summarizeResult({}).exit_code).toBe(0);
    expect(summarizeResult({ exit_code: "oops" }).exit_code).toBe(0);
    expect(summarizeResult(null).exit_code).toBe(0);
    expect(summarizeResult(undefined).exit_code).toBe(0);
  });

  test("slices a string result to 2000 chars verbatim", () => {
    const long = "a".repeat(3000);
    const out = summarizeResult(long);
    expect(out.exit_code).toBe(0);
    expect(out.stdout).toHaveLength(2000);
  });

  test("exit_code 0 is preserved (not falsy-coerced to default)", () => {
    expect(summarizeResult({ exit_code: 0 }).exit_code).toBe(0);
  });
});

describe("createSessionMap", () => {
  test("get/set/has/delete/size behave like a map", () => {
    const m = createSessionMap({ maxSize: 5 });
    expect(m.size()).toBe(0);
    expect(m.has("k")).toBe(false);

    m.set("k", { workItemId: "w1" });
    expect(m.has("k")).toBe(true);
    expect(m.get("k")).toEqual({ workItemId: "w1" });
    expect(m.size()).toBe(1);

    expect(m.delete("k")).toBe(true);
    expect(m.get("k")).toBeUndefined();
    expect(m.size()).toBe(0);
    expect(m.delete("missing")).toBe(false);
  });

  test("updating an existing key does not evict", () => {
    const m = createSessionMap({ maxSize: 1 });
    m.set("k", { v: 1 });
    const res = m.set("k", { v: 2 });
    expect(res.evictedKey).toBeNull();
    expect(m.get("k")).toEqual({ v: 2 });
    expect(m.size()).toBe(1);
  });

  test("evicts the oldest entry (FIFO) when at capacity and returns it", () => {
    const m = createSessionMap({ maxSize: 2 });
    m.set("a", { workItemId: "wa" });
    m.set("b", { workItemId: "wb" });
    expect(m.size()).toBe(2);

    const res = m.set("c", { workItemId: "wc" });
    expect(res.evictedKey).toBe("a");
    expect(res.evicted).toEqual({ workItemId: "wa" });

    // "a" is gone, "b" and "c" remain.
    expect(m.has("a")).toBe(false);
    expect(m.has("b")).toBe(true);
    expect(m.has("c")).toBe(true);
    expect(m.size()).toBe(2);
  });

  test("eviction order follows insertion, not access", () => {
    const m = createSessionMap({ maxSize: 2 });
    m.set("a", { workItemId: "wa" });
    m.set("b", { workItemId: "wb" });
    // Access "a" — FIFO must NOT promote it (this is documented behavior).
    m.get("a");
    const res = m.set("c", { workItemId: "wc" });
    expect(res.evictedKey).toBe("a");
  });

  test("rejects a non-positive maxSize", () => {
    expect(() => createSessionMap({ maxSize: 0 })).toThrow();
    expect(() => createSessionMap({ maxSize: -1 })).toThrow();
    expect(() => createSessionMap({ maxSize: NaN })).toThrow();
  });
});
