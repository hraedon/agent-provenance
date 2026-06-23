import { expect, test, describe, beforeAll, afterAll } from "bun:test";
import {
  mkdtempSync,
  rmSync,
  readFileSync,
  writeFileSync,
  chmodSync,
  existsSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import cairnPlugin from "./index.js";

// Integration test for BC-022: an end-event bridge failure must be recorded
// as a degradation rather than silently swallowed (the previous behavior
// deleted the in-flight entry and logged nothing actionable, orphaning the
// begin event invisibly).

// Write an executable node script the plugin can spawn via CAIRN_BRIDGE_PATH.
// The real `cairn-bridge` is an installed executable; the fakes need a
// shebang + execute bits to be spawnable the same way.
function writeBridge(path, body) {
  writeFileSync(path, `#!/usr/bin/env node\n${body}\n`, { mode: 0o755 });
  chmodSync(path, 0o755);
}

let root;
let fakeBridge;

beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), "cairn-it-"));
  // A fake bridge: succeed for "begin", fail (exit 1) for "end". This
  // simulates the regista side being unreachable at end-event time.
  fakeBridge = join(root, "fake-bridge.mjs");
  writeBridge(
    fakeBridge,
    `import { readFileSync } from "node:fs";
const raw = readFileSync(0, "utf8");
const msg = JSON.parse(raw);
if (msg.action === "begin") {
  process.stdout.write(JSON.stringify({ status: "ok", work_item_id: "00000000-0000-0000-0000-000000000001", args_hash: "sha256:deadbeef" }) + "\\n");
} else if (msg.action === "end") {
  process.stderr.write("simulated regista failure\\n");
  process.exit(1);
} else if (msg.action === "attest_scope" || msg.action === "attest_session") {
  process.stdout.write(JSON.stringify({ status: "ok", event_id: "ev-1" }) + "\\n");
} else {
  process.exit(2);
}`,
  );
  process.env.CAIRN_BRIDGE_PATH = fakeBridge;
});

afterAll(() => {
  rmSync(root, { recursive: true, force: true });
});

function mkClient(logs) {
  return { app: { log: (m) => logs.push(m) } };
}

describe("BC-022: end-event failure is surfaced, not swallowed", () => {
  test("a failing end records a degradation and logs the orphan", async () => {
    const logs = [];
    const plugin = await cairnPlugin({ client: mkClient(logs), stateDir: root });
    const sessionID = "sess-endfail";
    const callID = "call-1";

    await plugin["tool.execute.before"](
      { tool: "Write", sessionID, callID },
      { args: { filePath: join(root, "out.txt"), content: "x" } },
    );

    await plugin["tool.execute.after"](
      {
        tool: "Write",
        sessionID,
        callID,
        args: { filePath: join(root, "out.txt"), content: "x" },
      },
      { output: "written", result: { exit_code: 0 } },
    );

    // The end failed, so an orphan marker must be present...
    const logPath = join(root, sessionID, "degradation.log");
    expect(existsSync(logPath)).toBe(true);
    const entries = readFileSync(logPath, "utf8").trim().split("\n").map(JSON.parse);
    const postFail = entries.find((e) => e.action === "post");
    expect(postFail).toBeDefined();
    expect(postFail.detail).toContain("Write");
    expect(postFail.detail).toContain("00000000-0000-0000-0000-000000000001");
    expect(postFail.detail).toMatch(/orphan/i);

    // ...and the failure was surfaced to the user (not silent).
    expect(logs.some((l) => /end Write FAILED/i.test(l))).toBe(true);
    expect(logs.some((l) => /provenance gap/i.test(l))).toBe(true);

    // The in-flight entry was cleaned up (no unbounded retention of failures).
    expect(plugin._sessionMapSize()).toBe(0);
  });

  test("a failing begin records a degradation (tool call unrecorded)", async () => {
    // Use a fresh root + a begin-failing fake bridge for this case only.
    const sub = mkdtempSync(join(tmpdir(), "cairn-beginfail-"));
    const beginFailBridge = join(sub, "bf.mjs");
    writeBridge(
      beginFailBridge,
      `import { readFileSync } from "node:fs";
JSON.parse(readFileSync(0, "utf8"));
process.stderr.write("begin fails\\n");
process.exit(1);`,
    );
    const saved = process.env.CAIRN_BRIDGE_PATH;
    process.env.CAIRN_BRIDGE_PATH = beginFailBridge;
    try {
      const logs = [];
      const plugin = await cairnPlugin({ client: mkClient(logs), stateDir: sub });
      await plugin["tool.execute.before"](
        { tool: "Edit", sessionID: "sess-bf", callID: "c1" },
        { args: { filePath: "/tmp/x" } },
      );

      const entries = readFileSync(join(sub, "sess-bf", "degradation.log"), "utf8")
        .trim()
        .split("\n")
        .map(JSON.parse);
      const preFail = entries.find((e) => e.action === "pre");
      expect(preFail).toBeDefined();
      expect(preFail.detail).toContain("Edit");
      expect(preFail.detail).toMatch(/unrecorded/i);
      expect(plugin._sessionMapSize()).toBe(0);
    } finally {
      process.env.CAIRN_BRIDGE_PATH = saved;
      rmSync(sub, { recursive: true, force: true });
    }
  });
});

describe("happy path: begin+end both succeed leaves no degradation", async () => {
  test("no degradation.log on a clean round-trip", async () => {
    // Separate root where the fake bridge (still begin-ok) needs end-ok too.
    const sub = mkdtempSync(join(tmpdir(), "cairn-happy-"));
    const okBridge = join(sub, "ok.mjs");
    writeBridge(
      okBridge,
      `import { readFileSync } from "node:fs";
const msg = JSON.parse(readFileSync(0, "utf8"));
const out = msg.action === "begin"
  ? { status: "ok", work_item_id: "00000000-0000-0000-0000-000000000002", args_hash: "sha256:cafe" }
  : { status: "ok", event_id: "ev-" + msg.action };
process.stdout.write(JSON.stringify(out) + "\\n");`,
    );
    const saved = process.env.CAIRN_BRIDGE_PATH;
    process.env.CAIRN_BRIDGE_PATH = okBridge;
    try {
      const plugin = await cairnPlugin({ client: mkClient([]), stateDir: sub });
      await plugin["tool.execute.before"](
        { tool: "Read", sessionID: "sess-happy", callID: "c1" },
        { args: { filePath: "/tmp/r" } },
      );
      await plugin["tool.execute.after"](
        { tool: "Read", sessionID: "sess-happy", callID: "c1", args: { filePath: "/tmp/r" } },
        { output: "data", result: { exit_code: 0 } },
      );
      expect(existsSync(join(sub, "sess-happy", "degradation.log"))).toBe(false);
      expect(plugin._sessionMapSize()).toBe(0);
    } finally {
      process.env.CAIRN_BRIDGE_PATH = saved;
      rmSync(sub, { recursive: true, force: true });
    }
  });
});
