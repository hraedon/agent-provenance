import { expect, test, describe, beforeAll, afterAll } from "bun:test";
import {
  mkdtempSync,
  rmSync,
  readFileSync,
  writeFileSync,
  chmodSync,
  existsSync,
  mkdirSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";

// Compute the collision-free in-flight filename the plugin uses (WI-024 /
// adversarial review H1). Mirrors ``inflightFileName`` in index.js.
function inflightFile(sessionId, callID) {
  return createHash("sha256").update(`${sessionId}:${callID}`).digest("hex") + ".json";
}

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

describe("WI-024: in-flight work items survive a plugin restart", async () => {
  test("begin persists an in-flight entry that a fresh plugin recovers", async () => {
    const sub = mkdtempSync(join(tmpdir(), "cairn-restart-"));
    const okBridge = join(sub, "ok.mjs");
    writeBridge(
      okBridge,
      `import { readFileSync } from "node:fs";
const msg = JSON.parse(readFileSync(0, "utf8"));
const out = msg.action === "begin"
  ? { status: "ok", work_item_id: "00000000-0000-0000-0000-000000000003", args_hash: "sha256:beef" }
  : { status: "ok", event_id: "ev-" + msg.action };
process.stdout.write(JSON.stringify(out) + "\\n");`,
    );
    const saved = process.env.CAIRN_BRIDGE_PATH;
    process.env.CAIRN_BRIDGE_PATH = okBridge;
    try {
      // First "process": begin succeeds, creating a persisted in-flight entry.
      const p1 = await cairnPlugin({ client: mkClient([]), stateDir: sub });
      await p1["tool.execute.before"](
        { tool: "Write", sessionID: "sess-restart", callID: "c9" },
        { args: { filePath: join(sub, "x.txt"), content: "y" } },
      );
      // An in-flight file now exists on disk (hash-named, collision-free).
      const file = inflightFile("sess-restart", "c9");
      const inflightFile2 = join(sub, "sess-restart", "inflight", file);
      expect(existsSync(inflightFile2)).toBe(true);

      // Simulate a restart: drop p1, instantiate a fresh plugin against the
      // same state dir. The recovery loop should re-seed the in-memory map.
      const p2 = await cairnPlugin({ client: mkClient([]), stateDir: sub });
      expect(p2._sessionMapSize()).toBe(1);

      // The recovered entry lets the after hook close the work item cleanly.
      await p2["tool.execute.after"](
        { tool: "Write", sessionID: "sess-restart", callID: "c9", args: { filePath: "/tmp/x" } },
        { output: "written", result: { exit_code: 0 } },
      );
      expect(p2._sessionMapSize()).toBe(0);
      // Clean close removes the in-flight file.
      expect(existsSync(inflightFile2)).toBe(false);
      // No degradation on a successful recovery + close.
      expect(existsSync(join(sub, "sess-restart", "degradation.log"))).toBe(false);
    } finally {
      process.env.CAIRN_BRIDGE_PATH = saved;
      rmSync(sub, { recursive: true, force: true });
    }
  });

  test("stale in-flight entries from a crashed process are recorded as orphans", async () => {
    const sub = mkdtempSync(join(tmpdir(), "cairn-stale-"));
    const okBridge = join(sub, "ok.mjs");
    writeBridge(
      okBridge,
      `import { readFileSync } from "node:fs";
const msg = JSON.parse(readFileSync(0, "utf8"));
const out = msg.action === "begin"
  ? { status: "ok", work_item_id: "00000000-0000-0000-0000-000000000004", args_hash: "sha256:old" }
  : { status: "ok", event_id: "ev-" + msg.action };
process.stdout.write(JSON.stringify(out) + "\\n");`,
    );
    const saved = process.env.CAIRN_BRIDGE_PATH;
    process.env.CAIRN_BRIDGE_PATH = okBridge;
    try {
      // Manually plant a stale in-flight entry that predates the staleness
      // threshold, simulating a begin from a process that crashed long ago.
      const staleDir = join(sub, "sess-stale", "inflight");
      mkdirSync(staleDir, { recursive: true });
      const old = new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(); // 2h ago
      const staleFile = join(staleDir, inflightFile("sess-stale", "c1"));
      writeFileSync(
        staleFile,
        JSON.stringify({
          workItemId: "00000000-0000-0000-0000-000000000004",
          tool: "Edit",
          sessionId: "sess-stale",
          callID: "c1",
          beganAt: old,
        }) + "\n",
      );

      const logs = [];
      const plugin = await cairnPlugin({ client: mkClient(logs), stateDir: sub });
      // The stale entry was not re-seeded into the in-memory map...
      expect(plugin._sessionMapSize()).toBe(0);
      // ...but it was recorded as a degraded orphan.
      const logPath = join(sub, "sess-stale", "degradation.log");
      expect(existsSync(logPath)).toBe(true);
      const entries = readFileSync(logPath, "utf8").trim().split("\n").map(JSON.parse);
      const orphan = entries.find((e) => e.action === "orphan_restart");
      expect(orphan).toBeDefined();
      expect(orphan.detail).toContain("Edit");
      expect(orphan.detail).toMatch(/orphan/i);
      // The stale in-flight file was removed so it isn't re-recovered.
      expect(existsSync(staleFile)).toBe(false);
    } finally {
      process.env.CAIRN_BRIDGE_PATH = saved;
      rmSync(sub, { recursive: true, force: true });
    }
  });

  test("a failed end keeps the in-flight file so a restart can surface the orphan", async () => {
    // Adversarial review H3: after a failed end the begin is an orphan, but
    // the persisted entry must survive so a restart's staleness sweep can
    // record it rather than silently losing it.
    const sub = mkdtempSync(join(tmpdir(), "cairn-failedend-"));
    const beginOnlyBridge = join(sub, "bo.mjs");
    writeBridge(
      beginOnlyBridge,
      `import { readFileSync } from "node:fs";
const msg = JSON.parse(readFileSync(0, "utf8"));
if (msg.action === "begin") {
  process.stdout.write(JSON.stringify({ status: "ok", work_item_id: "00000000-0000-0000-0000-000000000005", args_hash: "sha256:f" }) + "\\n");
} else if (msg.action === "end") {
  process.stderr.write("end fails\\n");
  process.exit(1);
} else {
  process.stdout.write(JSON.stringify({ status: "ok", event_id: "ev" }) + "\\n");
}`,
    );
    const saved = process.env.CAIRN_BRIDGE_PATH;
    process.env.CAIRN_BRIDGE_PATH = beginOnlyBridge;
    try {
      const p1 = await cairnPlugin({ client: mkClient([]), stateDir: sub });
      await p1["tool.execute.before"](
        { tool: "Bash", sessionID: "sess-fe", callID: "c1" },
        { args: { command: "true" } },
      );
      await p1["tool.execute.after"](
        { tool: "Bash", sessionID: "sess-fe", callID: "c1", args: { command: "true" } },
        { output: "", result: { exit_code: 0 } },
      );
      // The end failed; the in-memory entry was removed but the file must
      // persist so a restart can recover/surface it.
      const file = join(sub, "sess-fe", "inflight", inflightFile("sess-fe", "c1"));
      expect(existsSync(file)).toBe(true);
    } finally {
      process.env.CAIRN_BRIDGE_PATH = saved;
      rmSync(sub, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// WI-011 item 2: the plugin's `event` hook handles session.started.
// plugin.test.js exercised attest_session through the fake bridge but never
// invoked the plugin's event handler itself; these tests drive plugin.event().
// ---------------------------------------------------------------------------

// A fake bridge that records every message it receives (one JSON per line) to
// the file named by CAIRN_TEST_RECORD, then answers attest_session with ok.
function writeRecordingBridge(path, recordFile) {
  writeBridge(
    path,
    `import { readFileSync, appendFileSync } from "node:fs";
const msg = JSON.parse(readFileSync(0, "utf8"));
appendFileSync(${JSON.stringify(recordFile)}, JSON.stringify(msg) + "\\n");
process.stdout.write(JSON.stringify({ status: "ok", event_id: "ev-" + msg.action }) + "\\n");`,
  );
}

function readRecord(recordFile) {
  if (!existsSync(recordFile)) return [];
  return readFileSync(recordFile, "utf8").trim().split("\n").filter(Boolean).map(JSON.parse);
}

async function waitForObservation(recordFile) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (readRecord(recordFile).some((call) => call.action === "model_observation")) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error("model observation bridge call did not complete");
}

describe("WI-011: plugin event handler attests session.started", () => {
  test("session.started invokes attest_session with the session id and harness", async () => {
    const sub = mkdtempSync(join(tmpdir(), "cairn-evstart-"));
    const recordFile = join(sub, "record.jsonl");
    const bridge = join(sub, "rec.mjs");
    writeRecordingBridge(bridge, recordFile);
    const savedBridge = process.env.CAIRN_BRIDGE_PATH;
    const savedAttest = process.env.CAIRN_ATTEST_ON_START;
    process.env.CAIRN_BRIDGE_PATH = bridge;
    process.env.CAIRN_ATTEST_ON_START = "1";
    try {
      const plugin = await cairnPlugin({ client: mkClient([]), stateDir: sub });
      await plugin.event({
        event: { type: "session.started", properties: { sessionID: "sess-ev1", version: "1.2.3" } },
      });

      const calls = readRecord(recordFile);
      const attest = calls.find((c) => c.action === "attest_session");
      expect(attest).toBeDefined();
      expect(attest.session_id).toBe("sess-ev1");
      expect(attest.harnesses).toEqual([{ name: "opencode", version: "1.2.3" }]);
      // No degradation on a successful attestation.
      expect(existsSync(join(sub, "sess-ev1", "degradation.log"))).toBe(false);
    } finally {
      process.env.CAIRN_BRIDGE_PATH = savedBridge;
      if (savedAttest === undefined) delete process.env.CAIRN_ATTEST_ON_START;
      else process.env.CAIRN_ATTEST_ON_START = savedAttest;
      rmSync(sub, { recursive: true, force: true });
    }
  });

  test("session.started is ignored when CAIRN_ATTEST_ON_START is off", async () => {
    const sub = mkdtempSync(join(tmpdir(), "cairn-evoff-"));
    const recordFile = join(sub, "record.jsonl");
    const bridge = join(sub, "rec.mjs");
    writeRecordingBridge(bridge, recordFile);
    const savedBridge = process.env.CAIRN_BRIDGE_PATH;
    const savedAttest = process.env.CAIRN_ATTEST_ON_START;
    process.env.CAIRN_BRIDGE_PATH = bridge;
    process.env.CAIRN_ATTEST_ON_START = "0";
    try {
      const plugin = await cairnPlugin({ client: mkClient([]), stateDir: sub });
      await plugin.event({
        event: { type: "session.started", properties: { sessionID: "sess-ev0" } },
      });
      const attest = readRecord(recordFile).find((c) => c.action === "attest_session");
      expect(attest).toBeUndefined();
    } finally {
      process.env.CAIRN_BRIDGE_PATH = savedBridge;
      if (savedAttest === undefined) delete process.env.CAIRN_ATTEST_ON_START;
      else process.env.CAIRN_ATTEST_ON_START = savedAttest;
      rmSync(sub, { recursive: true, force: true });
    }
  });

  test("session.started without a sessionID degrades and does not attest", async () => {
    const sub = mkdtempSync(join(tmpdir(), "cairn-evnosid-"));
    const recordFile = join(sub, "record.jsonl");
    const bridge = join(sub, "rec.mjs");
    writeRecordingBridge(bridge, recordFile);
    const savedBridge = process.env.CAIRN_BRIDGE_PATH;
    const savedAttest = process.env.CAIRN_ATTEST_ON_START;
    process.env.CAIRN_BRIDGE_PATH = bridge;
    process.env.CAIRN_ATTEST_ON_START = "1";
    try {
      const plugin = await cairnPlugin({ client: mkClient([]), stateDir: sub });
      await plugin.event({ event: { type: "session.started", properties: {} } });

      // No attestation was attempted...
      expect(readRecord(recordFile).find((c) => c.action === "attest_session")).toBeUndefined();
      // ...and the missing sessionID was recorded as a degradation.
      const logPath = join(sub, "session-start", "degradation.log");
      expect(existsSync(logPath)).toBe(true);
      const entry = readFileSync(logPath, "utf8").trim().split("\n").map(JSON.parse).pop();
      expect(entry.action).toBe("session_start");
      expect(entry.detail).toMatch(/sessionID/i);
    } finally {
      process.env.CAIRN_BRIDGE_PATH = savedBridge;
      if (savedAttest === undefined) delete process.env.CAIRN_ATTEST_ON_START;
      else process.env.CAIRN_ATTEST_ON_START = savedAttest;
      rmSync(sub, { recursive: true, force: true });
    }
  });
});

describe("WI-045: OpenCode records the dispatched model", () => {
  test("configured model A dispatching model B captures B", async () => {
    const sub = mkdtempSync(join(tmpdir(), "cairn-model-"));
    const recordFile = join(sub, "record.jsonl");
    const bridge = join(sub, "rec.mjs");
    writeRecordingBridge(bridge, recordFile);
    const savedBridge = process.env.CAIRN_BRIDGE_PATH;
    process.env.CAIRN_BRIDGE_PATH = bridge;
    try {
      const plugin = await cairnPlugin({ client: mkClient([]), stateDir: sub });
      await plugin["chat.message"](
        {
          sessionID: "sess-model",
          agent: "adversarial-reviewer-nemotron",
          model: { providerID: "provider-a", modelID: "nemotron-3-ultra" },
        },
        { message: {}, parts: [] },
      );
      const actual = {
        type: "message.updated",
        properties: {
          info: {
            id: "msg-1",
            sessionID: "sess-model",
            role: "assistant",
            providerID: "provider-b",
            modelID: "glm-5.2",
            agent: "adversarial-reviewer-nemotron",
          },
        },
      };
      await plugin.event({ event: actual });
      await plugin.event({ event: actual });
      await waitForObservation(recordFile);

      const observations = readRecord(recordFile).filter(
        (call) => call.action === "model_observation",
      );
      expect(observations).toHaveLength(1);
      expect(observations[0].observed_provider_id).toBe("provider-b");
      expect(observations[0].observed_model_id).toBe("glm-5.2");
      expect(observations[0].requested_provider_id).toBe("provider-a");
      expect(observations[0].requested_model_id).toBe("nemotron-3-ultra");
      expect(observations[0].observation_id).toBeTruthy();
      expect(observations[0].observed_model_id).not.toContain(
        observations[0].agent ?? "adversarial-reviewer-nemotron",
      );

      const reloaded = await cairnPlugin({ client: mkClient([]), stateDir: sub });
      await reloaded.event({ event: actual });
      const afterReload = readRecord(recordFile).filter(
        (call) => call.action === "model_observation",
      );
      expect(afterReload).toHaveLength(1);
      expect(afterReload[0].observation_id).toBe(observations[0].observation_id);
    } finally {
      process.env.CAIRN_BRIDGE_PATH = savedBridge;
      rmSync(sub, { recursive: true, force: true });
    }
  });

  test("model observation never waits for the bridge", async () => {
    const sub = mkdtempSync(join(tmpdir(), "cairn-model-nonblocking-"));
    const recordFile = join(sub, "record.jsonl");
    const bridge = join(sub, "slow.mjs");
    writeBridge(
      bridge,
      `import { readFileSync, appendFileSync } from "node:fs";
const msg = JSON.parse(readFileSync(0, "utf8"));
setTimeout(() => {
  appendFileSync(${JSON.stringify(recordFile)}, JSON.stringify(msg) + "\\n");
  process.stdout.write(JSON.stringify({ status: "ok", event_id: "ev" }) + "\\n");
}, 300);`,
    );
    const savedBridge = process.env.CAIRN_BRIDGE_PATH;
    process.env.CAIRN_BRIDGE_PATH = bridge;
    try {
      const plugin = await cairnPlugin({ client: mkClient([]), stateDir: sub });
      const started = performance.now();
      await plugin.event({
        event: {
          type: "message.updated",
          properties: {
            info: {
              id: "msg-slow",
              sessionID: "sess-slow",
              role: "assistant",
              providerID: "provider",
              modelID: "glm-5.2",
            },
          },
        },
      });
      expect(performance.now() - started).toBeLessThan(150);
      await waitForObservation(recordFile);
    } finally {
      process.env.CAIRN_BRIDGE_PATH = savedBridge;
      rmSync(sub, { recursive: true, force: true });
    }
  });
});
