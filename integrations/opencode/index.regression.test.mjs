import { test } from "node:test";
import assert from "node:assert/strict";
import {
  mkdtempSync,
  rmSync,
  readFileSync,
  existsSync,
  writeFileSync,
  chmodSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import cairnPlugin from "./index.js";

// Regression tests for the WI-045 review findings 1 and 2.
//
// index.test.js and plugin.test.js import "bun:test", which only bun's
// runtime can resolve. This host (mvmcc03) has node but not bun, so those
// suites cannot run here. This file is written against node's built-in test
// runner instead, exercising the same plugin entry points through the real
// (non-bun) invokeBridge/spawn path. Run with:
//   node --test index.regression.test.mjs

function writeBridge(path, body) {
  writeFileSync(path, `#!/usr/bin/env node\n${body}\n`, { mode: 0o755 });
  chmodSync(path, 0o755);
}

// A bash bridge starts roughly two orders of magnitude faster than a node
// bridge (measured on this host: ~1.5ms vs ~125ms per spawn). Finding 2's
// test spawns hundreds of bridge processes to exercise the dedup bound, so
// it uses this instead of writeBridge() to keep the suite fast.
function writeBashBridge(path, recordFile) {
  writeFileSync(
    path,
    `#!/usr/bin/env bash\ncat >> ${JSON.stringify(recordFile)}\necho '{"status":"ok","event_id":"ev"}'\n`,
    { mode: 0o755 },
  );
  chmodSync(path, 0o755);
}

function mkClient(logs = []) {
  return { app: { log: (m) => logs.push(m) } };
}

function readRecord(recordFile) {
  if (!existsSync(recordFile)) return [];
  return readFileSync(recordFile, "utf8")
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

test("finding 1: a second message.updated for the same key does not fire a second bridge call while the first is in flight", async () => {
  const sub = mkdtempSync(join(tmpdir(), "cairn-f1-"));
  const saved = process.env.CAIRN_BRIDGE_PATH;
  try {
    const recordFile = join(sub, "record.jsonl");
    const startsFile = join(sub, "starts.jsonl");
    const releaseFile = join(sub, "release");
    const bridge = join(sub, "rec.mjs");
    // The bridge announces that it has started, then blocks until the test
    // releases it. The test therefore holds the in-flight window open itself
    // rather than betting that a fixed delay outruns node's startup cost —
    // that bet is what CI runs 32395152087 and 32613140792 lost, reporting
    // "got 0" because the first call had not landed yet, which is a slow
    // runner and not the duplicate-call regression this test is here for.
    writeBridge(
      bridge,
      `import { readFileSync, appendFileSync, existsSync } from "node:fs";
const msg = JSON.parse(readFileSync(0, "utf8"));
appendFileSync(${JSON.stringify(startsFile)}, JSON.stringify(msg) + "\\n");
while (!existsSync(${JSON.stringify(releaseFile)})) {
  await new Promise((resolve) => setTimeout(resolve, 5));
}
appendFileSync(${JSON.stringify(recordFile)}, JSON.stringify(msg) + "\\n");
process.stdout.write(JSON.stringify({ status: "ok", event_id: "ev" }) + "\\n");`,
    );
    process.env.CAIRN_BRIDGE_PATH = bridge;

    const plugin = await cairnPlugin({ client: mkClient(), stateDir: sub });
    const eventFor = (modelID) => ({
      type: "message.updated",
      properties: {
        info: {
          id: "msg-1",
          sessionID: "sess-dup",
          role: "assistant",
          providerID: "provider-b",
          modelID,
        },
      },
    });

    // Bounded below the 10s bridge spawn timeout so a genuinely stuck bridge
    // surfaces as this timeout rather than as a killed child.
    async function waitFor(what, satisfied) {
      for (let attempt = 0; attempt < 500; attempt += 1) {
        if (satisfied()) return;
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
      throw new Error(`timed out waiting for ${what}`);
    }
    const startsFor = (modelID) =>
      readRecord(startsFile).filter((call) => call.observed_model_id === modelID);
    const recordsFor = (modelID) =>
      readRecord(recordFile).filter(
        (call) => call.action === "model_observation" && call.observed_model_id === modelID,
      );

    // Fire the first observation and wait for its bridge to block. From here
    // the call is provably in flight: the submit gate clears
    // pendingModelObservations only in the invokeBridge().finally(), which
    // cannot run until this child exits.
    await plugin.event({ event: eventFor("glm-5.2") });
    await waitFor("the first bridge call to start", () => startsFor("glm-5.2").length >= 1);

    // The same key again, while the first is still in flight. The submit gate
    // is synchronous, so with the first call pending the outcome is settled
    // here with no timing left in it. Under the bug (gate checked only
    // observedModels, which is populated in the bridge's .then(), and not
    // pendingModelObservations) this issued a second bridge call.
    await plugin.event({ event: eventFor("glm-5.2") });

    // A different key is never deduped, so its call is a barrier: it is
    // dispatched after any duplicate call would have been, so once it has
    // started, a duplicate would have started too.
    await plugin.event({ event: eventFor("glm-5.3") });
    await waitFor("the barrier bridge call to start", () => startsFor("glm-5.3").length >= 1);

    assert.equal(
      startsFor("glm-5.2").length,
      1,
      `expected exactly one bridge call while the first was in flight, got ${startsFor("glm-5.2").length}`,
    );

    // Release everything and confirm the same count on the recorded side,
    // once every bridge that started has finished.
    writeFileSync(releaseFile, "");
    await waitFor(
      "every started bridge call to finish",
      () => readRecord(recordFile).length >= readRecord(startsFile).length,
    );
    assert.equal(
      recordsFor("glm-5.2").length,
      1,
      `expected exactly one recorded observation for the duplicated key, got ${recordsFor("glm-5.2").length}`,
    );
    assert.equal(recordsFor("glm-5.3").length, 1, "the distinct key should not be deduped");
  } finally {
    process.env.CAIRN_BRIDGE_PATH = saved;
    rmSync(sub, { recursive: true, force: true });
  }
});

test("finding 2: the persisted model-observation dedup file is not truncated far below the in-memory bound", async () => {
  const sub = mkdtempSync(join(tmpdir(), "cairn-f2-"));
  const saved = process.env.CAIRN_BRIDGE_PATH;
  try {
    const recordFile = join(sub, "record.jsonl");
    const bridge = join(sub, "rec.sh");
    writeBashBridge(bridge, recordFile);
    process.env.CAIRN_BRIDGE_PATH = bridge;

    const plugin = await cairnPlugin({ client: mkClient(), stateDir: sub });
    const sessionID = "sess-bound";
    const persistedPath = join(sub, sessionID, "model-observations.json");

    function persistedCount() {
      if (!existsSync(persistedPath)) return 0;
      try {
        return JSON.parse(readFileSync(persistedPath, "utf8")).length;
      } catch {
        return 0;
      }
    }

    async function waitForPersistedCount(expected) {
      for (let attempt = 0; attempt < 200; attempt += 1) {
        if (persistedCount() >= expected) return;
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
      throw new Error(`persisted count never reached ${expected} (stuck at ${persistedCount()})`);
    }

    // Drive more distinct observations through one session than the old
    // persisted-file bound (256) — but well under the shared 4096 bound —
    // and confirm every one of them survives to disk. Before the fix, this
    // file was truncated to the most recent 256 keys regardless of how many
    // the in-memory set retained. Each iteration waits for its own
    // observation to land on disk before firing the next one, so the
    // read-modify-write persist step (a separate, pre-existing concern from
    // the persisted-vs-in-memory bound mismatch this test targets) never has
    // two writes racing concurrently.
    const total = 300;
    for (let i = 0; i < total; i += 1) {
      await plugin.event({
        event: {
          type: "message.updated",
          properties: {
            info: {
              id: `msg-${i}`,
              sessionID,
              role: "assistant",
              providerID: "provider",
              modelID: `model-${i}`,
            },
          },
        },
      });
      await waitForPersistedCount(i + 1);
    }

    const persisted = JSON.parse(readFileSync(persistedPath, "utf8"));
    assert.equal(
      persisted.length,
      total,
      `persisted dedup window truncated ${total} keys down to ${persisted.length}; ` +
        "it should now share the 4096 in-memory bound instead of the old 256 slice",
    );
  } finally {
    process.env.CAIRN_BRIDGE_PATH = saved;
    rmSync(sub, { recursive: true, force: true });
  }
});
