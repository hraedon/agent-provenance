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
    const bridge = join(sub, "rec.mjs");
    // Deliberately slow (50ms) so the first call is still in flight when the
    // second event fires synchronously after it — this is the
    // streaming-update race the finding describes ("message.updated" firing
    // repeatedly while an assistant message streams).
    writeBridge(
      bridge,
      `import { readFileSync, appendFileSync } from "node:fs";
const msg = JSON.parse(readFileSync(0, "utf8"));
setTimeout(() => {
  appendFileSync(${JSON.stringify(recordFile)}, JSON.stringify(msg) + "\\n");
  process.stdout.write(JSON.stringify({ status: "ok", event_id: "ev" }) + "\\n");
}, 50);`,
    );
    process.env.CAIRN_BRIDGE_PATH = bridge;

    const plugin = await cairnPlugin({ client: mkClient(), stateDir: sub });
    const event = {
      type: "message.updated",
      properties: {
        info: {
          id: "msg-1",
          sessionID: "sess-dup",
          role: "assistant",
          providerID: "provider-b",
          modelID: "glm-5.2",
        },
      },
    };

    // Fire the same event twice back-to-back. plugin.event() returns as soon
    // as it has synchronously kicked off (but not awaited) the bridge call,
    // so the second call reaches the gate before the first's promise
    // resolves. Under the bug (submit gate checked only observedModels, not
    // pendingModelObservations) this issued a second bridge call.
    await plugin.event({ event });
    await plugin.event({ event });

    // Give the slow bridge time to respond and the .then() to run.
    await new Promise((resolve) => setTimeout(resolve, 300));

    const observations = readRecord(recordFile).filter(
      (call) => call.action === "model_observation",
    );
    assert.equal(
      observations.length,
      1,
      `expected exactly one bridge call while the first was in flight, got ${observations.length}`,
    );
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
