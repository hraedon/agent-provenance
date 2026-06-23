import { spawn } from "node:child_process";
import { mkdirSync, appendFileSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

/**
 * Cairn provenance plugin — wraps the Python bridge script to log every
 * tool call to regista.
 *
 * Installation:
 *   1. Ensure `cairn` Python package is installed and `cairn-bridge` is in PATH
 *   2. Set environment variables:
 *      - CAIRN_DSN
 *      - CAIRN_PROJECT
 *      - CAIRN_KEY_PATH
 *      - PRINCIPAL_ID (optional)
 *   3. Add to opencode.json:
 *        "plugins": ["cairn-plugin"]
 *
 * Architecture:
 *   The plugin is a thin Node.js wrapper.  All heavy lifting (regista
 *   connection, event signing, file digest computation) lives in the Python
 *   `cairn_bridge.py` script that ships with the `cairn` Python package.
 *   This keeps Cairn the single source of truth and avoids duplicating logic
 *   across languages.
 *
 * Provenance-completeness contract (BC-022):
 *   A ``begin`` event that succeeds creates a regista work item; the matching
 *   ``end`` event must also be recorded or that work item is an *orphan* — a
 *   provenance gap of exactly the kind README §4 names as the residual
 *   "missing events" problem.  Two failure modes used to be swallowed
 *   silently here:
 *     1. The bridge call for the ``end`` action failed → the begin was
 *        orphaned with no record that the end was attempted and lost.
 *     2. The in-memory session map grew without bound (no TTL / eviction) →
 *        under sustained load an unclosed begin could be dropped, again
 *        orphaning it.
 *   Both are now surfaced through a durable, per-session degradation log
 *   (mirroring the Claude Code hook's ``_mark_degraded``), so a missing end
 *   is *discoverable* by an auditor rather than invisible.  Failures are not
 *   retried blindly because the bridge has no idempotency key and a retry
 *   after a partial success would create a duplicate event; the degradation
 *   log is the honest record instead.
 */

const BRIDGE_TIMEOUT_MS = parseInt(process.env.CAIRN_BRIDGE_TIMEOUT_MS ?? "10000", 10);

// Bound on the number of in-flight (begin-issued, end-pending) tool calls
// tracked in memory.  Each entry is ~small, but without a bound the map grows
// forever if an ``after`` hook never fires (tool crash, harness bug).  When
// the bound is reached the oldest unclosed begin is evicted and recorded as a
// degradation so the resulting orphan is discoverable.
const DEFAULT_MAX_SESSION_ENTRIES = parseInt(
  process.env.CAIRN_MAX_SESSION_ENTRIES ?? "10000",
  10,
);

const DEFAULT_STATE_DIR = process.env.CAIRN_STATE_DIR ?? join(tmpdir(), "cairn-sessions");

/**
 * Extract file paths from a tool-args object.  Covers the common argument
 * shapes used by opencode tools (single path under filePath/path/file, or a
 * list under files).  Pure helper, exported for testing.
 *
 * @param {Record<string, unknown>} [args]
 * @returns {string[]}
 */
export function extractFiles(args) {
  const files = [];
  if (!args || typeof args !== "object") return files;
  for (const key of ["filePath", "path", "file"]) {
    const v = args[key];
    if (typeof v === "string") files.push(v);
  }
  const many = args.files;
  if (Array.isArray(many)) {
    for (const f of many) if (typeof f === "string") files.push(f);
  } else if (typeof many === "string") {
    files.push(many);
  }
  return files;
}

/**
 * Sanitize a session id so it is safe to use as a filesystem path component.
 * Matches the Claude Code hook's sanitization so both harnesses share one
 * state layout.  Pure helper, exported for testing.
 *
 * @param {string} sessionId
 * @returns {string}
 */
export function safeSessionId(sessionId) {
  return String(sessionId).replace(/[^a-zA-Z0-9._-]/g, "_");
}

/**
 * Resolve (and create) the per-session state directory.  Mirrors the Claude
 * Code hook layout: ``<stateDir>/<safeSessionId>/`` with 0o700 permissions.
 *
 * A null/empty override falls back to the default so callers can forward an
 * absent option without coercing it themselves.
 *
 * @param {string} sessionId
 * @param {string} [stateDir]  override, mainly for tests
 * @returns {string} absolute path to the session state dir
 */
export function stateDir(sessionId, stateDir) {
  const base = stateDir || DEFAULT_STATE_DIR;
  const dir = join(base, safeSessionId(sessionId));
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  try {
    // Restrict to owner-only. Best-effort: the dir may pre-exist with broader
    // perms; tightening it defends the degradation log's integrity.
    chmodSync(dir, 0o700);
  } catch {
    // chmod best-effort; ignore.
  }
  return dir;
}

/**
 * Append a JSON degradation record to the per-session ``degradation.log``.
 * This is the durable, auditor-inspectable record that a provenance event
 * was attempted and lost (begin or end), or that an unclosed begin was
 * evicted from the in-memory map.  Mirrors the Claude Code hook so an
 * auditor inspects one log shape across harnesses.
 *
 * Pure-with-side-effects helper, exported for testing.
 *
 * @param {string} sessionId
 * @param {string} action   e.g. "pre" | "post" | "evicted"
 * @param {string} detail
 * @param {string} [stateDirOverride]
 */
export function markDegraded(sessionId, action, detail, stateDirOverride) {
  const ts = new Date().toISOString();
  const dir = stateDir(sessionId, stateDirOverride);
  const entry = JSON.stringify({ ts, action, detail }) + "\n";
  const marker = join(dir, "degradation.log");
  appendFileSync(marker, entry, { mode: 0o600 });
}

/**
 * Create a bounded FIFO map for tracking in-flight tool calls (begin issued,
 * end pending).  JS Map preserves insertion order, so the oldest entry is
 * evicted first.  ``set`` returns the evicted entry (if any) so the caller
 * can record a degradation for an unclosed begin.  Exported for testing.
 *
 * @param {{ maxSize?: number }} [opts]
 * @returns {{
 *   get: (key: string) => Record<string, unknown> | undefined,
 *   set: (key: string, value: Record<string, unknown>) => { evictedKey: string|null, evicted: Record<string, unknown>|null },
 *   delete: (key: string) => boolean,
 *   has: (key: string) => boolean,
 *   size: () => number,
 * }}
 */
export function createSessionMap(opts = {}) {
  const maxSize = opts.maxSize ?? DEFAULT_MAX_SESSION_ENTRIES;
  if (!Number.isFinite(maxSize) || maxSize < 1) {
    throw new TypeError(`CAIRN_MAX_SESSION_ENTRIES must be a positive integer, got ${maxSize}`);
  }
  const map = new Map();
  return {
    get(key) {
      return map.get(key);
    },
    set(key, value) {
      let evictedKey = null;
      let evicted = null;
      if (!map.has(key) && map.size >= maxSize) {
        evictedKey = map.keys().next().value;
        evicted = map.get(evictedKey) ?? null;
        map.delete(evictedKey);
      }
      map.set(key, value);
      return { evictedKey, evicted };
    },
    delete(key) {
      return map.delete(key);
    },
    has(key) {
      return map.has(key);
    },
    size() {
      return map.size;
    },
  };
}

/**
 * Invoke the Python bridge with a JSON-over-stdin payload.  Always resolves
 * (never rejects) to ``{ status: "ok" | "error", ... }`` so callers can
 * treat every outcome uniformly; a bridge failure is a normal result, not an
 * exception.  This is deliberate: the plugin must never throw into the host
 * harness's tool-execution path.
 *
 * @param {Record<string, unknown>} body
 * @param {{ app?: { log?: (m: string) => void } } | null} [client]
 * @returns {Promise<Record<string, unknown>>}
 */
function invokeBridge(body, client) {
  return new Promise((resolve) => {
    const payloadJSON = JSON.stringify(body) + "\n";
    const bridgePath = process.env.CAIRN_BRIDGE_PATH ?? "cairn-bridge";
    const proc = spawn(bridgePath, [], {
      stdio: ["pipe", "pipe", "pipe"],
      env: process.env,
      timeout: BRIDGE_TIMEOUT_MS,
    });

    let stdout = "";
    let stderr = "";

    proc.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });
    proc.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });

    proc.on("error", (err) => {
      const msg = `[cairn] bridge spawn error: ${err.message}`;
      logTo(client, msg);
      resolve({ status: "error" });
    });

    proc.stdin.write(payloadJSON);
    proc.stdin.end();

    proc.on("close", (exitCode) => {
      if (exitCode !== 0) {
        const msg = `[cairn] bridge failed (exit ${exitCode}): ${stderr.trim().slice(0, 200)}`;
        logTo(client, msg);
        resolve({ status: "error" });
        return;
      }

      if (!stdout) {
        resolve({ status: "error" });
        return;
      }
      try {
        resolve(JSON.parse(stdout));
      } catch {
        const msg = `[cairn] bridge returned non-JSON: ${stdout.slice(0, 200)}`;
        logTo(client, msg);
        resolve({ status: "error" });
      }
    });
  });
}

function logTo(client, msg) {
  if (client?.app?.log) {
    client.app.log(msg);
  } else {
    console.error(msg);
  }
}

/**
 * Build a result-summary payload for the ``end`` action from the harness's
 * ``after`` output.  Pure helper, exported for testing.
 *
 * @param {unknown} result
 * @returns {{ exit_code: number, stdout: string }}
 */
export function summarizeResult(result) {
  const r = /** @type {Record<string, unknown>} */ (result ?? {});
  const exitCode = typeof r.exit_code === "number" ? r.exit_code : 0;
  let stdout = "";
  if (typeof result === "string") {
    stdout = result.slice(0, 2000);
  } else if (result !== null && result !== undefined) {
    stdout = JSON.stringify(result).slice(0, 2000);
  }
  return { exit_code: exitCode, stdout };
}

export default async function cairnPlugin(ctx) {
  // The session map is per-plugin-instance (one opencode process), shared
  // across sessions/calls.  Bounded so a flood of unclosed begins cannot grow
  // memory without bound; evictions are recorded as degradations.
  const sessionMap = createSessionMap();
  const client = ctx?.client ?? null;
  const stateDirOverride = ctx?.stateDir ?? null;

  return {
    "tool.execute.before": async (input, output) => {
      const { tool, sessionID, callID } = input;
      const args = output.args ?? {};
      const files = extractFiles(args);

      const reply = await invokeBridge(
        { action: "begin", tool, args, files, session_id: sessionID },
        client,
      );

      if (reply?.status === "ok" && reply.work_item_id) {
        const { evictedKey, evicted } = sessionMap.set(`${sessionID}:${callID}`, {
          workItemId: reply.work_item_id,
          tool,
          sessionId: sessionID,
          callID,
          beganAt: new Date().toISOString(),
        });
        // If evicting an unclosed begin, record it so the orphan is
        // discoverable.  (An evicted entry always had a successful begin and
        // no matching end — that is precisely an orphaned work item.)
        if (evicted && evicted.sessionId) {
          markDegraded(
            evicted.sessionId,
            "evicted",
            `in-flight begin for ${evicted.tool} (work_item ${evicted.workItemId}) evicted from session map at capacity; its end event cannot be recorded`,
            stateDirOverride,
          );
          logTo(
            client,
            `[cairn] session map full; evicted unclosed begin for ${evicted.tool} ` +
              `(work_item ${evicted.workItemId}) — orphan recorded`,
          );
        }
        logTo(
          client,
          `[cairn] begin ${tool} → work_item ${reply.work_item_id} (args_hash ${reply.args_hash})`,
        );
      } else {
        // Begin never created a work item → no orphan, but the tool call is
        // entirely unrecorded.  Record that too so an auditor sees the gap
        // rather than a silent gap.
        markDegraded(
          sessionID,
          "pre",
          `bridge call failed for ${tool} begin; tool call unrecorded`,
          stateDirOverride,
        );
        logTo(client, `[cairn] begin ${tool} → FAILED (bridge error)`);
      }
    },

    "tool.execute.after": async (input, output) => {
      const { tool, sessionID, callID } = input;
      const key = `${sessionID}:${callID}`;
      const entry = sessionMap.get(key);
      if (!entry) {
        // Either begin failed (already recorded as a degradation) or the entry
        // was evicted under capacity pressure (also recorded). Nothing to close.
        return;
      }

      const args = input.args ?? {};
      const files = extractFiles(args);
      const result = output.result ?? output.output ?? "";

      const reply = await invokeBridge(
        {
          action: "end",
          work_item_id: entry.workItemId,
          session_id: sessionID,
          result_summary: summarizeResult(result),
          files,
          error: output.error ?? null,
        },
        client,
      );

      if (reply?.status === "ok") {
        logTo(client, `[cairn] end ${tool} → work_item ${entry.workItemId}`);
      } else {
        // BC-022: the end event was lost.  The begin is now an orphan — a
        // real provenance gap.  Record it durably so an auditor can find it
        // instead of the gap being silently swallowed (the previous behavior
        // deleted the entry and logged nothing actionable).
        markDegraded(
          sessionID,
          "post",
          `bridge call failed for ${tool} end; work_item ${entry.workItemId} is now an orphaned begin (provenance gap)`,
          stateDirOverride,
        );
        logTo(
          client,
          `[cairn] end ${tool} FAILED — work_item ${entry.workItemId} left without a matching end (provenance gap recorded)`,
        );
      }

      sessionMap.delete(key);
    },

    event: async ({ event }) => {
      if (event?.type === "session.started" && process.env.CAIRN_ATTEST_ON_START) {
        const sessionID = event.properties?.sessionID ?? "";
        if (!sessionID) {
          markDegraded(
            "session-start",
            "session_start",
            "session.started event has no sessionID; cannot attest session",
            stateDirOverride,
          );
          return;
        }
        const reply = await invokeBridge(
          {
            action: "attest_session",
            session_id: sessionID,
            harnesses: [
              {
                name: "opencode",
                version: event.properties?.version ?? "unknown",
              },
            ],
            scope_statement: "In scope: opencode.",
          },
          client,
        );
        if (reply?.status !== "ok") {
          markDegraded(
            sessionID,
            "session_start",
            "session attestation bridge call failed",
            stateDirOverride,
          );
        }
      }
    },

    // Exposed for diagnostics / testing only.  Not part of the opencode hook
    // contract; the host will simply never call these names.
    _sessionMapSize: () => sessionMap.size(),
  };
}
