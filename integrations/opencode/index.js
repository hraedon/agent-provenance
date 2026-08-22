import { spawn } from "node:child_process";
import {
  mkdirSync,
  appendFileSync,
  chmodSync,
  readFileSync,
  writeFileSync,
  readdirSync,
  unlinkSync,
  existsSync,
} from "node:fs";
import { join, resolve } from "node:path";
import { createHash } from "node:crypto";
import { homedir } from "node:os";
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

const BRIDGE_TIMEOUT_MS = (() => {
  const v = parseInt(process.env.CAIRN_BRIDGE_TIMEOUT_MS ?? "10000", 10);
  return Number.isFinite(v) && v > 0 ? v : 10000;
})();

// Bound on the number of in-flight (begin-issued, end-pending) tool calls
// tracked in memory.  Each entry is ~small, but without a bound the map grows
// forever if an ``after`` hook never fires (tool crash, harness bug).  When
// the bound is reached the oldest unclosed begin is evicted and recorded as a
// degradation so the resulting orphan is discoverable.
const DEFAULT_MAX_SESSION_ENTRIES = (() => {
  const v = parseInt(process.env.CAIRN_MAX_SESSION_ENTRIES ?? "10000", 10);
  return Number.isFinite(v) && v > 0 ? v : 10000;
})();

const DEFAULT_STATE_DIR = process.env.CAIRN_STATE_DIR ?? join(tmpdir(), "cairn-sessions");

// Entries older than this on plugin startup are treated as orphans left by a
// prior process that crashed mid-tool-call. Their matching ``after`` hook will
// never fire (the call died with the process), so they are recorded as
// degradations and dropped from the in-memory map instead of lingering.
// 30 minutes is generous: tool calls rarely span that, and a session that
// resumes after a crash will re-issue calls under new call IDs.
const INFLIGHT_STALENESS_MS = (() => {
  const v = parseInt(process.env.CAIRN_INFLIGHT_STALENESS_MS ?? "1800000", 10);
  return Number.isFinite(v) && v > 0 ? v : 1800000;
})();

// Subdirectory (under each session's state dir) holding one JSON file per
// in-flight tool call. A per-session layout keeps a restart's recovery scoped
// and reuses the existing 0o700 session-state perms.
const INFLIGHT_SUBDIR = "inflight";

/**
 * Parse a boolean env var (WI-012).
 * Only "1", "true", "yes", "on" (case-insensitive) are truthy.
 * @param {string} name
 * @returns {boolean}
 */
function isEnvTruthy(name) {
  const v = process.env[name];
  if (!v) return false;
  return ["1", "true", "yes", "on"].includes(v.trim().toLowerCase());
}

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
  let s = String(sessionId).replace(/[^a-zA-Z0-9._-]/g, "_");
  if (s === "." || s === "..") s = "_";
  return s;
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
  try {
    const ts = new Date().toISOString();
    const dir = stateDir(sessionId, stateDirOverride);
    const entry = JSON.stringify({ ts, action, detail }) + "\n";
    const marker = join(dir, "degradation.log");
    appendFileSync(marker, entry, { mode: 0o600 });
  } catch {
    // Observation must not block the harness even when its local gap log is unavailable.
  }
}

function loadModelObservationKeys(sessionId, stateDirOverride) {
  try {
    const path = join(stateDir(sessionId, stateDirOverride), "model-observations.json");
    if (!existsSync(path)) return new Set();
    const values = JSON.parse(readFileSync(path, "utf8"));
    return new Set(Array.isArray(values) ? values.filter((value) => typeof value === "string") : []);
  } catch {
    return new Set();
  }
}

function persistModelObservationKeys(sessionId, keys, stateDirOverride) {
  try {
    const path = join(stateDir(sessionId, stateDirOverride), "model-observations.json");
    writeFileSync(
      path,
      JSON.stringify([...keys].slice(-MODEL_OBSERVATION_DEDUP_LIMIT)) + "\n",
      { mode: 0o600 },
    );
  } catch {
    markDegraded(
      sessionId,
      "model_observation",
      "could not persist model observation deduplication state",
      stateDirOverride,
    );
  }
}

// Shared bound for the model-observation dedup window, both in memory
// (observedModels, via rememberObservedModel) and on disk (the
// model-observations.json restart-dedup file, via
// persistModelObservationKeys). These two used to drift silently — the
// in-memory set was bounded at 4096 while the persisted file was sliced to
// only 256 — so a restart's dedup window was 16x narrower than the
// in-process one with no indication anywhere that this was intentional.
// 4096 is chosen (rather than shrinking the in-memory side down to 256)
// because the persisted file holds only short JSON strings (one
// `JSON.stringify([sessionID, providerID, modelID])` key each), so 4096
// entries costs at most a few hundred KB on disk — cheap relative to the
// benefit of restart-dedup covering the same window as in-process dedup.
// It also matches the existing per-plugin-instance bound already used for
// `requestedModels` above, so all three model-identity maps in this file
// share one order-of-magnitude convention.
export const MODEL_OBSERVATION_DEDUP_LIMIT = 4096;

function rememberObservedModel(keys, observationKey) {
  keys.add(observationKey);
  while (keys.size > MODEL_OBSERVATION_DEDUP_LIMIT) {
    keys.delete(keys.values().next().value);
  }
}

/**
 * Sanitize an arbitrary string for safe use as a filename component.
 * @param {string} s
 * @returns {string}
 */
function safeName(s) {
  let out = String(s).replace(/[^a-zA-Z0-9._-]/g, "_");
  if (out === "." || out === "..") out = "_";
  return out;
}

/**
 * Map a session-map key (``${sessionId}:${callID}``) to a collision-free
 * filename stem. Two distinct keys must never collapse to the same file
 * (adversarial review H1): a lossy character substitution like ``safeName``
 * would let ``a:b`` and ``a_b`` clobber each other's in-flight entry. We
 * therefore hash the *original* key with SHA-256 and use the hex digest as
 * the stem. The original key is also stored inside the JSON entry so
 * recovery can reconstruct the canonical session-map key without relying
 * on the (now opaque) filename.
 *
 * @param {string} key
 * @returns {string}
 */
function inflightFileName(key) {
  return createHash("sha256").update(String(key)).digest("hex") + ".json";
}

/**
 * Resolve the in-flight directory for a given session.
 *
 * @param {string} sessionId
 * @param {string} [stateDirOverride]
 * @returns {string}
 */
function inflightDir(sessionId, stateDirOverride) {
  const dir = join(stateDir(sessionId, stateDirOverride), INFLIGHT_SUBDIR);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  try {
    chmodSync(dir, 0o700);
  } catch {
    // best-effort
  }
  return dir;
}

/**
 * Persist an in-flight tool-call entry to disk so a plugin restart can
 * recover it (WI-024).  The entry is written as
 * ``<session-state>/inflight/<sha256(key)>.json`` with 0o600 perms.
 *
 * @param {string} key  the ``${sessionID}:${callID}`` session-map key
 * @param {Record<string, unknown>} entry
 * @param {string} sessionId
 * @param {string} [stateDirOverride]
 */
export function persistInFlightEntry(key, entry, sessionId, stateDirOverride) {
  const dir = inflightDir(sessionId, stateDirOverride);
  const file = join(dir, inflightFileName(key));
  try {
    writeFileSync(file, JSON.stringify(entry) + "\n", { mode: 0o600 });
  } catch {
    // Persistence is best-effort; if it fails the entry still lives in the
    // in-memory map and a restart simply cannot recover it. Record the gap
    // so an auditor can discover it (adversarial review L10).
    markDegraded(
      sessionId,
      "persist",
      `could not persist in-flight entry for ${entry.tool ?? "unknown"} ` +
        `(work_item ${entry.workItemId ?? "?"}); a restart will not recover it`,
      stateDirOverride,
    );
  }
}

/**
 * Remove a persisted in-flight entry once the matching ``end`` has been
 * recorded (WI-024).  Missing file is a no-op.
 *
 * @param {string} key
 * @param {string} sessionId
 * @param {string} [stateDirOverride]
 */
export function removeInFlightEntry(key, sessionId, stateDirOverride) {
  const dir = inflightDir(sessionId, stateDirOverride);
  const file = join(dir, inflightFileName(key));
  try {
    unlinkSync(file);
  } catch {
    // already gone or never persisted — fine
  }
}

/**
 * Load all persisted in-flight entries for a session (WI-024).  Returns a
 * list of ``{ key, entry }`` pairs.  Files that fail to parse are skipped
 * (best-effort recovery; a corrupt entry is logged via markDegraded so the
 * gap is discoverable).  Entries whose ``sessionId`` does not match the
 * directory they were loaded from are treated as corrupt (adversarial
 * review H2).
 *
 * The ``key`` returned is reconstructed from ``entry.sessionId`` and
 * ``entry.callID`` (the canonical session-map key), NOT from the filename —
 * the filename is an opaque SHA-256 digest and is not reversible.
 *
 * @param {string} sessionId
 * @param {string} [stateDirOverride]
 * @returns {{ key: string, entry: Record<string, unknown> }[]}
 */
export function loadInFlightEntries(sessionId, stateDirOverride) {
  const base = stateDirOverride || DEFAULT_STATE_DIR;
  const dir = join(base, safeSessionId(sessionId), INFLIGHT_SUBDIR);
  if (!existsSync(dir)) return [];
  const out = [];
  let files;
  try {
    files = readdirSync(dir);
  } catch {
    return [];
  }
  for (const f of files) {
    if (!f.endsWith(".json")) continue;
    try {
      const raw = readFileSync(join(dir, f), "utf8");
      const entry = JSON.parse(raw);
      if (!entry || typeof entry !== "object") {
        throw new Error("not an object");
      }
      // Validate the entry belongs to this session (adversarial review H2).
      if (
        typeof entry.sessionId !== "string" ||
        typeof entry.callID !== "string" ||
        entry.sessionId !== sessionId
      ) {
        markDegraded(
          sessionId,
          "recover",
          `in-flight entry file ${f} has a sessionId/callID that does not ` +
            `match its directory; treating it as corrupt and skipping`,
          stateDirOverride,
        );
        continue;
      }
      out.push({ key: `${entry.sessionId}:${entry.callID}`, entry });
    } catch {
      markDegraded(
        sessionId,
        "recover",
        `in-flight entry file ${f} could not be parsed; orphan from prior ` +
          `process may be undiscoverable`,
        stateDirOverride,
      );
    }
  }
  return out;
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

/**
 * Resolve a sha256 digest of the opencode config file, mirroring the
 * Claude Code hook's _resolve_settings_digest (WI-018).
 *
 * Looks for opencode.json or opencode.jsonc in the project directory,
 * then in the user's home config directory.  Returns null if no config
 * file is found.
 *
 * @param {string} [projectDir]  override, mainly for tests
 * @param {string} [homeDir]     override, mainly for tests
 * @returns {string | null}  "sha256:..." or null
 */
export function resolveConfigDigest(projectDir, homeDir) {
  const candidates = [];
  if (projectDir) {
    candidates.push(join(projectDir, "opencode.json"));
    candidates.push(join(projectDir, "opencode.jsonc"));
  }
  const home = homeDir || homedir();
  candidates.push(join(home, ".config", "opencode", "opencode.json"));
  candidates.push(join(home, ".config", "opencode", "opencode.jsonc"));
  for (const p of candidates) {
    try {
      const buf = readFileSync(p);
      const hash = createHash("sha256").update(buf).digest("hex");
      return "sha256:" + hash;
    } catch {
      // file not found or unreadable; try next candidate
    }
  }
  return null;
}

export default async function cairnPlugin(ctx) {
  // The session map is per-plugin-instance (one opencode process), shared
  // across sessions/calls.  Bounded so a flood of unclosed begins cannot grow
  // memory without bound; evictions are recorded as degradations.
  const sessionMap = createSessionMap();
  const requestedModels = new Map();
  const observedModels = new Set();
  const pendingModelObservations = new Set();
  const client = ctx?.client ?? null;
  const stateDirOverride = ctx?.stateDir ?? null;

  // WI-024: recover in-flight entries persisted by a prior (crashed) plugin
  // instance. Each session's state dir may hold ``inflight/*.json`` files;
  // we seed the in-memory map from them so a pending ``after`` hook can
  // still close the work item. Entries older than the staleness threshold
  // are recorded as degraded orphans (their ``after`` will never fire) and
  // dropped from disk so they are not re-recovered on the next restart.
  {
    const baseDir = stateDirOverride || DEFAULT_STATE_DIR;
    let sessionDirs;
    try {
      sessionDirs = readdirSync(baseDir, { withFileTypes: true })
        .filter((d) => d.isDirectory())
        .map((d) => d.name);
    } catch {
      sessionDirs = [];
    }
    for (const sd of sessionDirs) {
      for (const { key, entry } of loadInFlightEntries(sd, stateDirOverride)) {
        const beganAt = entry.beganAt ? Date.parse(entry.beganAt) : NaN;
        const age = Number.isFinite(beganAt) ? Date.now() - beganAt : Infinity;
        if (age > INFLIGHT_STALENESS_MS) {
          markDegraded(
            sd,
            "orphan_restart",
            `in-flight begin for ${entry.tool ?? "unknown"} ` +
              `(work_item ${entry.workItemId ?? "?"}) was still open when the ` +
              `plugin restarted and is older than the staleness threshold ` +
              `(${Math.round(INFLIGHT_STALENESS_MS / 1000)}s); its end event will ` +
              `never fire — recorded as an orphan (WI-024)`,
            stateDirOverride,
          );
          // Remove the stale file so it is not re-recovered next restart.
          removeInFlightEntry(key, sd, stateDirOverride);
          logTo(
            client,
            `[cairn] recovered stale in-flight begin for ${entry.tool ?? "unknown"} ` +
              `(work_item ${entry.workItemId ?? "?"}) — recorded as orphan`,
          );
        } else {
          sessionMap.set(key, entry);
          logTo(
            client,
            `[cairn] recovered in-flight begin for ${entry.tool ?? "unknown"} ` +
              `(work_item ${entry.workItemId ?? "?"}) from prior process`,
          );
        }
      }
    }
  }

  return {
    "chat.message": async (input) => {
      if (
        input?.sessionID &&
        typeof input.model?.providerID === "string" &&
        typeof input.model?.modelID === "string"
      ) {
        requestedModels.set(input.sessionID, {
          providerID: input.model.providerID,
          modelID: input.model.modelID,
        });
        while (requestedModels.size > 4096) {
          requestedModels.delete(requestedModels.keys().next().value);
        }
      }
    },

    "tool.execute.before": async (input, output) => {
      const { tool, sessionID, callID } = input;
      const args = output.args ?? {};
      const files = extractFiles(args);

      const reply = await invokeBridge(
        { action: "begin", tool, args, files, session_id: sessionID },
        client,
      );

      if (reply?.status === "ok" && reply.work_item_id) {
        const entry = {
          workItemId: reply.work_item_id,
          tool,
          sessionId: sessionID,
          callID,
          beganAt: new Date().toISOString(),
        };
        const { evictedKey, evicted } = sessionMap.set(`${sessionID}:${callID}`, entry);
        // WI-024: persist so a plugin restart can recover this in-flight call.
        persistInFlightEntry(`${sessionID}:${callID}`, entry, sessionID, stateDirOverride);
        // If evicting an unclosed begin, record it so the orphan is
        // discoverable.  (An evicted entry always had a successful begin and
        // no matching end — that is precisely an orphaned work item.)
        if (evicted && evicted.sessionId) {
          removeInFlightEntry(
            `${evicted.sessionId}:${evicted.callID ?? ""}`,
            evicted.sessionId,
            stateDirOverride,
          );
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
        // WI-024: the call closed cleanly; drop the persisted in-flight entry.
        removeInFlightEntry(key, sessionID, stateDirOverride);
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
      // WI-024: the in-flight file is removed only on a *successful* end
      // (above). On a failed end the begin is an orphan, but we keep the
      // persisted entry so a future restart can still recover and surface it
      // rather than silently losing it (adversarial review H3).
    },

    event: async ({ event }) => {
      if (event?.type === "message.updated") {
        const info = event.properties?.info;
        if (info?.role === "assistant" && info.sessionID) {
          const requested = requestedModels.get(info.sessionID);
          const observedProvider =
            typeof info.providerID === "string" ? info.providerID : null;
          const observedModel = typeof info.modelID === "string" ? info.modelID : null;
          const observationKey = JSON.stringify([
            info.sessionID,
            observedProvider,
            observedModel,
          ]);
          if (
            !observedModels.has(observationKey) &&
            !pendingModelObservations.has(observationKey)
          ) {
            const persisted = loadModelObservationKeys(info.sessionID, stateDirOverride);
            if (persisted.has(observationKey)) {
              rememberObservedModel(observedModels, observationKey);
            }
          }
          // Guard the submit gate with both sets, not just observedModels:
          // observedModels is populated only once the bridge's `.then()`
          // resolves, but `message.updated` fires repeatedly while an
          // assistant message streams. Without also checking
          // pendingModelObservations, every one of those repeat events for
          // the same key would fire its own bridge call while the first is
          // still in flight (review finding 1). The bridge derives a
          // deterministic uuid5 event id from observation_id, so a
          // duplicate call is an idempotent append rather than a duplicate
          // event, but it is still a wasted round-trip and degradation-log
          // noise we can avoid for free.
          if (!observedModels.has(observationKey) && !pendingModelObservations.has(observationKey)) {
            const body = {
              action: "model_observation",
              session_id: info.sessionID,
              source: "opencode.message.updated",
              observation_id: observationKey,
              observed_provider_id: observedProvider,
              observed_model_id: observedModel,
              requested_provider_id: requested?.providerID ?? null,
              requested_model_id: requested?.modelID ?? null,
            };
            if (isEnvTruthy("CAIRN_SINGLE_MODEL_SERVICE")) {
              body.declared_model_lineage = process.env.CAIRN_MODEL_LINEAGE ?? null;
            }
            pendingModelObservations.add(observationKey);
            void invokeBridge(body, client)
              .then((reply) => {
                if (reply?.status === "ok") {
                  rememberObservedModel(observedModels, observationKey);
                  const persisted = loadModelObservationKeys(info.sessionID, stateDirOverride);
                  persisted.add(observationKey);
                  persistModelObservationKeys(info.sessionID, persisted, stateDirOverride);
                  if (reply.finding) {
                    logTo(client, `[cairn] model observation finding: ${reply.finding}`);
                  }
                } else {
                  markDegraded(
                    info.sessionID,
                    "model_observation",
                    "model observation bridge call failed",
                    stateDirOverride,
                  );
                }
                if (!observedModel) {
                  markDegraded(
                    info.sessionID,
                    "model_observation",
                    "assistant message metadata has no observed model identifier",
                    stateDirOverride,
                  );
                }
              })
              .catch(() => {
                markDegraded(
                  info.sessionID,
                  "model_observation",
                  "model observation callback failed",
                  stateDirOverride,
                );
              })
              .finally(() => pendingModelObservations.delete(observationKey));
          }
        }
      }
      if (event?.type === "session.started" && isEnvTruthy("CAIRN_ATTEST_ON_START")) {
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
        const configDigest = resolveConfigDigest(
          process.env.OPENCODE_PROJECT_DIR || process.env.PWD,
        );
        const harnessName = "opencode";
        const reply = await invokeBridge(
          {
            action: "attest_session",
            session_id: sessionID,
            harnesses: [
              {
                name: harnessName,
                version: event.properties?.version ?? "unknown",
              },
            ],
            scope_statement: "In scope: opencode.",
            harness_config_digests: configDigest
              ? { [harnessName]: configDigest }
              : null,
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
