import { spawn } from "node:child_process";

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
 */

const BRIDGE_TIMEOUT_MS = parseInt(process.env.CAIRN_BRIDGE_TIMEOUT_MS ?? "10000", 10);

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

    proc.stdout.on("data", (chunk) => { stdout += chunk.toString(); });
    proc.stderr.on("data", (chunk) => { stderr += chunk.toString(); });

    proc.on("error", (err) => {
      const msg = `[cairn] bridge spawn error: ${err.message}`;
      if (client?.app?.log) {
        client.app.log(msg);
      } else {
        console.error(msg);
      }
      resolve({ status: "error" });
    });

    proc.stdin.write(payloadJSON);
    proc.stdin.end();

    proc.on("close", (exitCode) => {
      if (exitCode !== 0) {
        const msg = `[cairn] bridge failed (exit ${exitCode}): ${stderr.trim().slice(0, 200)}`;
        if (client?.app?.log) {
          client.app.log(msg);
        } else {
          console.error(msg);
        }
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
        if (client?.app?.log) {
          client.app.log(msg);
        } else {
          console.error(msg);
        }
        resolve({ status: "error" });
      }
    });
  });
}

export default async function cairnPlugin(ctx) {
  const sessionMap = new Map();

  return {
    "tool.execute.before": async (input, output) => {
      const { tool, sessionID, callID } = input;
      const args = output.args ?? {};
      const files = [];
      if (args.filePath) files.push(args.filePath);
      if (args.path) files.push(args.path);
      if (args.file) files.push(args.file);
      if (args.files) {
        const f = Array.isArray(args.files) ? args.files : [args.files];
        files.push(...f);
      }

      const reply = await invokeBridge(
        { action: "begin", tool, args, files, session_id: sessionID },
        ctx.client
      );

      if (reply?.status === "ok") {
        sessionMap.set(`${sessionID}:${callID}`, reply.work_item_id);
        ctx.client?.app?.log?.(
          `[cairn] begin ${tool} → work_item ${reply.work_item_id} (args_hash ${reply.args_hash})`
        );
      } else {
        ctx.client?.app?.log?.(
          `[cairn] begin ${tool} → FAILED (bridge error)`
        );
      }
    },

    "tool.execute.after": async (input, output) => {
      const { tool, sessionID, callID } = input;
      const wi_id = sessionMap.get(`${sessionID}:${callID}`);
      if (!wi_id) return;

      const args = input.args ?? {};
      const files = [];
      if (args.filePath) files.push(args.filePath);
      if (args.path) files.push(args.path);
      if (args.file) files.push(args.file);
      if (args.files) {
        const f = Array.isArray(args.files) ? args.files : [args.files];
        files.push(...f);
      }

      const result = output.result ?? output.output ?? "";
      await invokeBridge(
        {
          action: "end",
          work_item_id: wi_id,
          session_id: sessionID,
          result_summary: {
            exit_code: result.exit_code ?? 0,
            stdout:
              typeof result === "string"
                ? result.slice(0, 2000)
                : JSON.stringify(result).slice(0, 2000),
          },
          files,
          error: output.error ?? null,
        },
        ctx.client
      );

      ctx.client?.app?.log?.(`[cairn] end ${tool} → work_item ${wi_id}`);
      sessionMap.delete(`${sessionID}:${callID}`);
    },

    event: async ({ event }) => {
      if (event?.type === "session.started" && process.env.CAIRN_ATTEST_ON_START) {
        await invokeBridge(
          {
            action: "attest_scope",
            harnesses: [
              {
                name: "opencode",
                version: event.properties?.version ?? "unknown",
              },
            ],
            scope_statement: "In scope: opencode.",
          },
          ctx.client
        );
      }
    },
  };
}