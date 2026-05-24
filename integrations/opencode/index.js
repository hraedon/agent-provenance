import { tool } from "@opencode-ai/plugin";
import { $ } from "bun";

/**
 * Cairn provenance plugin — wraps the Python bridge script to log every
 * tool call to substrate.
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
 *   The plugin is a thin TypeScript wrapper.  All heavy lifting (substrate
 *   connection, event signing, file digest computation) lives in the Python
 *   `cairn_bridge.py` script that ships with the `cairn` Python package.
 *   This keeps Cairn the single source of truth and avoids duplicating logic
 *   across languages.
 */

const BRIDGE_TIMEOUT_MS = parseInt(process.env.CAIRN_BRIDGE_TIMEOUT_MS ?? "5000", 10);

async function invokeBridge(body, client) {
  const payloadJSON = JSON.stringify(body) + "\n";
  const bridgePath = process.env.CAIRN_BRIDGE_PATH ?? "cairn-bridge";
  const proc = Bun.spawn({
    cmd: [bridgePath],
    stdin: "pipe",
    stdout: "pipe",
    stderr: "pipe",
    env: process.env,
  });
  const encoder = new TextEncoder();
  proc.stdin.write(encoder.encode(payloadJSON));
  proc.stdin.end();

  const stdout = await new Response(proc.stdout).text();
  const stderr = await new Response(proc.stderr).text();
  const exitCode = await proc.exited;

  if (exitCode !== 0) {
    const msg = `[cairn] bridge failed (exit ${exitCode}): ${stderr.trim().slice(0, 200)}`;
    if (client?.app?.log) {
      client.app.log(msg);
    } else {
      console.error(msg);
    }
    return { status: "error" };
  }

  if (!stdout) return { status: "error" };
  try {
    return JSON.parse(stdout);
  } catch {
    const msg = `[cairn] bridge returned non-JSON: ${stdout.slice(0, 200)}`;
    if (client?.app?.log) {
      client.app.log(msg);
    } else {
      console.error(msg);
    }
    return { status: "error" };
  }
}

export default async function cairnPlugin(ctx) {
  const sessionMap = new Map();

  return {
    hooks: {
      "tool.execute.before": async (input, output) => {
        const { tool, sessionID, callID } = input;
        const args = output.args ?? {};
        // Derive file paths from args so the Python adapter can pre-digest them
        const files = [];
        if (args.filePath) files.push(args.filePath);
        if (args.path) files.push(args.path);
        if (args.file) files.push(args.file);
        if (args.files) {
          const f = Array.isArray(args.files) ? args.files : [args.files];
          files.push(...f);
        }

        const reply = await invokeBridge(
          { action: "begin", tool, args, files },
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

        const result =
          output.result ?? output.output ?? "";
        await invokeBridge(
          {
            action: "end",
            work_item_id: wi_id,
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
    },
  };
}