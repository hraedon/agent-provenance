import cairnPlugin from "./index.js";
import { writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

// Prepare substrate key file
const tmpDir = tmpdir();
const keyFile = join(tmpDir, "cairn_dogfood_keys.json");
writeFileSync(
  keyFile,
  JSON.stringify({
    keys: [
      {
        key_id: "cairn-test-001",
        secret: "supersecret-test-key-32bytes!!",
        status: "active",
        alg: "HMAC-SHA256",
      },
    ],
  })
);

process.env.CAIRN_DSN = "postgresql://substrate_test:substrate_test@localhost/substrate_test";
process.env.CAIRN_PROJECT = "cairn_dogfood_test";
process.env.CAIRN_KEY_PATH = keyFile;
process.env.PRINCIPAL_ID = "human:owner";
process.env.CAIRN_HARNESS_NAME = "opencode";
process.env.CAIRN_HARNESS_VERSION = "1.15.7";

process.env.CAIRN_BRIDGE_PATH = "/projects/agent-provenance/.venv/bin/cairn-bridge";
const dogfoodDir = "/tmp/cairn_dogfood_session";
try {
  await (await import("fs/promises")).mkdir(dogfoodDir, { recursive: true });
} catch {}

const capturedLogs = [];
const mockClient = {
  app: {
    log: (msg) => {
      capturedLogs.push(msg);
      console.log("[MOCK LOG]", msg);
    },
  },
};

async function main() {
  const plugin = await cairnPlugin({ client: mockClient });
  console.log("=== Cairn OpenCode Dogfood Session ===\n");

  // --- Tool call 1: Write a file ---
  let callID = 1;
  const file1 = join(dogfoodDir, "plan.md");
  await plugin.hooks["tool.execute.before"](
    { tool: "Write", sessionID: "dogfood", callID: `call-${callID}` },
    { args: { filePath: file1, content: "# Plan\n\nTODO" } }
  );
  writeFileSync(file1, "# Plan\n\nTODO");
  await plugin.hooks["tool.execute.after"](
    { tool: "Write", sessionID: "dogfood", callID: `call-${callID}`, args: { filePath: file1, content: "# Plan\n\nTODO" } },
    { output: "written", result: { exit_code: 0 } }
  );
  callID++;

  // --- Tool call 2: Edit the file ---
  await plugin.hooks["tool.execute.before"](
    { tool: "Edit", sessionID: "dogfood", callID: `call-${callID}` },
    { args: { filePath: file1, oldString: "TODO", newString: "DONE" } }
  );
  const fs = await import("fs/promises");
  const content = await fs.readFile(file1, "utf-8");
  await fs.writeFile(file1, content.replace("TODO", "DONE"));
  await plugin.hooks["tool.execute.after"](
    { tool: "Edit", sessionID: "dogfood", callID: `call-${callID}`, args: { filePath: file1, oldString: "TODO", newString: "DONE" } },
    { output: "edited", result: { exit_code: 0 } }
  );
  callID++;

  // --- Tool call 3: Write another file ---
  const file2 = join(dogfoodDir, "notes.txt");
  await plugin.hooks["tool.execute.before"](
    { tool: "Write", sessionID: "dogfood", callID: `call-${callID}` },
    { args: { filePath: file2, content: "Initial notes" } }
  );
  writeFileSync(file2, "Initial notes");
  await plugin.hooks["tool.execute.after"](
    { tool: "Write", sessionID: "dogfood", callID: `call-${callID}`, args: { filePath: file2, content: "Initial notes" } },
    { output: "written", result: { exit_code: 0 } }
  );
  callID++;

  // --- Tool call 4: Read a file ---
  await plugin.hooks["tool.execute.before"](
    { tool: "Read", sessionID: "dogfood", callID: `call-${callID}` },
    { args: { filePath: file2 } }
  );
  const readResult = await fs.readFile(file2, "utf-8");
  await plugin.hooks["tool.execute.after"](
    { tool: "Read", sessionID: "dogfood", callID: `call-${callID}`, args: { filePath: file2 } },
    { output: readResult, result: { exit_code: 0 } }
  );
  callID++;

  // --- Tool call 5: Bash command ---
  await plugin.hooks["tool.execute.before"](
    { tool: "Bash", sessionID: "dogfood", callID: `call-${callID}` },
    { args: { command: "echo hello world" } }
  );
  await plugin.hooks["tool.execute.after"](
    { tool: "Bash", sessionID: "dogfood", callID: `call-${callID}`, args: { command: "echo hello world" } },
    { output: "hello world\n", result: { exit_code: 0 } }
  );
  callID++;

  console.log("\nDogfood session complete. Total tool calls:", (callID - 1));
  console.log("Logs:", capturedLogs.length);
}

main().catch((err) => {
  console.error("Error:", err);
  process.exit(1);
});
