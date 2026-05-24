import cairnPlugin from "./index.js";
import { writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

// Prepare substrate key file
const tmpDir = tmpdir();
const keyFile = join(tmpDir, "cairn_test_keys.json");
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
process.env.CAIRN_BRIDGE_PATH = "/projects/agent-provenance/.venv/bin/cairn-bridge";

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
  const result = await cairnPlugin({ client: mockClient });
  console.log("Plugin loaded, hooks:", Object.keys(result.hooks));

  // Session start attestation
  if (result.hooks.event) {
    await result.hooks.event({
      event: { type: "session.started", properties: { version: "1.15.7" } },
    });
  }

  // Simulate a tool call
  const sessionID = "sess-test";
  const callID = "call-1";

  await result.hooks["tool.execute.before"](
    { tool: "Write", sessionID, callID },
    { args: { filePath: "/tmp/cairn_test.txt", content: "hello" } }
  );

  await result.hooks["tool.execute.after"](
    { tool: "Write", sessionID, callID, args: { filePath: "/tmp/cairn_test.txt", content: "hello" } },
    { output: "written", result: { exit_code: 0 } }
  );

  console.log("\nCaptured logs:", capturedLogs.length);
  capturedLogs.forEach((l) => console.log(" -", l));
}

main().catch((err) => {
  console.error("Error:", err);
  process.exit(1);
});
