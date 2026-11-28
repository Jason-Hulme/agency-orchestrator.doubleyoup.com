// hub#618: Node-only helper for test/enroll-host-installer.test.ts (kept out of the typechecked test file: this
// project has no @types/node). It runs the installer's own enrol python (host-install-enroll.py) under python3, with
// only urllib.request.urlopen stubbed (run-installer-enroll.py). The stub sends the request to a local HTTP server
// that hands it to `handler`, the real Worker entry.
import { spawn, spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { fileURLToPath } from "node:url";

const RUNNER_PATH = fileURLToPath(new URL("./run-installer-enroll.py", import.meta.url));

export function hasPython3() {
  return spawnSync("python3", ["--version"]).status === 0;
}

async function startServer(origin, handler) {
  const server = createServer((incoming, outgoing) => {
    const chunks = [];
    incoming.on("data", (chunk) => chunks.push(chunk));
    incoming.on("end", async () => {
      const request = new Request(`${origin}${incoming.url}`, {
        method: incoming.method,
        headers: { "content-type": String(incoming.headers["content-type"] ?? "") },
        body: Buffer.concat(chunks),
      });
      const response = await handler(request);
      outgoing.statusCode = response.status;
      outgoing.setHeader("content-type", response.headers.get("content-type") ?? "");
      outgoing.end(Buffer.from(await response.arrayBuffer()));
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { server, port: server.address().port };
}

/**
 * Runs the installer's enrol python the way the installer does: the facts blob and the code on stdin (one per line),
 * the Worker origin as the one argument. Resolves with the exit status, stdout (the params JSON) and stderr.
 */
export async function runInstallerEnrol({ origin, handler, factsBlob, code }) {
  const { server, port } = await startServer(origin, handler);
  try {
    return await new Promise((resolve) => {
      const child = spawn("python3", ["-I", RUNNER_PATH, origin], { env: { DY_TEST_ENROLL_SERVER: `127.0.0.1:${port}` } });
      let stdout = "";
      let stderr = "";
      child.stdout.on("data", (chunk) => (stdout += chunk));
      child.stderr.on("data", (chunk) => (stderr += chunk));
      child.on("close", (status) => resolve({ status, stdout, stderr }));
      child.stdin.end(`${factsBlob}\n${code}\n`);
    });
  } finally {
    server.close();
  }
}
