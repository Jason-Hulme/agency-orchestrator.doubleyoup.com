// hub#476: the vitest global setup for test/host-ssh.worker.test.ts. It runs in Node, before the workers project.
//
// It builds and starts test/fixtures/host-sshd (a real OpenSSH server on Debian 12), makes a fresh ed25519 user key
// in the OpenSSH format the Worker parses, authorizes it for the login `dy`, publishes the stub installer at its
// content-addressed path, and hands the facts to the tests with `provide`. The container is removed at the end.
//
// When Docker is not available the tests are skipped with a message (the facts carry `available: false`), so a
// machine without Docker can still run the rest of the suite. A plain .mjs file: the repo's tsconfig has no Node
// types, and this file never runs in workerd.

import { execFileSync } from "node:child_process";
import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { connect } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const FIXTURE_DIR = join(dirname(fileURLToPath(import.meta.url)), "fixtures", "host-sshd");
const IMAGE_TAG = "dy-agency-orchestrator-host-sshd-test";
const LOGIN = "dy";

function docker(args, input) {
  return execFileSync("docker", args, { input, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"], timeout: 600_000 });
}

function sshString(bytes) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return Buffer.concat([length, bytes]);
}

function sshUint32(value) {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32BE(value);
  return bytes;
}

/** A fresh ed25519 key as an unencrypted "openssh-key-v1" PEM, plus its authorized_keys line. */
function makeOpenSshEd25519Key() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicRaw = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  const seed = privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32);
  const keyType = Buffer.from("ssh-ed25519");
  const publicBlob = Buffer.concat([sshString(keyType), sshString(publicRaw)]);
  const check = randomBytes(4);
  let privateSection = Buffer.concat([
    check,
    check,
    sshString(keyType),
    sshString(publicRaw),
    sshString(Buffer.concat([seed, publicRaw])),
    sshString(Buffer.from("hub476-test")),
  ]);
  const padding = [];
  for (let index = 1; (privateSection.length + padding.length) % 8 !== 0; index++) {
    padding.push(index);
  }
  privateSection = Buffer.concat([privateSection, Buffer.from(padding)]);
  const body = Buffer.concat([
    Buffer.from("openssh-key-v1\0"),
    sshString(Buffer.from("none")),
    sshString(Buffer.from("none")),
    sshString(Buffer.alloc(0)),
    sshUint32(1),
    sshString(publicBlob),
    sshString(privateSection),
  ]);
  const lines = body.toString("base64").match(/.{1,70}/g);
  const pem = ["-----BEGIN OPENSSH PRIVATE KEY-----", ...lines, "-----END OPENSSH PRIVATE KEY-----", ""].join("\n");
  return { pem, authorizedKeyLine: `ssh-ed25519 ${publicBlob.toString("base64")} hub476-test\n` };
}

function fingerprintOfPublicKeyLine(line) {
  const blob = Buffer.from(line.trim().split(/\s+/)[1], "base64");
  return `SHA256:${createHash("sha256").update(blob).digest("base64").replace(/=+$/, "")}`;
}

/** Wait until the server sends its SSH version line. */
async function waitForSshBanner(port, deadlineMs) {
  while (Date.now() < deadlineMs) {
    const banner = await new Promise((resolve) => {
      const socket = connect({ host: "127.0.0.1", port });
      socket.setTimeout(1000);
      socket.once("data", (data) => {
        socket.destroy();
        resolve(data.toString());
      });
      socket.once("error", () => resolve(""));
      socket.once("timeout", () => {
        socket.destroy();
        resolve("");
      });
    });
    if (banner.startsWith("SSH-2.0-")) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error("the test sshd did not answer in time");
}

export default async function setup(project) {
  try {
    docker(["version", "--format", "{{.Server.Version}}"]);
  } catch {
    console.warn("host-ssh tests: Docker is not available, so the real-sshd tests are skipped.");
    project.provide("hostSshd", { available: false });
    return undefined;
  }

  docker(["build", "--quiet", "--tag", IMAGE_TAG, FIXTURE_DIR]);
  const containerId = docker(["run", "--detach", "--rm", "--publish", "127.0.0.1::22", IMAGE_TAG]).trim();
  const teardown = () => {
    try {
      docker(["rm", "--force", containerId]);
    } catch {
      // Already gone (--rm); nothing to clean.
    }
  };

  try {
    const portLine = docker(["port", containerId, "22/tcp"]).trim().split("\n")[0];
    const port = Number(portLine.slice(portLine.lastIndexOf(":") + 1));
    await waitForSshBanner(port, Date.now() + 30_000);

    const userKey = makeOpenSshEd25519Key();
    docker(
      ["exec", "--interactive", containerId, "sh", "-c", `install -d -m 700 -o ${LOGIN} -g ${LOGIN} /home/${LOGIN}/.ssh && cat > /home/${LOGIN}/.ssh/authorized_keys && chown ${LOGIN}:${LOGIN} /home/${LOGIN}/.ssh/authorized_keys && chmod 600 /home/${LOGIN}/.ssh/authorized_keys`],
      userKey.authorizedKeyLine,
    );
    const hostKeyLine = docker(["exec", containerId, "cat", "/etc/ssh/ssh_host_ed25519_key.pub"]);

    const installer = readFileSync(join(FIXTURE_DIR, "host-install-stub.sh"));
    const installerSha256 = createHash("sha256").update(installer).digest("hex");
    docker(["exec", "--interactive", containerId, "sh", "-c", `cat > /srv/self-hosted/host-install-${installerSha256}.sh`], installer);
    // A file served under a sha256 its bytes do not have: the stub must refuse to run it.
    const tamperedSha256 = createHash("sha256").update("not the tampered bytes").digest("hex");
    docker(["exec", "--interactive", containerId, "sh", "-c", `cat > /srv/self-hosted/host-install-${tamperedSha256}.sh`], "#!/bin/sh\necho tampered\n");

    project.provide("hostSshd", {
      available: true,
      port,
      login: LOGIN,
      privateKeyPem: userKey.pem,
      // A valid key that is NOT authorized on the server: the login must fail as auth-failed.
      unauthorizedKeyPem: makeOpenSshEd25519Key().pem,
      hostKeyFingerprint: fingerprintOfPublicKeyLine(hostKeyLine),
      installerOrigin: "https://installer.test",
      installerSha256,
      tamperedSha256,
    });
  } catch (error) {
    teardown();
    throw error;
  }
  return teardown;
}
