// Node-only stub for the workerd built-in module "cloudflare:sockets" (hub#476).
//
// src/ssh-client.ts imports `connect` from it, and the Node vitest project imports the Worker entry, so the module
// graph needs it to resolve. No Node test opens a socket: the SSH client runs against a real sshd only in the
// workers project (test/host-ssh.worker.test.ts). A call here fails loudly instead of pretending to connect.
export function connect(): never {
  throw new Error("cloudflare:sockets is not available under Node; run the SSH tests in the workers project");
}
