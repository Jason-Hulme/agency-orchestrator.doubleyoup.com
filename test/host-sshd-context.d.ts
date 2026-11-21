// hub#476: the facts test/host-sshd.global-setup.mjs provides to test/host-ssh.worker.test.ts.
declare module "vitest" {
  export interface ProvidedContext {
    hostSshd:
      | { available: false }
      | {
          available: true;
          port: number;
          login: string;
          privateKeyPem: string;
          unauthorizedKeyPem: string;
          hostKeyFingerprint: string;
          installerOrigin: string;
          installerSha256: string;
          tamperedSha256: string;
        };
  }
}
export {};
