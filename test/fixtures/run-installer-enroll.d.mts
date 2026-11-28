export function hasPython3(): boolean;
export function runInstallerEnrol(options: {
  origin: string;
  handler: (request: Request) => Promise<Response>;
  factsBlob: string;
  code: string;
}): Promise<{ status: number | null; stdout: string; stderr: string }>;
