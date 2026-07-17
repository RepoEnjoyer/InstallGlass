import { chmod, mkdir, mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { preparePackageSpec, type PreparedSpec } from "./spec.js";

export interface AuditWorkspace {
  root: string;
  analysis: string;
  output: string;
  proxyOutput: string;
  preparedSpec: PreparedSpec;
}

export async function createAuditWorkspace(packageSpec: string): Promise<AuditWorkspace> {
  const root = await mkdtemp(join(tmpdir(), "installglass-"));
  await chmod(root, 0o700);
  const analysis = join(root, "analysis");
  const output = join(root, "output");
  const proxyOutput = join(root, "proxy-output");
  const input = join(analysis, "input");
  await Promise.all([
    mkdir(analysis, { recursive: true }),
    mkdir(output, { recursive: true }),
    mkdir(proxyOutput, { recursive: true }),
  ]);
  const preparedSpec = await preparePackageSpec(packageSpec, input);
  return { root, analysis, output, proxyOutput, preparedSpec };
}

export async function removeAuditWorkspace(workspace: AuditWorkspace): Promise<void> {
  await rm(workspace.root, { recursive: true, force: true, maxRetries: 3 });
}
