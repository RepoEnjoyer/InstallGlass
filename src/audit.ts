import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { collectEvidence } from "./analyzers/collect.js";
import { buildFindings, summarize } from "./analyzers/findings.js";
import { INSTALLGLASS_VERSION, LIMITATIONS, REPORT_SCHEMA_VERSION } from "./constants.js";
import { DockerClient } from "./docker.js";
import { renderJson } from "./reporters/json.js";
import { renderMarkdown } from "./reporters/markdown.js";
import { createAuditWorkspace, removeAuditWorkspace } from "./workspace.js";
import type { AuditOptions, AuditReport } from "./types.js";

async function writePrivateFile(path: string, content: string): Promise<void> {
  const absolute = resolve(path);
  await mkdir(dirname(absolute), { recursive: true });
  await writeFile(absolute, content, { encoding: "utf8", mode: 0o600 });
}

export async function auditPackage(options: AuditOptions): Promise<AuditReport> {
  const started = Date.now();
  const startedAt = new Date(started).toISOString();
  const workspace = await createAuditWorkspace(options.packageSpec);
  try {
    const client = new DockerClient(options.dockerCommand);
    const run = await client.runAudit(
      options,
      {
        analysisDirectory: workspace.analysis,
        outputDirectory: workspace.output,
        proxyOutputDirectory: workspace.proxyOutput,
      },
      workspace.preparedSpec.containerSpec,
    );
    const dockerVersion = run.dockerVersion;
    const imageId = run.imageId;
    const image = run.image;
    const timedOut = run.command.timedOut;

    const collected = await collectEvidence(workspace.output, workspace.proxyOutput);
    const installCompleted = !timedOut && collected.sandboxResult?.installExitCode === 0;
    if (run.command.exitCode !== 0 && !timedOut && !collected.sandboxResult) {
      collected.warnings.push("The analysis container exited before producing a completion record.");
    }
    const findings = buildFindings(collected.evidence, installCompleted, collected.warnings);
    const completed = Date.now();
    const sanitizedSandboxResult = collected.sandboxResult
      ? { ...collected.sandboxResult, packageSpec: workspace.preparedSpec.displaySpec }
      : null;
    const report: AuditReport = {
      metadata: {
        installGlassVersion: INSTALLGLASS_VERSION,
        schemaVersion: REPORT_SCHEMA_VERSION,
        packageSpec: workspace.preparedSpec.displaySpec,
        startedAt,
        completedAt: new Date(completed).toISOString(),
        durationMs: completed - started,
        timedOut,
        dockerVersion,
        sandboxImage: image,
        sandboxImageId: imageId,
        sandboxResult: sanitizedSandboxResult,
      },
      summary: summarize(findings, installCompleted),
      evidence: collected.evidence,
      findings,
      limitations: [...LIMITATIONS, ...collected.warnings.map((warning) => `Collection warning: ${warning}`)],
    };

    await writePrivateFile(options.outputPath, renderMarkdown(report));
    if (options.jsonPath) await writePrivateFile(options.jsonPath, renderJson(report));
    return report;
  } finally {
    if (!options.keepWorkspace) await removeAuditWorkspace(workspace);
  }
}
