import { join } from "node:path";
import { analyzeHookRecords, parseLifecycleLog } from "./hook.js";
import { analyzeProxyRecords } from "./proxy.js";
import { analyzeStraceFiles } from "./strace.js";
import { findFiles, readJson, readJsonLines } from "../io.js";
import type {
  AuditEvidence,
  HookRecord,
  ManifestEntry,
  NativeArtifact,
  ProxyRecord,
  SandboxResult,
  StaticSignal,
} from "../types.js";

export interface CollectionResult {
  sandboxResult: SandboxResult | null;
  evidence: AuditEvidence;
  warnings: string[];
}

function projectPath(path: string): string {
  return `<project>/${path.replace(/^\.\//u, "")}`;
}

export async function collectEvidence(outputDirectory: string, proxyOutputDirectory: string): Promise<CollectionResult> {
  const warnings: string[] = [];
  const [sandboxResult, manifest, nativeArtifacts, staticSignals, hookLines, proxyLines, tracePaths, lifecycleScripts] =
    await Promise.all([
      readJson<SandboxResult>(join(outputDirectory, "sandbox-result.json")),
      readJson<ManifestEntry[]>(join(outputDirectory, "manifest.json")),
      readJson<NativeArtifact[]>(join(outputDirectory, "native.json")),
      readJson<StaticSignal[]>(join(outputDirectory, "static.json")),
      readJsonLines<HookRecord>(join(outputDirectory, "hook.jsonl")),
      readJsonLines<ProxyRecord>(join(proxyOutputDirectory, "network.jsonl")),
      findFiles(outputDirectory, "trace"),
      parseLifecycleLog(join(outputDirectory, "npm.stderr.log")),
    ]);

  if (!sandboxResult) warnings.push("The sandbox did not produce its completion record.");
  if (tracePaths.length === 0) warnings.push("No syscall trace files were produced.");
  if (hookLines.rejected > 0) warnings.push(`${hookLines.rejected} malformed Node instrumentation record(s) were ignored.`);
  if (proxyLines.rejected > 0) warnings.push(`${proxyLines.rejected} malformed proxy record(s) were ignored.`);
  if (sandboxResult?.truncated.manifest) warnings.push("The installed-file manifest reached its collection limit.");
  if (sandboxResult?.truncated.staticSignals) warnings.push("The static-signal scan reached its collection limit.");

  const hook = analyzeHookRecords(hookLines.records);
  const proxyNetwork = analyzeProxyRecords(proxyLines.records);
  const syscall = await analyzeStraceFiles(tracePaths);

  return {
    sandboxResult,
    warnings,
    evidence: {
      files: syscall.files,
      manifest: (manifest ?? []).map((entry) => ({ ...entry, path: projectPath(entry.path) })),
      lifecycleScripts,
      processes: hook.processes,
      network: [...proxyNetwork, ...syscall.directNetwork].sort((left, right) =>
        `${left.hostname}:${left.port}:${left.method}`.localeCompare(`${right.hostname}:${right.port}:${right.method}`),
      ),
      environment: hook.environment,
      nativeArtifacts: (nativeArtifacts ?? []).map((entry) => ({ ...entry, path: projectPath(entry.path) })),
      staticSignals: (staticSignals ?? []).map((entry) => ({
        ...entry,
        path: projectPath(`node_modules/${entry.path}`),
      })),
      credentialPathReads: syscall.credentialPathReads,
    },
  };
}
