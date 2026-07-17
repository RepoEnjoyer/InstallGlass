#!/usr/bin/env node
import { resolve } from "node:path";
import { auditPackage } from "./audit.js";
import {
  DEFAULT_CPUS,
  DEFAULT_MEMORY,
  DEFAULT_PIDS_LIMIT,
  DEFAULT_TIMEOUT_MS,
  INSTALLGLASS_VERSION,
} from "./constants.js";
import { DockerClient } from "./docker.js";
import { InstallGlassError } from "./errors.js";
import type { AuditOptions, Severity } from "./types.js";

const usage = `InstallGlass ${INSTALLGLASS_VERSION}

Run npm installation in a hardened Docker sandbox and produce an evidence report.

Usage:
  installglass audit <package-spec> [options]
  installglass doctor [--docker-command <command>]
  installglass --help

Examples:
  installglass audit lodash
  installglass audit some-package@1.2.3 --output audit.md --json audit.json
  installglass audit ./local-package --timeout 3m --fail-on high

Options:
  -o, --output <path>       Markdown report (default: installglass-report.md)
      --json <path>         Also write the complete JSON evidence report
      --timeout <duration>  Sandbox timeout, such as 90s or 3m (default: 2m)
      --memory <limit>      Docker memory limit (default: ${DEFAULT_MEMORY})
      --cpus <count>        Docker CPU limit (default: ${DEFAULT_CPUS})
      --pids-limit <count>  Process limit (default: ${DEFAULT_PIDS_LIMIT})
      --docker-command <c>  Docker-compatible command (default: docker)
      --rebuild             Rebuild the pinned sandbox image
      --keep-workspace      Retain temporary evidence for local debugging
      --fail-on <severity>  Exit 3 at or above: low, medium, high, critical
  -h, --help                Show help
  -v, --version             Show version
`;

const failureRank: Record<Exclude<Severity, "info">, number> = { low: 1, medium: 2, high: 3, critical: 4 };

function valueAfter(args: string[], index: number, option: string): string {
  const value = args[index + 1];
  if (!value || value.startsWith("-")) throw new InstallGlassError("INVALID_OPTION", `${option} requires a value.`);
  return value;
}

function duration(value: string): number {
  const match = /^(\d+)(ms|s|m)?$/u.exec(value);
  if (!match) throw new InstallGlassError("INVALID_TIMEOUT", "Timeout must be a positive duration such as 90000ms, 90s, or 3m.");
  const amount = Number(match[1]);
  const multiplier = match[2] === "m" ? 60_000 : match[2] === "s" ? 1_000 : 1;
  const result = amount * multiplier;
  if (result < 1_000 || result > 30 * 60_000) throw new InstallGlassError("INVALID_TIMEOUT", "Timeout must be between 1 second and 30 minutes.");
  return result;
}

function positiveNumber(value: string, option: string, maximum: number): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0 || parsed > maximum) {
    throw new InstallGlassError("INVALID_OPTION", `${option} must be greater than zero and no more than ${maximum}.`);
  }
  return parsed;
}

function parseAudit(args: string[]): AuditOptions {
  const packageSpec = args[0];
  if (!packageSpec || packageSpec.startsWith("-")) throw new InstallGlassError("MISSING_SPEC", "The audit command requires one package specification.");
  const options: AuditOptions = {
    packageSpec,
    outputPath: "installglass-report.md",
    timeoutMs: DEFAULT_TIMEOUT_MS,
    memory: DEFAULT_MEMORY,
    cpus: DEFAULT_CPUS,
    pidsLimit: DEFAULT_PIDS_LIMIT,
    dockerCommand: "docker",
    rebuildImage: false,
    keepWorkspace: false,
  };

  for (let index = 1; index < args.length; index += 1) {
    const option = args[index];
    if (option === "-o" || option === "--output") options.outputPath = valueAfter(args, index++, option);
    else if (option === "--json") options.jsonPath = valueAfter(args, index++, option);
    else if (option === "--timeout") options.timeoutMs = duration(valueAfter(args, index++, option));
    else if (option === "--memory") {
      const value = valueAfter(args, index++, option);
      if (!/^\d+(?:[kmg])?$/iu.test(value)) throw new InstallGlassError("INVALID_OPTION", "--memory must be a Docker size such as 768m or 1g.");
      options.memory = value.toLowerCase();
    } else if (option === "--cpus") options.cpus = positiveNumber(valueAfter(args, index++, option), option, 64);
    else if (option === "--pids-limit") options.pidsLimit = Math.floor(positiveNumber(valueAfter(args, index++, option), option, 32_768));
    else if (option === "--docker-command") options.dockerCommand = valueAfter(args, index++, option);
    else if (option === "--rebuild") options.rebuildImage = true;
    else if (option === "--keep-workspace") options.keepWorkspace = true;
    else if (option === "--fail-on") {
      const value = valueAfter(args, index++, option) as Exclude<Severity, "info">;
      if (!(value in failureRank)) throw new InstallGlassError("INVALID_OPTION", "--fail-on must be low, medium, high, or critical.");
      options.failOn = value;
    } else {
      throw new InstallGlassError("INVALID_OPTION", `Unknown option: ${option ?? ""}`);
    }
  }
  options.outputPath = resolve(options.outputPath);
  if (options.jsonPath) options.jsonPath = resolve(options.jsonPath);
  return options;
}

async function main(): Promise<number> {
  const args = process.argv.slice(2);
  if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
    process.stdout.write(usage);
    return 0;
  }
  if (args[0] === "--version" || args[0] === "-v") {
    process.stdout.write(`${INSTALLGLASS_VERSION}\n`);
    return 0;
  }
  if (args[0] === "doctor") {
    let dockerCommand = "docker";
    if (args[1] === "--docker-command") dockerCommand = valueAfter(args, 1, "--docker-command");
    else if (args.length > 1) throw new InstallGlassError("INVALID_OPTION", `Unknown doctor option: ${args[1] ?? ""}`);
    const result = await new DockerClient(dockerCommand).doctor();
    process.stdout.write(`Docker Engine ${result.version} is available.\n`);
    return 0;
  }
  const auditArguments = args[0] === "audit" ? args.slice(1) : args;
  const options = parseAudit(auditArguments);
  const isLocal = options.packageSpec.startsWith(".") || options.packageSpec.startsWith("/") || options.packageSpec.startsWith("file:") || /^[A-Za-z]:[\\/]/u.test(options.packageSpec);
  process.stdout.write(`Auditing ${isLocal ? "local package" : options.packageSpec}…\n`);
  const report = await auditPackage(options);
  process.stdout.write(`Report written. Verdict: ${report.summary.verdict}; observed-risk score: ${report.summary.riskScore}/100.\n`);
  if (options.failOn) {
    const threshold = failureRank[options.failOn];
    const shouldFail = report.findings.some((item) => item.severity !== "info" && failureRank[item.severity] >= threshold);
    if (shouldFail) return 3;
  }
  return 0;
}

main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((error: unknown) => {
    const message = error instanceof Error ? error.message : "Unknown error";
    const code = error instanceof InstallGlassError ? error.code : "UNEXPECTED_ERROR";
    process.stderr.write(`InstallGlass error [${code}]: ${message}\n`);
    process.exitCode = 1;
  });
