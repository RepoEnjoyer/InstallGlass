import type { AuditReport, Finding, Severity } from "../types.js";

type Cell = string | number | boolean | null | undefined;

function escapeCell(value: Cell): string {
  return String(value ?? "—").replace(/\|/gu, "\\|").replace(/\r?\n/gu, " ");
}

function code(value: Cell): string {
  return `\`${String(value ?? "—").replace(/`/gu, "\\`")}\``;
}

function table(headers: string[], rows: Cell[][]): string {
  if (rows.length === 0) return "_None observed._\n";
  return [
    `| ${headers.map(escapeCell).join(" | ")} |`,
    `| ${headers.map(() => "---").join(" | ")} |`,
    ...rows.map((row) => `| ${row.map(escapeCell).join(" | ")} |`),
    "",
  ].join("\n");
}

function findingSection(item: Finding): string {
  const evidence = item.evidence.length > 0 ? item.evidence.map((line) => `- ${code(line)}`).join("\n") : "- No additional evidence.";
  return [
    `### ${item.severity.toUpperCase()} · ${item.title}`,
    "",
    `${item.detail} Confidence: **${item.confidence}**.`,
    "",
    evidence,
    "",
    `**Recommendation:** ${item.recommendation}`,
    "",
  ].join("\n");
}

const verdictLabel: Record<AuditReport["summary"]["verdict"], string> = {
  "low-observed-risk": "Low observed risk",
  "review-recommended": "Review recommended",
  "high-risk-behavior": "High-risk behavior observed",
  incomplete: "Incomplete run",
};

export function renderMarkdown(report: AuditReport): string {
  const { metadata, summary, evidence } = report;
  const severities: Severity[] = ["critical", "high", "medium", "low", "info"];
  const changedFiles = evidence.files.filter((event) => event.operation !== "read");
  const readFiles = evidence.files.filter((event) => event.operation === "read");
  const sandbox = metadata.sandboxResult;

  return [
    "# InstallGlass audit report",
    "",
    `> **${verdictLabel[summary.verdict]} · ${summary.riskScore}/100 observed-risk score**`,
    "",
    "InstallGlass reports evidence from one sandboxed install. It does not certify that a package is safe.",
    "",
    "## Run summary",
    "",
    table(
      ["Field", "Value"],
      [
        ["Package specification", code(metadata.packageSpec)],
        ["Install completed", summary.installCompleted ? "Yes" : "No"],
        ["Started (UTC)", metadata.startedAt],
        ["Duration", `${metadata.durationMs} ms`],
        ["InstallGlass", metadata.installGlassVersion],
        ["Docker Engine", metadata.dockerVersion || "Unavailable"],
        ["Sandbox image", `${metadata.sandboxImage} (${metadata.sandboxImageId.slice(0, 20) || "unknown"})`],
        ["Node / npm", sandbox ? `${sandbox.nodeVersion} / ${sandbox.npmVersion}` : "No completion record"],
        ["Resolved packages", sandbox?.resolvedPackages ?? "Unknown"],
        ["Lockfile SHA-256", sandbox?.lockfileSha256 ?? "Not produced"],
      ],
    ),
    table(["Critical", "High", "Medium", "Low", "Info"], [severities.map((severity) => summary.findingsBySeverity[severity])]),
    "## Findings",
    "",
    report.findings.length > 0 ? report.findings.map(findingSection).join("\n") : "_No reportable behavior was observed._\n",
    "## Network destinations",
    "",
    "Destinations only; request bodies, headers, query strings, and credentials are not collected.",
    "",
    table(
      ["Destination", "Method", "Blocked", "Count", "Reason"],
      evidence.network.map((event) => [`${event.hostname}:${event.port}`, event.method, event.blocked ? "Yes" : "No", event.count, event.reason ?? "—"]),
    ),
    "## Lifecycle scripts",
    "",
    table(
      ["Package", "Stage", "Command", "Count"],
      evidence.lifecycleScripts.map((event) => [
        `${event.packageName ?? "unknown"}@${event.packageVersion ?? "unknown"}`,
        event.lifecycle ?? "unknown",
        code(event.command),
        event.count,
      ]),
    ),
    "## Child processes",
    "",
    table(
      ["Executable", "Arguments", "Lifecycle", "Count"],
      evidence.processes.map((event) => [code(event.executable), event.arguments.map(code).join(" "), event.lifecycle ?? "—", event.count]),
    ),
    "## Environment-variable access",
    "",
    "Names and access operations only. Values are never recorded.",
    "",
    table(
      ["Variable", "Operations", "Package / lifecycle", "Count"],
      evidence.environment.map((event) => [
        code(event.variable),
        event.operations.join(", "),
        [event.packageName, event.lifecycle].filter(Boolean).join(" / ") || "unattributed",
        event.count,
      ]),
    ),
    "## Files created or modified",
    "",
    table(
      ["Operation", "Path", "Count"],
      changedFiles.slice(0, 500).map((event) => [event.operation, code(event.path), event.count]),
    ),
    changedFiles.length > 500 ? `_Showing 500 of ${changedFiles.length} changed-path records._\n` : "",
    "## Sensitive path reads",
    "",
    evidence.credentialPathReads.length > 0
      ? evidence.credentialPathReads.map((path) => `- ${code(path)}`).join("\n") + "\n"
      : "_None observed._\n",
    "",
    "## Other file reads",
    "",
    table(["Path", "Count"], readFiles.slice(0, 200).map((event) => [code(event.path), event.count])),
    readFiles.length > 200 ? `_Showing 200 of ${readFiles.length} read-path records._\n` : "",
    "## Native and executable artifacts",
    "",
    table(
      ["Format", "Path", "Size", "SHA-256"],
      evidence.nativeArtifacts.map((artifact) => [artifact.format, code(artifact.path), artifact.size, code(artifact.sha256)]),
    ),
    "## Static signals",
    "",
    "These are source heuristics, not proof of malicious execution. No source snippets are copied into the report.",
    "",
    table(
      ["Rule", "Location", "Confidence", "Fingerprint"],
      evidence.staticSignals.map((signal) => [signal.rule, `${code(signal.path)}:${signal.line}`, signal.confidence, code(signal.fingerprint)]),
    ),
    "## Installed artifact manifest",
    "",
    `${evidence.manifest.length} entries were inventoried. The machine-readable JSON report contains the full manifest.`,
    "",
    "## Limitations",
    "",
    ...report.limitations.map((limitation) => `- ${limitation}`),
    "",
    "## Reproduction",
    "",
    `Run ${code(`installglass audit ${metadata.packageSpec}`)} with InstallGlass ${metadata.installGlassVersion} and sandbox image ${metadata.sandboxImage}. Exact registry responses can change over time; compare the lockfile hash and image ID above.`,
    "",
    `Report schema: ${metadata.schemaVersion}. Generated by [InstallGlass](https://github.com/RepoEnjoyer/InstallGlass).`,
    "",
  ].join("\n");
}
