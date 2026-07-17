import type { AuditEvidence, AuditSummary, Finding, Severity } from "../types.js";

const severityWeight: Record<Severity, number> = { critical: 45, high: 28, medium: 12, low: 4, info: 0 };
const sensitiveEnvironment = /(?:TOKEN|SECRET|PASSWORD|PASSWD|AUTH|COOKIE|CREDENTIAL|PRIVATE|API_KEY|ACCESS_KEY|AWS_|AZURE_|GITHUB_|NPM_TOKEN)/iu;
const suspiciousExecutable = /(?:^|\/)(?:bash|sh|zsh|curl|wget|nc|ncat|socat|python|python3|powershell|pwsh)$/iu;

function finding(value: Finding): Finding {
  return value;
}

export function buildFindings(evidence: AuditEvidence, installCompleted: boolean, collectionWarnings: string[]): Finding[] {
  const findings: Finding[] = [];

  if (!installCompleted) {
    findings.push(finding({
      id: "sandbox.install-incomplete",
      severity: "medium",
      category: "sandbox",
      title: "Installation did not complete successfully",
      detail: "The evidence may cover only the portion of the install that ran before failure or timeout.",
      evidence: [],
      recommendation: "Review the npm diagnostic and rerun after resolving the install error.",
      confidence: "high",
    }));
  }

  if (collectionWarnings.length > 0) {
    findings.push(finding({
      id: "sandbox.collection-warning",
      severity: "low",
      category: "sandbox",
      title: "Evidence collection was incomplete",
      detail: "One or more collectors reported a warning.",
      evidence: collectionWarnings.slice(0, 20),
      recommendation: "Treat missing sections as unknown rather than safe and rerun if the warning is transient.",
      confidence: "high",
    }));
  }

  if (evidence.credentialPathReads.length > 0) {
    findings.push(finding({
      id: "credentials.path-read",
      severity: "critical",
      category: "credentials",
      title: "Credential locations were read during installation",
      detail: "A process opened one or more decoy credential paths. InstallGlass never places real credentials in the sandbox.",
      evidence: evidence.credentialPathReads.slice(0, 25),
      recommendation: "Do not install this package on a trusted host until the responsible code and maintainer intent are understood.",
      confidence: "high",
    }));
  }

  const sensitiveAccess = evidence.environment.filter((event) => sensitiveEnvironment.test(event.variable));
  if (sensitiveAccess.length > 0) {
    findings.push(finding({
      id: "environment.sensitive-name",
      severity: "high",
      category: "environment",
      title: "Sensitive environment-variable names were accessed",
      detail: "Only variable names and access operations were recorded; values were never captured.",
      evidence: sensitiveAccess.slice(0, 25).map((event) => `${event.variable} (${event.operations.join(", ")})`),
      recommendation: "Inspect the accessing lifecycle script and avoid exposing credentials during installation.",
      confidence: "high",
    }));
  }

  const blockedNetwork = evidence.network.filter((event) => event.blocked);
  if (blockedNetwork.length > 0) {
    findings.push(finding({
      id: "network.blocked-private",
      severity: "high",
      category: "network",
      title: "Network destinations were blocked by policy",
      detail: "The egress proxy rejected a private, reserved, invalid, or DNS-rebinding destination.",
      evidence: blockedNetwork.slice(0, 25).map((event) => `${event.hostname}:${event.port}${event.reason ? ` — ${event.reason}` : ""}`),
      recommendation: "Determine why installation attempted to contact this destination before trusting the package.",
      confidence: "high",
    }));
  }

  const directNetwork = evidence.network.filter((event) => event.method === "DIRECT");
  if (directNetwork.length > 0) {
    findings.push(finding({
      id: "network.direct-attempt",
      severity: "high",
      category: "network",
      title: "A direct network connection was attempted outside the proxy path",
      detail: "Syscall tracing observed a non-proxy connection attempt. The internal Docker network should prevent internet routing.",
      evidence: directNetwork.slice(0, 25).map((event) => `${event.hostname}:${event.port}`),
      recommendation: "Review the initiating process and treat the package as untrusted.",
      confidence: "high",
    }));
  }

  if (evidence.lifecycleScripts.length > 0) {
    findings.push(finding({
      id: "lifecycle.executed",
      severity: "low",
      category: "lifecycle",
      title: "npm lifecycle scripts executed",
      detail: "Lifecycle scripts can run arbitrary commands with the installing user's permissions outside a sandbox.",
      evidence: evidence.lifecycleScripts.slice(0, 25).map((event) => `${event.packageName}@${event.packageVersion} ${event.lifecycle}: ${event.command}`),
      recommendation: "Confirm each script is expected for the package's documented functionality.",
      confidence: "high",
    }));
  }

  const suspiciousProcesses = evidence.processes.filter((event) => suspiciousExecutable.test(event.executable));
  if (suspiciousProcesses.length > 0) {
    findings.push(finding({
      id: "process.shell-or-downloader",
      severity: "medium",
      category: "process",
      title: "Shells or common downloader processes were spawned",
      detail: "This can be legitimate build behavior, but it increases the install script's capability surface.",
      evidence: suspiciousProcesses.slice(0, 25).map((event) => `${event.executable} ${event.arguments.join(" ")}`.trim()),
      recommendation: "Inspect the associated lifecycle command and verify any downloaded artifact independently.",
      confidence: "medium",
    }));
  }

  if (evidence.nativeArtifacts.length > 0) {
    findings.push(finding({
      id: "native-code.present",
      severity: "medium",
      category: "native-code",
      title: "Native or directly executable artifacts are present",
      detail: "Native code is less transparent to JavaScript-only review and may be platform-specific.",
      evidence: evidence.nativeArtifacts.slice(0, 25).map((artifact) => `${artifact.format} ${artifact.path} (${artifact.size} bytes, sha256:${artifact.sha256.slice(0, 12)}…)`),
      recommendation: "Verify artifact provenance, hashes, supported platforms, and whether source builds are available.",
      confidence: "high",
    }));
  }

  const credentialSignals = evidence.staticSignals.filter((signal) => signal.rule === "credential-path-literal");
  if (credentialSignals.length > 0) {
    findings.push(finding({
      id: "static.credential-path",
      severity: "medium",
      category: "credentials",
      title: "Installed source contains credential-path literals",
      detail: "This is a static heuristic and does not prove the path was accessed.",
      evidence: credentialSignals.slice(0, 25).map((signal) => `${signal.path}:${signal.line} (${signal.fingerprint})`),
      recommendation: "Inspect the matching source and compare it with runtime credential-path evidence.",
      confidence: "medium",
    }));
  }

  const obfuscation = evidence.staticSignals.filter((signal) => signal.rule !== "credential-path-literal");
  if (obfuscation.length > 0) {
    findings.push(finding({
      id: "static.obfuscation",
      severity: "medium",
      category: "obfuscation",
      title: "Potentially obscured or dynamically evaluated code was found",
      detail: "Heuristics can match minified bundles and legitimate compatibility code; manual review is required.",
      evidence: obfuscation.slice(0, 25).map((signal) => `${signal.rule}: ${signal.path}:${signal.line} (${signal.fingerprint})`),
      recommendation: "Review the exact files, preferably against the package's published source repository.",
      confidence: "medium",
    }));
  }

  return findings.sort((left, right) => severityWeight[right.severity] - severityWeight[left.severity] || left.id.localeCompare(right.id));
}

export function summarize(findings: Finding[], installCompleted: boolean): AuditSummary {
  const findingsBySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let riskScore = 0;
  for (const item of findings) {
    findingsBySeverity[item.severity] += 1;
    riskScore += severityWeight[item.severity];
  }
  riskScore = Math.min(100, riskScore);
  const verdict = !installCompleted
    ? "incomplete"
    : riskScore >= 55
      ? "high-risk-behavior"
      : riskScore >= 16
        ? "review-recommended"
        : "low-observed-risk";
  return { riskScore, verdict, findingsBySeverity, installCompleted };
}
