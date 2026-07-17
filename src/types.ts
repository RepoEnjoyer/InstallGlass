export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type FindingCategory =
  | "credentials"
  | "environment"
  | "filesystem"
  | "lifecycle"
  | "native-code"
  | "network"
  | "obfuscation"
  | "process"
  | "sandbox";

export interface Finding {
  id: string;
  severity: Severity;
  category: FindingCategory;
  title: string;
  detail: string;
  evidence: string[];
  recommendation: string;
  confidence: "high" | "medium" | "low";
}

export interface FileEvent {
  operation: "create" | "delete" | "metadata" | "mkdir" | "read" | "rename" | "write";
  path: string;
  count: number;
}

export interface ManifestEntry {
  path: string;
  size: number;
  mode: number;
  sha256?: string;
}

export interface LifecycleEvent {
  packageName: string | null;
  packageVersion: string | null;
  lifecycle: string | null;
  command: string;
  cwd: string | null;
  count: number;
}

export interface ProcessEvent {
  executable: string;
  arguments: string[];
  packageName: string | null;
  lifecycle: string | null;
  count: number;
}

export interface NetworkEvent {
  hostname: string;
  port: number;
  method: "CONNECT" | "HTTP" | "DIRECT";
  blocked: boolean;
  reason?: string;
  count: number;
}

export interface EnvironmentAccess {
  variable: string;
  operations: ("get" | "has" | "list")[];
  packageName: string | null;
  lifecycle: string | null;
  count: number;
}

export interface NativeArtifact {
  path: string;
  format: "ELF" | "Mach-O" | "PE" | "WebAssembly" | "executable-script";
  size: number;
  sha256: string;
}

export interface StaticSignal {
  rule: string;
  path: string;
  line: number;
  fingerprint: string;
  confidence: "high" | "medium" | "low";
}

export interface SandboxResult {
  packageSpec: string;
  installExitCode: number | null;
  installSignal: string | null;
  nodeVersion: string;
  npmVersion: string;
  resolvedPackages: number;
  lockfileSha256: string | null;
  manifestEntries: number;
  truncated: {
    manifest: boolean;
    staticSignals: boolean;
  };
}

export interface AuditEvidence {
  files: FileEvent[];
  manifest: ManifestEntry[];
  lifecycleScripts: LifecycleEvent[];
  processes: ProcessEvent[];
  network: NetworkEvent[];
  environment: EnvironmentAccess[];
  nativeArtifacts: NativeArtifact[];
  staticSignals: StaticSignal[];
  credentialPathReads: string[];
}

export interface AuditMetadata {
  installGlassVersion: string;
  schemaVersion: number;
  packageSpec: string;
  startedAt: string;
  completedAt: string;
  durationMs: number;
  timedOut: boolean;
  dockerVersion: string;
  sandboxImage: string;
  sandboxImageId: string;
  sandboxResult: SandboxResult | null;
}

export interface AuditSummary {
  riskScore: number;
  verdict: "low-observed-risk" | "review-recommended" | "high-risk-behavior" | "incomplete";
  findingsBySeverity: Record<Severity, number>;
  installCompleted: boolean;
}

export interface AuditReport {
  metadata: AuditMetadata;
  summary: AuditSummary;
  evidence: AuditEvidence;
  findings: Finding[];
  limitations: string[];
}

export interface AuditOptions {
  packageSpec: string;
  outputPath: string;
  jsonPath?: string;
  timeoutMs: number;
  memory: string;
  cpus: number;
  pidsLimit: number;
  dockerCommand: string;
  rebuildImage: boolean;
  keepWorkspace: boolean;
  failOn?: Exclude<Severity, "info">;
}

export interface CommandResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  timedOut: boolean;
}

export interface HookRecord {
  type: "child_process" | "env_access" | "hook_error" | "process_start";
  operation?: "get" | "has" | "list";
  variable?: string;
  executable?: string;
  arguments?: string[];
  pid?: number;
  childPid?: number;
  packageName?: string | null;
  packageVersion?: string | null;
  lifecycle?: string | null;
  cwd?: string | null;
}

export interface ProxyRecord {
  hostname: string;
  port: number;
  method: "CONNECT" | "HTTP";
  blocked: boolean;
  reason?: string;
}

export interface RawSandboxEvidence {
  sandboxResult: SandboxResult | null;
  files: FileEvent[];
  manifest: ManifestEntry[];
  lifecycleScripts: LifecycleEvent[];
  processes: ProcessEvent[];
  network: NetworkEvent[];
  environment: EnvironmentAccess[];
  nativeArtifacts: NativeArtifact[];
  staticSignals: StaticSignal[];
  credentialPathReads: string[];
  collectionWarnings: string[];
}
