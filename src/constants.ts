export const INSTALLGLASS_VERSION = "1.0.0";
export const REPORT_SCHEMA_VERSION = 1;
export const SANDBOX_IMAGE = `installglass/sandbox:${INSTALLGLASS_VERSION}`;
export const DEFAULT_TIMEOUT_MS = 120_000;
export const DEFAULT_MEMORY = "768m";
export const DEFAULT_CPUS = 1.5;
export const DEFAULT_PIDS_LIMIT = 256;
export const MAX_CAPTURE_BYTES = 2 * 1024 * 1024;

export const LIMITATIONS = [
  "InstallGlass observes one installation run; conditional behavior may differ by operating system, architecture, time, or remote response.",
  "Environment-variable access is instrumented for Node.js processes. Native programs and processes that remove NODE_OPTIONS can read inherited variables without appearing in that evidence section.",
  "TLS is not intercepted. Network evidence records proxy destinations and blocked direct connections, not encrypted request bodies.",
  "Static signals are heuristics, not a malware verdict. Minified, generated, and compatibility code can trigger them.",
  "Containers reduce exposure but do not provide a virtual-machine security boundary. Keep Docker and the host kernel updated.",
] as const;
