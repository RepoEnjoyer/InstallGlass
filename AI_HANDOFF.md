# AI handoff

## Purpose

InstallGlass audits npm installation behavior inside a disposable Docker sandbox and produces privacy-minimized evidence. It is a security observation tool, not a malware classifier.

## Architecture

- `src/cli.ts`: argument parsing, resource validation, exit codes.
- `src/audit.ts`: audit orchestration and report writes.
- `src/docker.ts`: image lifecycle, isolated networks, hardened containers, cleanup.
- `src/spec.ts` and `src/workspace.ts`: safe input copying and temporary workspace ownership.
- `sandbox/sandbox-runner.mjs`: clean npm project, decoys, install, inventory.
- `sandbox/proxy.mjs`: public-only HTTP/CONNECT egress and destination logging.
- `sandbox/env-hook.cjs`: Node environment-name and child-process instrumentation.
- `sandbox/scan.mjs`: bounded artifact manifest, native detection, static heuristics.
- `src/analyzers`: JSONL/syscall parsing and deterministic finding rules.
- `src/reporters`: Markdown and JSON serialization.

## Important decisions

1. The analysis container has no direct egress. A separate proxy is the only routed path.
2. Real host npm configuration and credentials are never mounted or forwarded. v1 therefore does not support private registries.
3. HTTPS is not intercepted. Destination metadata is sufficient for the first release and avoids collecting secrets or content.
4. Environment instrumentation records names and operations only. It filters tool variables and never serializes values.
5. Local paths are copied under a neutral fixed name, and reports use `file:<local-package>`.
6. Static signals stay explicitly separate from runtime evidence.
7. There are zero runtime npm dependencies to reduce this security tool's own supply-chain surface.
8. The default Docker seccomp profile is retained. The analysis container adds only `SYS_PTRACE` after dropping all capabilities so `strace` can follow its own child tree. The proxy drops all capabilities. Do not add `--privileged`, share a PID namespace, or mount the Docker socket.

## Current limitations

- Only npm installs in Linux containers are supported.
- Native/non-Node environment access is not instrumented.
- PID lineage is not yet used to attribute every process and file event to a package.
- TLS contents are opaque.
- Static scanning is intentionally shallow and bounded.
- A single run cannot reveal dormant, conditional, or sandbox-aware behavior.
- Docker is unavailable in some development environments; CI owns the real-container regression test.

## Tests

- `test/spec.test.ts`: input validation and local-path privacy.
- `test/redact.test.ts`: token, URL credential, decoy, and entropy redaction.
- `test/analyzers.test.ts`: environment and proxy aggregation.
- `test/strace.test.ts`: syscall parsing, normalization, credential reads, proxy filtering.
- `test/findings.test.ts`: severity, scoring, and verdict behavior.
- `test/fixtures/probe-package`: end-to-end behavior fixture exercised by GitHub Actions.

Run `npm run check`. For container validation, build first and run the fixture exactly as documented in `CONTRIBUTING.md`. Never replace the synthetic fixture with a real suspicious package in CI.

## Sensible next steps

1. Implement PID lineage from `strace -ff` plus hook `childPid` records, then attach file/process/network evidence to exact lifecycle packages.
2. Add a version-diff report while preserving stable schema-1 fields.
3. Add policy and SARIF output for CI adoption.

## Guardrails for future AI work

- Credit only `RepoEnjoyer`.
- Never add personal names, email addresses, local paths, real credentials, private URLs, or copied audit data.
- Treat reports and fixture changes as security-sensitive.
- Verify claims with tests and update limitations when coverage is partial.
- Do not claim a release, workflow result, or external publication without checking GitHub.
