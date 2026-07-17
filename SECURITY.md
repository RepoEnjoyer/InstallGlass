# Security policy

## Supported versions

Security fixes are provided for the latest release. During the initial 1.x series, upgrade to the newest tagged version before reporting a result discrepancy.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository:

1. Open the repository's **Security** tab.
2. Choose **Report a vulnerability**.
3. Describe the affected version, impact, minimal reproduction, and proposed mitigation if known.

Do not open a public issue for sandbox escapes, credential exposure, proxy bypasses, unsafe report disclosure, or other vulnerabilities that could put users at risk. Do not include real credentials, private package contents, personal data, or unreviewed audit reports in a submission. Synthetic fixtures are preferred.

RepoEnjoyer will aim to acknowledge a complete report within seven days. Fix timing depends on severity and reproducibility. No bounty is currently offered.

## Security boundaries worth reviewing

- `src/docker.ts`: container flags, mounts, networks, and cleanup
- `sandbox/proxy.mjs`: destination validation and DNS rebinding defenses
- `sandbox/env-hook.cjs`: data minimization and redaction
- `src/analyzers`: normalization and false-positive boundaries
- `src/reporters`: report privacy

## Safe disclosure testing

Never test against infrastructure or packages you do not own or have permission to examine. The integration fixture in `test/fixtures/probe-package` deliberately exercises the main evidence paths without using real secrets or external targets beyond the public npm registry.
