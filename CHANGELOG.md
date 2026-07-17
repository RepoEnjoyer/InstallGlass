# Changelog

All notable changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and releases follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-07-17

### Added

- Hardened, non-root Docker analysis container with read-only root filesystem and resource limits.
- Separate dual-network egress proxy that records destinations and blocks private/reserved addresses.
- Runtime tracing for file syscalls, child processes, npm lifecycle scripts, and Node environment-variable names.
- Decoy credential locations for detecting sensitive-path reads without exposing host data.
- Native artifact inventory with format, size, and SHA-256.
- Deterministic static signals for credential-path literals, dynamic evaluation, encoded payloads, dense escapes, and shell downloaders.
- Reproducible Markdown report and schema-versioned JSON output.
- Deterministic findings, observed-risk score, and CI-friendly severity threshold.
- Unit test suite and real Docker integration fixture.

[Unreleased]: https://github.com/RepoEnjoyer/InstallGlass/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/RepoEnjoyer/InstallGlass/releases/tag/v1.0.0
