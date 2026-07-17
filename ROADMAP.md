# Roadmap

InstallGlass 1.0 is intentionally narrow: high-signal npm installation evidence with privacy-safe defaults.

## Near term

- Add `installglass diff` for stable comparisons between package versions.
- Add a declarative policy file for allowed domains, lifecycle stages, native formats, and CI thresholds.
- Attribute non-Node child processes to lifecycle packages more precisely using PID lineage.
- Add tested rootless Docker and Podman support without weakening isolation.
- Emit SARIF alongside Markdown and JSON for code-scanning integrations.

## Later

- Verify npm provenance and registry signatures when the target publishes them.
- Add offline package/tarball analysis with all egress disabled.
- Add pnpm and Yarn adapters behind the same evidence schema.
- Provide optional content hashes for network responses without storing bodies.
- Ship signed release artifacts and reproducible sandbox-image attestations.

## Not planned

- Uploading reports or package contents to a hosted service.
- Automatically declaring packages “safe” or “malware.”
- Forwarding host registry credentials into the sandbox by default.
- Decrypting TLS traffic or collecting request bodies.

Roadmap items are directional, not promises. Contributions should preserve the zero-telemetry, local-first model.
