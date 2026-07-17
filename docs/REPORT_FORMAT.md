# Report format

Every audit produces Markdown. `--json <path>` writes the complete machine-readable report using schema version `1`.

## Top-level JSON fields

| Field | Meaning |
| --- | --- |
| `metadata` | Tool/image/runtime identity, target spec, timing, and sandbox completion record |
| `summary` | Deterministic score, verdict, severity counts, and install status |
| `evidence` | Normalized runtime and static evidence arrays |
| `findings` | Rules triggered by the evidence, with recommendations |
| `limitations` | General limitations plus run-specific collection warnings |

## Evidence stability

Arrays are sorted where collection order has no meaning. Paths use placeholders such as `<project>`, `<home>`, `<input>`, and `<tmp>`. Local host paths are replaced with `file:<local-package>`.

Timestamps, durations, registry responses, generated package files, Docker image IDs, and syscall counts may differ between runs. Pin the target package version and compare `metadata.sandboxImageId` plus `metadata.sandboxResult.lockfileSha256` when investigating a difference.

## Privacy properties

Reports do not intentionally contain:

- environment-variable values;
- HTTP bodies, headers, credentials, or query strings;
- host npm/Git/Docker/cloud configuration;
- local package source paths;
- raw package source snippets;
- raw npm or container logs.

Child-process arguments are bounded and passed through token, URL-credential, decoy, and high-entropy redaction. Review any report before sharing it because arbitrary package-controlled filenames and command arguments can still be descriptive.

## Compatibility

Consumers should reject unknown major schema versions and ignore unknown fields. New evidence fields may be added in a minor InstallGlass release without removing existing schema-1 fields.
