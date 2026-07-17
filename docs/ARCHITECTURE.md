# Architecture

InstallGlass separates orchestration, execution, egress, collection, interpretation, and presentation so each trust boundary can be reviewed independently.

## Components

1. `src/cli.ts` validates user input and resource limits.
2. `src/workspace.ts` creates a mode-`0700` disposable host workspace. Local package inputs are copied under a fixed neutral name.
3. `src/docker.ts` builds the pinned sandbox image, creates two fresh Docker bridge networks, and starts the proxy and analysis containers.
4. `sandbox/proxy.mjs` resolves each requested destination, rejects private/reserved results, connects to a selected public address, and records destination metadata.
5. `sandbox/sandbox-runner.mjs` builds a clean npm project, seeds decoy credential files, invokes npm with foreground lifecycle scripts, and inventories the result.
6. `sandbox/env-hook.cjs` is injected into Node processes with `NODE_OPTIONS`. It records environment-variable names and child-process metadata without values.
7. `strace` records file, process, and network syscalls for the entire install tree.
8. `src/analyzers` normalizes, aggregates, and classifies raw evidence.
9. `src/reporters` produces deterministic Markdown and JSON views from the same typed report object.

## Network topology

The analysis container joins only an `--internal` Docker bridge. The proxy joins both that internal bridge and a separate egress bridge. The analysis container receives standard HTTP proxy variables and cannot route directly to the internet through its own network.

The analysis container drops all capabilities and then adds only `SYS_PTRACE`, which Docker's default seccomp policy uses to permit syscall tracing. The proxy remains in a separate container and PID namespace with every capability dropped.

The proxy resolves hostnames itself and connects to a chosen IP rather than resolving again in the connection call. Any result set containing a private or reserved address is blocked to reduce DNS rebinding risk. HTTPS passes through as an opaque CONNECT tunnel; TLS is not intercepted.

## Data flow

Raw evidence exists only in the temporary mode-`0700` workspace unless `--keep-workspace` is explicitly used. The report intentionally excludes npm stdout/stderr, environment values, HTTP headers and bodies, query strings, source snippets, and host paths. Output reports are created with mode `0600` where supported.

## Finding model

Findings are deterministic rules, not learned judgments. Each rule has a severity, confidence, explanation, evidence list, and recommendation. The risk score is a capped sum used for sorting attention:

| Severity | Weight |
| --- | ---: |
| Critical | 45 |
| High | 28 |
| Medium | 12 |
| Low | 4 |
| Info | 0 |

An incomplete install always produces the `incomplete` verdict even if other evidence is present.

## Dependency policy

The published CLI has no runtime npm dependencies. Node built-ins implement process execution, HTTP proxying, parsing, hashing, and file operations. Development dependencies are exact-version locked.
