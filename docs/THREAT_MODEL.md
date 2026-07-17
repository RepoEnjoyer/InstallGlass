# Threat model

## Goal

InstallGlass aims to let a developer observe an untrusted npm package's ordinary installation behavior without exposing routine host files, package-manager credentials, or unrestricted host networking.

## Protected assets

- Host files outside InstallGlass's disposable workspace
- Host environment variables and credential stores
- npm, Git, Docker, cloud, and SSH credentials
- Local network and metadata-service endpoints
- Host CPU, memory, and process availability
- Report privacy

## Assumed attacker

The package may run arbitrary lifecycle code, spawn processes, use native executables, attempt network access, inspect its filesystem and environment, detect analysis, exhaust resources, or exploit the container runtime/kernel.

## Controls

- No host project directory is mounted into the analysis container.
- Local targets are copied into a temporary directory rather than mounted from their original path.
- The container runs as a non-root numeric user with a read-only root, `no-new-privileges`, and only `SYS_PTRACE` retained so `strace` can follow the container's own process tree. The separate proxy drops every capability.
- CPU, memory, PID, and wall-clock limits constrain basic denial of service.
- Only disposable analysis and evidence directories are writable bind mounts.
- The analysis network is internal; a separate proxy provides constrained public egress.
- The proxy blocks loopback, private, link-local, multicast, reserved, `.local`, and mixed public/private DNS results.
- Real host credentials and configuration are not forwarded. Decoy files make credential-path reads visible.
- Reports omit values, request contents, raw source, raw logs, and host paths.

## Out of scope and residual risk

- Container escapes and kernel/runtime zero-days. Docker containers are not virtual machines.
- A package can attempt to interfere with same-user processes inside its disposable analysis container; no host processes or proxy process share that PID namespace.
- Side channels, covert channels, and resource-exhaustion techniques not stopped by configured limits.
- Behavior gated on a different OS, CPU, time, locale, registry response, user interaction, or sandbox detection.
- Environment access by native processes or code that removes `NODE_OPTIONS`.
- Decrypted HTTPS content. InstallGlass sees the destination, not the TLS payload.
- Attribution of every non-Node child process to an exact dependency when npm does not expose that relation.
- Authenticating package publisher intent or proving that registry artifacts match a source repository.

## Safe use guidance

- Keep Docker, its Linux VM/kernel, and the host OS updated.
- Prefer a dedicated VM when examining a package believed to contain an active container escape or kernel exploit.
- Pin exact package versions so evidence can be compared.
- Do not put tokens in package URLs or alter the sandbox to mount credential directories.
- Treat “low observed risk” as “nothing stronger appeared in this run,” never as certification.

See [SECURITY.md](../SECURITY.md) for vulnerability reporting.
