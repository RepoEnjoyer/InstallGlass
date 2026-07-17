# Contributing

Thanks for improving InstallGlass. Security controls and evidence claims need tests and clear limitations; small, reviewable pull requests are preferred.

## Development setup

Requirements: Node.js 20+, npm 10+, Docker Engine or Docker Desktop, and Git.

```bash
git clone https://github.com/RepoEnjoyer/InstallGlass.git
cd InstallGlass
npm ci
npm run check
```

`npm run check` runs ESLint, strict TypeScript checking, Vitest, and the production build. The repository `.npmrc` disables dependency lifecycle scripts during `npm ci`; explicit project scripts still work.

Run an end-to-end sandbox audit:

```bash
npm run build
node dist/cli.js audit ./test/fixtures/probe-package --json probe.json
```

The fixture should trigger a lifecycle record, a child Node process, a public registry destination, an `NPM_TOKEN` name access, a changed file, and a decoy SSH-key path read. It contains no real credentials.

## Pull requests

- Add or update tests for behavior changes.
- Document new evidence fields and limitations.
- Keep the runtime dependency count at zero unless a dependency is necessary, small, actively maintained, and security-reviewed.
- Never commit `.env` files, raw audit workspaces, private package contents, credentials, personal details, or machine-specific paths.
- Use synthetic domains under `example.invalid` in tests, except for the public npm integration ping.
- Do not weaken container, network, or report privacy defaults for convenience.
- Run `npm run check` and `npm pack --dry-run` before opening a pull request.

## Evidence rule design

Runtime evidence and static heuristics must remain distinct. A static string is not proof of execution. Each finding needs a stable ID, severity, confidence, bounded evidence, and useful remediation. Avoid claims that InstallGlass certifies software as safe or malicious.

## Commit style

Use concise imperative messages such as `Add proxy DNS rebinding test` or `Document native artifact limits`. By contributing, you agree that your work is licensed under the MIT License.
