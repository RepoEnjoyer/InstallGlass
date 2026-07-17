import { createHash } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { buildManifest, staticScan } from "./scan.mjs";

const packageSpec = process.argv[2];
if (!packageSpec) {
  process.stderr.write("InstallGlass sandbox runner requires one package specification.\n");
  process.exit(2);
}

const analysisRoot = "/analysis";
const projectRoot = join(analysisRoot, "project");
const homeRoot = join(analysisRoot, "home");
const outputRoot = "/output";

async function seedDecoys() {
  const decoys = [
    [".ssh/id_rsa", "INSTALLGLASS_DECOY_PRIVATE_KEY"],
    [".aws/credentials", "[default]\naws_access_key_id=INSTALLGLASS_DECOY"],
    [".git-credentials", "INSTALLGLASS_DECOY_CREDENTIAL"],
    [".docker/config.json", '{"auths":{"example.invalid":{"auth":"INSTALLGLASS_DECOY"}}}'],
    [".config/gcloud/application_default_credentials.json", '{"type":"installglass_decoy"}'],
  ];
  for (const [relativePath, content] of decoys) {
    const path = join(homeRoot, relativePath);
    await mkdir(join(path, ".."), { recursive: true });
    await writeFile(path, `${content}\n`, { encoding: "utf8", mode: 0o600 });
    await chmod(path, 0o600);
  }
}

await Promise.all([
  mkdir(projectRoot, { recursive: true }),
  mkdir(outputRoot, { recursive: true }),
  mkdir(join(analysisRoot, "npm-cache"), { recursive: true }),
  seedDecoys(),
]);

await writeFile(
  join(projectRoot, "package.json"),
  `${JSON.stringify({ name: "installglass-analysis-target", version: "0.0.0", private: true }, null, 2)}\n`,
  "utf8",
);

const stdoutPath = join(outputRoot, "npm.stdout.log");
const stderrPath = join(outputRoot, "npm.stderr.log");
const npmVersion = spawnSync("npm", ["--version"], { encoding: "utf8" }).stdout.trim();
const startedAt = Date.now();
const npm = spawn(
  "npm",
  [
    "install",
    "--foreground-scripts",
    "--ignore-scripts=false",
    "--no-audit",
    "--no-fund",
    "--package-lock=true",
    "--save-exact",
    "--loglevel=verbose",
    "--",
    packageSpec,
  ],
  {
    cwd: projectRoot,
    env: process.env,
    stdio: ["ignore", "pipe", "pipe"],
  },
);

const stdoutChunks = [];
const stderrChunks = [];
npm.stdout.on("data", (chunk) => stdoutChunks.push(chunk));
npm.stderr.on("data", (chunk) => stderrChunks.push(chunk));
const completion = await new Promise((resolve) => {
  npm.on("error", (error) => resolve({ code: null, signal: error.code || "SPAWN_ERROR" }));
  npm.on("close", (code, signal) => resolve({ code, signal }));
});
await Promise.all([
  writeFile(stdoutPath, Buffer.concat(stdoutChunks), { mode: 0o600 }),
  writeFile(stderrPath, Buffer.concat(stderrChunks), { mode: 0o600 }),
]);

const { manifest, nativeArtifacts, truncated: manifestTruncated } = await buildManifest(projectRoot);
const nodeModules = join(projectRoot, "node_modules");
const scan = await staticScan(nodeModules).catch(() => ({ signals: [], filesScanned: 0, truncated: false }));
let lockfileSha256 = null;
let resolvedPackages = 0;
try {
  const lockBytes = await readFile(join(projectRoot, "package-lock.json"));
  lockfileSha256 = createHash("sha256").update(lockBytes).digest("hex");
  const lock = JSON.parse(lockBytes.toString("utf8"));
  resolvedPackages = Math.max(0, Object.keys(lock.packages ?? {}).length - 1);
} catch {
  // Failed installs may not produce a lockfile.
}

await Promise.all([
  writeFile(join(outputRoot, "manifest.json"), `${JSON.stringify(manifest)}\n`, { mode: 0o600 }),
  writeFile(join(outputRoot, "native.json"), `${JSON.stringify(nativeArtifacts)}\n`, { mode: 0o600 }),
  writeFile(join(outputRoot, "static.json"), `${JSON.stringify(scan.signals)}\n`, { mode: 0o600 }),
  writeFile(
    join(outputRoot, "sandbox-result.json"),
    `${JSON.stringify({
      packageSpec,
      installExitCode: completion.code,
      installSignal: completion.signal,
      nodeVersion: process.version,
      npmVersion,
      durationMs: Date.now() - startedAt,
      resolvedPackages,
      lockfileSha256,
      manifestEntries: manifest.length,
      staticFilesScanned: scan.filesScanned,
      truncated: { manifest: manifestTruncated, staticSignals: scan.truncated },
    })}\n`,
    { mode: 0o600 },
  ),
]);
