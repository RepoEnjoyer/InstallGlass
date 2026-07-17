import { access } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";
import { runCommand } from "./command.js";
import { SANDBOX_IMAGE } from "./constants.js";
import { InstallGlassError } from "./errors.js";
import { redact } from "./redact.js";
import type { AuditOptions, CommandResult } from "./types.js";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const sandboxContext = resolve(packageRoot, "sandbox");

export interface DockerSessionPaths {
  analysisDirectory: string;
  outputDirectory: string;
  proxyOutputDirectory: string;
}

export interface DockerRunResult {
  command: CommandResult;
  dockerVersion: string;
  imageId: string;
  image: string;
}

function sessionName(): string {
  return `installglass-${randomBytes(6).toString("hex")}`;
}

function hostIdentity(): string {
  const uid = process.getuid?.();
  const gid = process.getgid?.();
  return uid === undefined || gid === undefined ? "10001:10001" : `${uid}:${gid}`;
}

async function delay(ms: number): Promise<void> {
  await new Promise((resolveDelay) => setTimeout(resolveDelay, ms));
}

export class DockerClient {
  public constructor(private readonly command = "docker") {}

  public async doctor(): Promise<{ version: string }> {
    let result: CommandResult;
    try {
      result = await runCommand(this.command, ["version", "--format", "{{.Server.Version}}"], { timeoutMs: 15_000 });
    } catch {
      throw new InstallGlassError(
        "DOCKER_NOT_FOUND",
        `Could not start ${this.command}. Install Docker Engine or Docker Desktop and ensure its command is available.`,
      );
    }
    if (result.exitCode !== 0 || !result.stdout.trim()) {
      throw new InstallGlassError(
        "DOCKER_UNAVAILABLE",
        `Docker is installed but its daemon is unavailable: ${redact(result.stderr.trim() || "no diagnostic returned")}`,
      );
    }
    return { version: result.stdout.trim() };
  }

  public async ensureImage(rebuild: boolean): Promise<string> {
    await access(resolve(sandboxContext, "Dockerfile"));
    const existing = await runCommand(this.command, ["image", "inspect", SANDBOX_IMAGE, "--format", "{{.Id}}"], {
      timeoutMs: 15_000,
    });
    if (existing.exitCode === 0 && existing.stdout.trim() && !rebuild) return existing.stdout.trim();

    const built = await runCommand(
      this.command,
      ["build", "--pull", "--tag", SANDBOX_IMAGE, sandboxContext],
      { timeoutMs: 10 * 60_000 },
    );
    if (built.exitCode !== 0) {
      throw new InstallGlassError("IMAGE_BUILD_FAILED", `The sandbox image failed to build: ${redact(built.stderr)}`);
    }
    const inspected = await runCommand(this.command, ["image", "inspect", SANDBOX_IMAGE, "--format", "{{.Id}}"], {
      timeoutMs: 15_000,
    });
    if (inspected.exitCode !== 0 || !inspected.stdout.trim()) {
      throw new InstallGlassError("IMAGE_INSPECT_FAILED", "Docker built the sandbox image but did not return its image ID.");
    }
    return inspected.stdout.trim();
  }

  private async createNetwork(name: string, internal: boolean): Promise<void> {
    const args = ["network", "create", "--driver", "bridge"];
    if (internal) args.push("--internal");
    args.push(name);
    const result = await runCommand(this.command, args, { timeoutMs: 30_000 });
    if (result.exitCode !== 0) {
      throw new InstallGlassError("NETWORK_CREATE_FAILED", `Docker could not create an isolated network: ${redact(result.stderr)}`);
    }
  }

  private async waitForProxy(container: string): Promise<void> {
    const probe = [
      "exec",
      container,
      "node",
      "-e",
      "const n=require('node:net');const s=n.connect(8080,'127.0.0.1',()=>{s.end();process.exit(0)});s.on('error',()=>process.exit(1));setTimeout(()=>process.exit(1),500)",
    ];
    for (let attempt = 0; attempt < 30; attempt += 1) {
      const result = await runCommand(this.command, probe, { timeoutMs: 2_000 });
      if (result.exitCode === 0) return;
      await delay(200);
    }
    throw new InstallGlassError("PROXY_START_FAILED", "The isolated network proxy did not become ready.");
  }

  public async runAudit(
    options: AuditOptions,
    paths: DockerSessionPaths,
    containerSpec: string,
  ): Promise<DockerRunResult> {
    const { version } = await this.doctor();
    const imageId = await this.ensureImage(options.rebuildImage);
    const base = sessionName();
    const internalNetwork = `${base}-internal`;
    const egressNetwork = `${base}-egress`;
    const proxyContainer = `${base}-proxy`;
    const analysisContainer = `${base}-analysis`;
    const identity = hostIdentity();
    const cleanupErrors: string[] = [];

    try {
      await this.createNetwork(internalNetwork, true);
      await this.createNetwork(egressNetwork, false);

      const proxy = await runCommand(
        this.command,
        [
          "run",
          "--detach",
          "--name",
          proxyContainer,
          "--network",
          egressNetwork,
          "--read-only",
          "--cap-drop",
          "ALL",
          "--security-opt",
          "no-new-privileges",
          "--pids-limit",
          "128",
          "--memory",
          "256m",
          "--cpus",
          "0.5",
          "--user",
          identity,
          "--tmpfs",
          "/tmp:rw,noexec,nosuid,nodev,size=32m,mode=1777",
          "--mount",
          `type=bind,source=${paths.proxyOutputDirectory},target=/proxy-output`,
          SANDBOX_IMAGE,
          "node",
          "/opt/installglass/proxy.mjs",
        ],
        { timeoutMs: 30_000 },
      );
      if (proxy.exitCode !== 0) {
        throw new InstallGlassError("PROXY_START_FAILED", `Docker could not start the proxy: ${redact(proxy.stderr)}`);
      }
      const connected = await runCommand(
        this.command,
        ["network", "connect", "--alias", "proxy", internalNetwork, proxyContainer],
        { timeoutMs: 30_000 },
      );
      if (connected.exitCode !== 0) {
        throw new InstallGlassError("PROXY_NETWORK_FAILED", `Docker could not attach the proxy: ${redact(connected.stderr)}`);
      }
      await this.waitForProxy(proxyContainer);

      const proxyUrl = "http://proxy:8080";
      const runArgs = [
        "run",
        "--rm",
        "--name",
        analysisContainer,
        "--network",
        internalNetwork,
        "--read-only",
        "--cap-drop",
        "ALL",
        "--cap-add",
        "SYS_PTRACE",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        String(options.pidsLimit),
        "--memory",
        options.memory,
        "--cpus",
        String(options.cpus),
        "--user",
        identity,
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=128m,mode=1777",
        "--mount",
        `type=bind,source=${paths.analysisDirectory},target=/analysis`,
        "--mount",
        `type=bind,source=${paths.outputDirectory},target=/output`,
        "--env",
        "HOME=/analysis/home",
        "--env",
        "NPM_CONFIG_CACHE=/analysis/npm-cache",
        "--env",
        "NPM_CONFIG_USERCONFIG=/analysis/home/.npmrc",
        "--env",
        "INSTALLGLASS_HOOK_LOG=/output/hook.jsonl",
        "--env",
        "NODE_OPTIONS=--require=/opt/installglass/env-hook.cjs",
        "--env",
        "NODE_USE_ENV_PROXY=1",
        "--env",
        `HTTP_PROXY=${proxyUrl}`,
        "--env",
        `HTTPS_PROXY=${proxyUrl}`,
        "--env",
        `http_proxy=${proxyUrl}`,
        "--env",
        `https_proxy=${proxyUrl}`,
        "--env",
        "NO_PROXY=localhost,127.0.0.1,proxy",
        SANDBOX_IMAGE,
        "strace",
        "-ff",
        "-qq",
        "-s",
        "512",
        "-yy",
        "-e",
        "trace=%file,%process,%network",
        "-o",
        "/output/trace",
        "node",
        "/opt/installglass/sandbox-runner.mjs",
        containerSpec,
      ];
      const command = await runCommand(this.command, runArgs, { timeoutMs: options.timeoutMs });
      return { command, dockerVersion: version, imageId, image: SANDBOX_IMAGE };
    } finally {
      for (const args of [
        ["rm", "--force", analysisContainer],
        ["rm", "--force", proxyContainer],
        ["network", "rm", internalNetwork],
        ["network", "rm", egressNetwork],
      ]) {
        const result = await runCommand(this.command, args, { timeoutMs: 20_000 }).catch(() => null);
        if (result && result.exitCode !== 0 && !result.stderr.includes("No such")) cleanupErrors.push(result.stderr);
      }
      void cleanupErrors;
    }
  }
}
