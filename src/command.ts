import { spawn } from "node:child_process";
import type { CommandResult } from "./types.js";
import { MAX_CAPTURE_BYTES } from "./constants.js";

export interface RunCommandOptions {
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  timeoutMs?: number;
  onSpawn?: (pid: number | undefined) => void;
}

function appendBounded(current: string, chunk: Buffer): string {
  if (current.length >= MAX_CAPTURE_BYTES) return current;
  return (current + chunk.toString("utf8")).slice(0, MAX_CAPTURE_BYTES);
}

export async function runCommand(
  command: string,
  args: readonly string[],
  options: RunCommandOptions = {},
): Promise<CommandResult> {
  return await new Promise((resolve, reject) => {
    const child = spawn(command, [...args], {
      cwd: options.cwd,
      env: options.env,
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });
    options.onSpawn?.(child.pid);
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    let settled = false;
    const timeout = options.timeoutMs
      ? setTimeout(() => {
          timedOut = true;
          child.kill("SIGKILL");
        }, options.timeoutMs)
      : undefined;
    timeout?.unref();

    child.stdout.on("data", (chunk: Buffer) => {
      stdout = appendBounded(stdout, chunk);
    });
    child.stderr.on("data", (chunk: Buffer) => {
      stderr = appendBounded(stderr, chunk);
    });
    child.once("error", (error) => {
      if (settled) return;
      settled = true;
      if (timeout) clearTimeout(timeout);
      reject(error);
    });
    child.once("close", (code) => {
      if (settled) return;
      settled = true;
      if (timeout) clearTimeout(timeout);
      resolve({ exitCode: code ?? 1, stdout, stderr, timedOut });
    });
  });
}
