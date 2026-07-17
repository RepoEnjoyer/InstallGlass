import { readFile } from "node:fs/promises";
import { increment, normalizeSandboxPath, stableSort } from "./common.js";
import type { EnvironmentAccess, HookRecord, LifecycleEvent, ProcessEvent } from "../types.js";

const sensitiveVariable = /(?:TOKEN|SECRET|PASSWORD|PASSWD|AUTH|COOKIE|CREDENTIAL|PRIVATE|API_KEY|ACCESS_KEY|AWS_|AZURE_|GITHUB_|NPM_TOKEN)/iu;
const toolVariables = new Set(["INSTALLGLASS_HOOK_LOG", "NODE_OPTIONS"]);

function cleanArguments(argumentsList: string[] | undefined): string[] {
  return (argumentsList ?? []).slice(0, 24).map((argument) => normalizeSandboxPath(argument).slice(0, 256));
}

export function analyzeHookRecords(records: HookRecord[]): {
  environment: EnvironmentAccess[];
  processes: ProcessEvent[];
} {
  const environment = new Map<string, EnvironmentAccess>();
  const processes = new Map<string, ProcessEvent>();

  for (const record of records) {
    if (record.type === "env_access" && record.variable && record.operation) {
      if (toolVariables.has(record.variable)) continue;
      if (!record.lifecycle && !sensitiveVariable.test(record.variable)) continue;
      const variable = record.variable;
      const operation = record.operation;
      const key = [variable, record.packageName ?? "", record.lifecycle ?? ""].join("\u0000");
      increment(
        environment,
        key,
        () => ({
          variable,
          operations: [operation],
          packageName: record.packageName ?? null,
          lifecycle: record.lifecycle ?? null,
          count: 1,
        }),
        (value) => {
          value.count += 1;
          if (!value.operations.includes(operation)) {
            value.operations.push(operation);
            value.operations.sort();
          }
        },
      );
    }

    if (record.type === "child_process" && record.executable) {
      const args = cleanArguments(record.arguments);
      const executable = normalizeSandboxPath(record.executable);
      const key = [executable, JSON.stringify(args), record.packageName ?? "", record.lifecycle ?? ""].join("\u0000");
      increment(
        processes,
        key,
        () => ({
          executable,
          arguments: args,
          packageName: record.packageName ?? null,
          lifecycle: record.lifecycle ?? null,
          count: 1,
        }),
        (value) => {
          value.count += 1;
        },
      );
    }
  }

  return {
    environment: stableSort([...environment.values()], (item) => `${item.variable}:${item.packageName}:${item.lifecycle}`),
    processes: stableSort([...processes.values()], (item) => `${item.executable}:${item.arguments.join(" ")}`),
  };
}

export async function parseLifecycleLog(path: string): Promise<LifecycleEvent[]> {
  let body: string;
  try {
    body = await readFile(path, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw error;
  }

  const events = new Map<string, LifecycleEvent>();
  for (const line of body.split("\n")) {
    const match = /^npm (?:info|warn) run (.+)@([^ ]+) (preinstall|install|postinstall|prepublish|preprepare|prepare|postprepare) (.+)$/u.exec(line.trim());
    if (!match) continue;
    const [, packageName, packageVersion, lifecycle, command] = match;
    if (!packageName || !packageVersion || !lifecycle || !command) continue;
    const key = `${packageName}\u0000${packageVersion}\u0000${lifecycle}\u0000${command}`;
    increment(
      events,
      key,
      () => ({ packageName, packageVersion, lifecycle, command: command.slice(0, 512), cwd: null, count: 1 }),
      (value) => {
        value.count += 1;
      },
    );
  }
  return stableSort([...events.values()], (item) => `${item.packageName}:${item.lifecycle}:${item.command}`);
}
