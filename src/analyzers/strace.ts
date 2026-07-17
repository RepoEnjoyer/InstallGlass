import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { increment, normalizeSandboxPath, stableSort } from "./common.js";
import type { FileEvent, NetworkEvent } from "../types.js";

const credentialPath = /\/(?:\.ssh|\.aws|\.azure|\.config\/gcloud|\.kube|\.docker)(?:\/|$)|\/\.git-credentials$/iu;
const ignoredPaths = ["<tool>", "<output>", "<npm-cache>", "/usr/", "/lib/", "/etc/ld.so", "/proc/", "/dev/", "<tmp>"];
const seededPaths = new Set([
  "<home>/.npmrc",
  "<home>/.git-credentials",
  "<home>/.ssh/id_installglass_decoy",
  "<home>/.aws/credentials",
  "<project>/package.json",
]);

function decodeCString(value: string): string {
  return value.replace(/\\(x[0-9a-fA-F]{2}|[0-7]{1,3}|\\|"|n|r|t)/gu, (_match, escaped: string) => {
    if (escaped.startsWith("x")) return String.fromCharCode(Number.parseInt(escaped.slice(1), 16));
    if (/^[0-7]+$/u.test(escaped)) return String.fromCharCode(Number.parseInt(escaped, 8));
    return ({ "\\": "\\", '"': '"', n: "\n", r: "\r", t: "\t" } as Record<string, string>)[escaped] ?? "";
  });
}

function quotedValues(line: string): string[] {
  const values: string[] = [];
  for (const match of line.matchAll(/"((?:\\.|[^"\\])*)"/gu)) values.push(decodeCString(match[1] ?? ""));
  return values;
}

function operationFor(line: string): FileEvent["operation"] | null {
  if (/\b(?:unlink|unlinkat|rmdir)\(/u.test(line)) return "delete";
  if (/\b(?:rename|renameat|renameat2)\(/u.test(line)) return "rename";
  if (/\b(?:mkdir|mkdirat)\(/u.test(line)) return "mkdir";
  if (/\b(?:chmod|fchmodat|chown|lchown|utime|utimes|utimensat)\(/u.test(line)) return "metadata";
  if (/\b(?:creat|mknod|symlink|symlinkat|link|linkat)\(/u.test(line)) return "create";
  if (/\b(?:open|openat|openat2)\(/u.test(line)) {
    if (/O_(?:WRONLY|RDWR|CREAT|TRUNC|APPEND)/u.test(line)) return line.includes("O_CREAT") ? "create" : "write";
    return "read";
  }
  if (/\b(?:stat|lstat|newfstatat|access|readlink|readlinkat)\(/u.test(line)) return "read";
  return null;
}

function relevantPath(path: string): boolean {
  if (!path.startsWith("/")) return false;
  const normalized = normalizeSandboxPath(path);
  if (seededPaths.has(normalized)) return false;
  return !ignoredPaths.some((prefix) => normalized.startsWith(prefix));
}

export async function analyzeStraceFiles(paths: string[]): Promise<{
  files: FileEvent[];
  directNetwork: NetworkEvent[];
  credentialPathReads: string[];
}> {
  const files = new Map<string, FileEvent>();
  const directNetwork = new Map<string, NetworkEvent>();
  const credentialReads = new Set<string>();

  for (const path of paths) {
    const body = await readFile(path, "utf8");
    let cwd = "/";
    for (const line of body.split("\n")) {
      if (!line) continue;
      const failed = line.includes(" = -1 ");
      const changedDirectory = /^chdir\("((?:\\.|[^"\\])*)"\)\s+=\s+0$/u.exec(line)?.[1];
      if (changedDirectory) {
        const decoded = decodeCString(changedDirectory);
        cwd = decoded.startsWith("/") ? decoded : resolve(cwd, decoded);
      }
      const operation = failed ? null : operationFor(line);
      if (operation) {
        const values = quotedValues(line)
          .map((value) => (value.startsWith("/") ? value : resolve(cwd, value)))
          .filter(relevantPath);
        const pathsForEvent = operation === "rename" ? values.slice(0, 2) : values.slice(0, 1);
        for (const rawPath of pathsForEvent) {
          const normalized = normalizeSandboxPath(rawPath).slice(0, 512);
          const key = `${operation}\u0000${normalized}`;
          increment(
            files,
            key,
            () => ({ operation, path: normalized, count: 1 }),
            (value) => {
              value.count += 1;
            },
          );
          if (operation === "read" && credentialPath.test(rawPath)) credentialReads.add(normalized);
        }
      }

      if (line.includes("connect(") && !line.includes("htons(8080)")) {
        const ip = /inet_addr\("([0-9.]+)"\)/u.exec(line)?.[1] ?? /inet_pton\(AF_INET6, "([0-9a-f:]+)"/iu.exec(line)?.[1];
        const portText = /htons\((\d+)\)/u.exec(line)?.[1];
        if (ip && portText && ip !== "127.0.0.1" && ip !== "::1") {
          const port = Number(portText);
          const key = `${ip}\u0000${port}`;
          increment(
            directNetwork,
            key,
            () => ({
              hostname: ip,
              port,
              method: "DIRECT",
              blocked: failed,
              ...(failed ? { reason: "internal network prevented direct connection" } : {}),
              count: 1,
            }),
            (value) => {
              value.count += 1;
            },
          );
        }
      }
    }
  }

  return {
    files: stableSort([...files.values()], (item) => `${item.path}:${item.operation}`).slice(0, 5_000),
    directNetwork: stableSort([...directNetwork.values()], (item) => `${item.hostname}:${item.port}`),
    credentialPathReads: [...credentialReads].sort(),
  };
}
