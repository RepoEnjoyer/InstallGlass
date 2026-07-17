import { createHash } from "node:crypto";
import { lstat, open, readFile, readdir } from "node:fs/promises";
import { join, relative, sep } from "node:path";

const MANIFEST_LIMIT = 20_000;
const STATIC_FILE_LIMIT = 20_000;
const STATIC_SIGNAL_LIMIT = 500;
const MAX_STATIC_BYTES = 2 * 1024 * 1024;
const MAX_HASH_BYTES = 64 * 1024 * 1024;

function portablePath(root, path) {
  return relative(root, path).split(sep).join("/");
}

async function sha256(path) {
  const bytes = await readFile(path);
  return createHash("sha256").update(bytes).digest("hex");
}

async function firstBytes(path, length = 8) {
  const handle = await open(path, "r");
  try {
    const buffer = Buffer.alloc(length);
    const { bytesRead } = await handle.read(buffer, 0, length, 0);
    return buffer.subarray(0, bytesRead);
  } finally {
    await handle.close();
  }
}

function binaryFormat(bytes, mode) {
  if (bytes.length >= 4 && bytes[0] === 0x7f && bytes.subarray(1, 4).toString("ascii") === "ELF") return "ELF";
  if (bytes.length >= 2 && bytes.subarray(0, 2).toString("ascii") === "MZ") return "PE";
  const magic = bytes.length >= 4 ? bytes.readUInt32BE(0) : 0;
  if ([0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe, 0xcafebabe].includes(magic)) return "Mach-O";
  if (bytes.length >= 4 && bytes.subarray(0, 4).equals(Buffer.from([0x00, 0x61, 0x73, 0x6d]))) return "WebAssembly";
  if ((mode & 0o111) !== 0 && bytes.subarray(0, 2).toString("ascii") === "#!") return "executable-script";
  return null;
}

export async function buildManifest(root) {
  const manifest = [];
  const nativeArtifacts = [];
  let truncated = false;

  async function visit(directory) {
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (manifest.length >= MANIFEST_LIMIT) {
        truncated = true;
        return;
      }
      const path = join(directory, entry.name);
      const stat = await lstat(path);
      const item = { path: portablePath(root, path), size: stat.size, mode: stat.mode & 0o777 };
      if (entry.isSymbolicLink()) {
        manifest.push(item);
        continue;
      }
      if (entry.isDirectory()) {
        manifest.push(item);
        await visit(path);
        continue;
      }
      if (!entry.isFile()) continue;
      if (stat.size <= MAX_HASH_BYTES) item.sha256 = await sha256(path);
      manifest.push(item);
      const format = binaryFormat(await firstBytes(path), stat.mode);
      if (format && item.sha256) nativeArtifacts.push({ path: item.path, format, size: stat.size, sha256: item.sha256 });
    }
  }

  await visit(root);
  return { manifest, nativeArtifacts, truncated };
}

const rules = [
  { id: "dynamic-eval", confidence: "medium", pattern: /\beval\s*\(|\bnew\s+Function\s*\(/gu },
  { id: "credential-path-literal", confidence: "high", pattern: /(?:\.ssh[\\/]|\.aws[\\/](?:credentials|config)|\.git-credentials|\.npmrc|application_default_credentials\.json)/giu },
  { id: "encoded-payload", confidence: "medium", pattern: /["'`](?:[A-Za-z0-9+/]{400,}={0,2})["'`]/gu },
  { id: "dense-hex-escapes", confidence: "medium", pattern: /(?:\\x[0-9a-fA-F]{2}){40,}/gu },
  { id: "shell-downloader", confidence: "medium", pattern: /\b(?:curl|wget)\b[^\n]{0,160}\bhttps?:\/\//giu },
];

export async function staticScan(root) {
  const signals = [];
  let filesScanned = 0;
  let truncated = false;

  async function visit(directory) {
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (filesScanned >= STATIC_FILE_LIMIT || signals.length >= STATIC_SIGNAL_LIMIT) {
        truncated = true;
        return;
      }
      const path = join(directory, entry.name);
      if (entry.isDirectory()) {
        await visit(path);
        continue;
      }
      if (!entry.isFile() || !/\.(?:c?js|mjs|json|node|sh)$/iu.test(entry.name)) continue;
      const stat = await lstat(path);
      if (stat.size > MAX_STATIC_BYTES) continue;
      filesScanned += 1;
      const content = await readFile(path, "utf8").catch(() => null);
      if (content === null) continue;
      for (const rule of rules) {
        rule.pattern.lastIndex = 0;
        for (const match of content.matchAll(rule.pattern)) {
          const offset = match.index ?? 0;
          const line = content.slice(0, offset).split("\n").length;
          const fingerprint = createHash("sha256").update(`${rule.id}\0${portablePath(root, path)}\0${line}`).digest("hex").slice(0, 16);
          signals.push({ rule: rule.id, path: portablePath(root, path), line, fingerprint, confidence: rule.confidence });
          if (signals.length >= STATIC_SIGNAL_LIMIT) {
            truncated = true;
            return;
          }
        }
      }
    }
  }

  await visit(root);
  return { signals, filesScanned, truncated };
}
