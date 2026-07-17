import { lstat, readFile, readdir } from "node:fs/promises";
import { relative } from "node:path";

const root = new URL("../", import.meta.url);
const ignoredDirectories = new Set([".git", "coverage", "dist", "node_modules"]);
const ignoredFiles = new Set(["scripts/privacy-check.mjs"]);
const maximumBytes = 2 * 1024 * 1024;
const findings = [];

const rules = [
  ["GitHub token", /\b(?:gh[pousr]|github_pat)_[A-Za-z0-9_]{12,}\b/gu],
  ["AWS access key", /\bAKIA[0-9A-Z]{16}\b/gu],
  ["private-key block", /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/gu],
  ["credential URL", /https?:\/\/[^\s/@:]+:[^\s/@]+@/gu],
  ["host workspace path", /(?:\/workspace\/|\/Users\/|(?<!\/analysis)\/home\/[A-Za-z0-9][A-Za-z0-9._-]*\/|[A-Za-z]:\\Users\\)/gu],
  ["email address", /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/giu],
];

async function visit(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.isDirectory() && ignoredDirectories.has(entry.name)) continue;
    const url = new URL(entry.isDirectory() ? `${entry.name}/` : entry.name, directory);
    if (entry.isDirectory()) {
      await visit(url);
      continue;
    }
    if (!entry.isFile()) continue;
    const path = relative(root.pathname, url.pathname).split("\\").join("/");
    if (ignoredFiles.has(path)) continue;
    const stat = await lstat(url);
    if (stat.size > maximumBytes) continue;
    const content = await readFile(url, "utf8").catch(() => null);
    if (content === null || content.includes("\u0000")) continue;
    for (const [label, pattern] of rules) {
      pattern.lastIndex = 0;
      for (const match of content.matchAll(pattern)) {
        if (label === "email address" && match[0].toLowerCase().endsWith("@example.invalid")) continue;
        const line = content.slice(0, match.index ?? 0).split("\n").length;
        findings.push(`${path}:${line} ${label}`);
      }
    }
  }
}

await visit(root);
if (findings.length > 0) {
  process.stderr.write(`Privacy check failed:\n${findings.map((item) => `- ${item}`).join("\n")}\n`);
  process.exitCode = 1;
} else {
  process.stdout.write("Privacy check passed: no obvious secrets, personal email addresses, or host paths found.\n");
}
