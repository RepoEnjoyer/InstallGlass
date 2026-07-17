import { readFile } from "node:fs/promises";

const report = JSON.parse(await readFile(process.argv[2] ?? "integration-report.json", "utf8"));
const checks = [
  ["install completed", report.summary?.installCompleted === true],
  ["lifecycle script", report.evidence?.lifecycleScripts?.some((item) => item.packageName === "installglass-integration-probe")],
  ["sensitive environment name", report.evidence?.environment?.some((item) => item.variable === "NPM_TOKEN")],
  ["decoy credential read", report.evidence?.credentialPathReads?.includes("<home>/.ssh/id_rsa")],
  ["public npm destination", report.evidence?.network?.some((item) => item.hostname === "registry.npmjs.org" && item.blocked === false)],
  ["private destination block", report.evidence?.network?.some((item) => item.hostname === "169.254.169.254" && item.blocked === true)],
  ["created fixture file", report.evidence?.files?.some((item) => item.path.endsWith("/installglass-created.txt") && ["create", "write"].includes(item.operation))],
  ["child process", report.evidence?.processes?.some((item) => item.executable === "node")],
];

const failed = checks.filter(([, passed]) => !passed).map(([label]) => label);
if (failed.length > 0) {
  process.stderr.write(`Integration evidence missing: ${failed.join(", ")}\n`);
  process.exitCode = 1;
} else {
  process.stdout.write("Integration report contains every expected evidence class.\n");
}
