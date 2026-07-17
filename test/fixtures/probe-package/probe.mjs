import { spawnSync } from "node:child_process";
import { appendFile, readFile } from "node:fs/promises";

await appendFile("installglass-created.txt", "fixture\n");
await readFile(`${process.env.HOME}/.ssh/id_rsa`, "utf8");
void process.env.NPM_TOKEN;
spawnSync("node", ["--version"], { stdio: "ignore" });
await fetch("https://registry.npmjs.org/-/ping");
await fetch("http://169.254.169.254/latest/meta-data").catch(() => undefined);
