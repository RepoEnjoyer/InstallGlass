import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, describe, expect, it } from "vitest";
import { analyzeStraceFiles } from "../src/analyzers/strace.js";

const temporary: string[] = [];
afterEach(async () => {
  await Promise.all(temporary.splice(0).map(async (path) => await rm(path, { recursive: true, force: true })));
});

describe("strace analyzer", () => {
  it("normalizes paths, detects credential reads, and excludes proxy connections", async () => {
    const root = await mkdtemp(join(tmpdir(), "installglass-trace-"));
    temporary.push(root);
    const trace = join(root, "trace.42");
    await writeFile(
      trace,
      [
        'openat(AT_FDCWD, "/analysis/project/node_modules/pkg/new.txt", O_WRONLY|O_CREAT, 0666) = 3',
        'openat(AT_FDCWD, "/analysis/home/.ssh/id_rsa", O_RDONLY) = 3',
        'connect(4, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("172.18.0.2")}, 16) = 0',
        'connect(4, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("203.0.113.8")}, 16) = -1 ECONNREFUSED',
      ].join("\n"),
    );

    const result = await analyzeStraceFiles([trace]);

    expect(result.files).toContainEqual({ operation: "create", path: "<project>/node_modules/pkg/new.txt", count: 1 });
    expect(result.credentialPathReads).toEqual(["<home>/.ssh/id_rsa"]);
    expect(result.directNetwork).toEqual([
      {
        hostname: "203.0.113.8",
        port: 4444,
        method: "DIRECT",
        blocked: true,
        reason: "internal network prevented direct connection",
        count: 1,
      },
    ]);
  });
});
