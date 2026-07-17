import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, describe, expect, it } from "vitest";
import { preparePackageSpec, validatePackageSpec } from "../src/spec.js";

const temporary: string[] = [];
afterEach(async () => {
  await Promise.all(temporary.splice(0).map(async (path) => await rm(path, { recursive: true, force: true })));
});

describe("package specification handling", () => {
  it("accepts normal registry package specifications", () => {
    expect(validatePackageSpec("@scope/package@1.2.3")).toBe("@scope/package@1.2.3");
  });

  it.each(["", "  ", "--registry=unsafe", "name\nother"])("rejects unsafe specification %j", (value) => {
    expect(() => validatePackageSpec(value)).toThrow();
  });

  it("copies local input under a privacy-safe fixed name", async () => {
    const root = await mkdtemp(join(tmpdir(), "installglass-spec-"));
    temporary.push(root);
    const source = join(root, "private-looking-directory-name");
    const input = join(root, "input");
    await mkdir(source);
    await writeFile(join(source, "package.json"), '{"name":"fixture","version":"1.0.0"}');

    const result = await preparePackageSpec(source, input);

    expect(result.containerSpec).toBe("file:/analysis/input/package-source");
    expect(result.displaySpec).toBe("file:<local-package>");
    expect(result.containerSpec).not.toContain("private-looking-directory-name");
  });
});
