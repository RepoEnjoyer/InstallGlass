import { lstat, mkdir, cp, copyFile } from "node:fs/promises";
import { extname, join, resolve } from "node:path";
import { InstallGlassError } from "./errors.js";

const PACKAGE_SPEC_MAX_LENGTH = 512;

export interface PreparedSpec {
  containerSpec: string;
  displaySpec: string;
  localSource: string | null;
}

export function validatePackageSpec(spec: string): string {
  const trimmed = spec.trim();
  if (!trimmed) {
    throw new InstallGlassError("INVALID_SPEC", "A package name, version, tarball, or local package path is required.");
  }
  if (trimmed.length > PACKAGE_SPEC_MAX_LENGTH || /[\0\r\n]/u.test(trimmed)) {
    throw new InstallGlassError("INVALID_SPEC", "The package specification is too long or contains control characters.");
  }
  if (trimmed.startsWith("-")) {
    throw new InstallGlassError("INVALID_SPEC", "Package specifications cannot begin with an option marker.");
  }
  return trimmed;
}

function looksLikeLocalPath(spec: string): boolean {
  return spec.startsWith("file:") || spec.startsWith(".") || spec.startsWith("/") || /^[A-Za-z]:[\\/]/u.test(spec);
}

export async function preparePackageSpec(specInput: string, inputDirectory: string): Promise<PreparedSpec> {
  const spec = validatePackageSpec(specInput);
  if (!looksLikeLocalPath(spec)) {
    return { containerSpec: spec, displaySpec: spec, localSource: null };
  }

  const withoutPrefix = spec.startsWith("file:") ? spec.slice("file:".length) : spec;
  const source = resolve(withoutPrefix);
  let stat;
  try {
    stat = await lstat(source);
  } catch {
    throw new InstallGlassError("LOCAL_SOURCE_NOT_FOUND", "The local package path does not exist.");
  }
  if (stat.isSymbolicLink()) {
    throw new InstallGlassError("UNSAFE_LOCAL_SOURCE", "A local package source cannot be a symbolic link.");
  }
  await mkdir(inputDirectory, { recursive: true });
  const targetName = stat.isDirectory() ? "package-source" : `package-source${extname(source).slice(0, 16)}`;
  const target = join(inputDirectory, targetName);
  if (stat.isDirectory()) {
    await cp(source, target, { recursive: true, dereference: false, errorOnExist: true, force: false });
  } else if (stat.isFile()) {
    await copyFile(source, target);
  } else {
    throw new InstallGlassError("UNSAFE_LOCAL_SOURCE", "The local package source must be a directory or regular file.");
  }
  return { containerSpec: `file:/analysis/input/${targetName}`, displaySpec: "file:<local-package>", localSource: source };
}
