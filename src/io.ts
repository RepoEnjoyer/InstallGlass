import { readFile, readdir } from "node:fs/promises";
import { basename, join } from "node:path";

export async function readJson<T>(path: string, validate?: (value: unknown) => value is T): Promise<T | null> {
  try {
    const value: unknown = JSON.parse(await readFile(path, "utf8"));
    if (validate && !validate(value)) return null;
    return value as T;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw error;
  }
}

export async function readJsonLines<T>(
  path: string,
  validate?: (value: unknown) => value is T,
): Promise<{ records: T[]; rejected: number }> {
  let body: string;
  try {
    body = await readFile(path, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return { records: [], rejected: 0 };
    throw error;
  }

  const records: T[] = [];
  let rejected = 0;
  for (const line of body.split("\n")) {
    if (!line.trim()) continue;
    try {
      const value: unknown = JSON.parse(line);
      if (validate && !validate(value)) rejected += 1;
      else records.push(value as T);
    } catch {
      rejected += 1;
    }
  }
  return { records, rejected };
}

export async function findFiles(directory: string, prefix: string): Promise<string[]> {
  let names: string[];
  try {
    names = await readdir(directory);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw error;
  }
  return names
    .filter((name) => basename(name).startsWith(prefix))
    .sort((left, right) => left.localeCompare(right))
    .map((name) => join(directory, name));
}
