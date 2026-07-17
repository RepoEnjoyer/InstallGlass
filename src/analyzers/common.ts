export function increment<T>(map: Map<string, T>, key: string, create: () => T, update: (value: T) => void): void {
  const existing = map.get(key);
  if (existing) {
    update(existing);
    return;
  }
  map.set(key, create());
}

export function normalizeSandboxPath(path: string): string {
  const roots: [string, string][] = [
    ["/analysis/project", "<project>"],
    ["/analysis/home", "<home>"],
    ["/analysis/input", "<input>"],
    ["/analysis/npm-cache", "<npm-cache>"],
    ["/opt/installglass", "<tool>"],
    ["/output", "<output>"],
    ["/tmp", "<tmp>"],
  ];
  for (const [root, replacement] of roots) {
    if (path === root || path.startsWith(`${root}/`)) return `${replacement}${path.slice(root.length)}`;
  }
  return path;
}

export function stableSort<T>(items: T[], key: (item: T) => string): T[] {
  return items.sort((left, right) => key(left).localeCompare(key(right)));
}
