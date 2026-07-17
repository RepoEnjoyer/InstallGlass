import { increment, stableSort } from "./common.js";
import type { NetworkEvent, ProxyRecord } from "../types.js";

export function analyzeProxyRecords(records: ProxyRecord[]): NetworkEvent[] {
  const events = new Map<string, NetworkEvent>();
  for (const record of records) {
    if (!record.hostname || !Number.isInteger(record.port)) continue;
    const hostname = record.hostname.toLowerCase().replace(/\.$/u, "").slice(0, 253);
    const reason = record.reason?.slice(0, 160);
    const key = [hostname, String(record.port), record.method, String(record.blocked), reason ?? ""].join("\u0000");
    increment(
      events,
      key,
      () => ({ hostname, port: record.port, method: record.method, blocked: record.blocked, ...(reason ? { reason } : {}), count: 1 }),
      (value) => {
        value.count += 1;
      },
    );
  }
  return stableSort([...events.values()], (item) => `${item.hostname}:${item.port}:${item.method}:${item.blocked}`);
}
