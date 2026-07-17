import { describe, expect, it } from "vitest";
import { analyzeHookRecords } from "../src/analyzers/hook.js";
import { analyzeProxyRecords } from "../src/analyzers/proxy.js";

describe("runtime evidence analyzers", () => {
  it("records sensitive variable names but never values", () => {
    const result = analyzeHookRecords([
      { type: "env_access", operation: "get", variable: "NPM_TOKEN", packageName: "fixture", lifecycle: "postinstall" },
      { type: "env_access", operation: "get", variable: "PATH", packageName: null, lifecycle: null },
    ]);
    expect(result.environment).toEqual([
      {
        variable: "NPM_TOKEN",
        operations: ["get"],
        packageName: "fixture",
        lifecycle: "postinstall",
        count: 1,
      },
    ]);
  });

  it("aggregates proxy destinations without URLs or headers", () => {
    const result = analyzeProxyRecords([
      { hostname: "REGISTRY.NPMJS.ORG", port: 443, method: "CONNECT", blocked: false },
      { hostname: "registry.npmjs.org", port: 443, method: "CONNECT", blocked: false },
    ]);
    expect(result).toEqual([
      { hostname: "registry.npmjs.org", port: 443, method: "CONNECT", blocked: false, count: 2 },
    ]);
  });
});
