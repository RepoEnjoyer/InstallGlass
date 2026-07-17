import { describe, expect, it } from "vitest";
import { buildFindings, summarize } from "../src/analyzers/findings.js";
import type { AuditEvidence } from "../src/types.js";

function emptyEvidence(): AuditEvidence {
  return {
    files: [],
    manifest: [],
    lifecycleScripts: [],
    processes: [],
    network: [],
    environment: [],
    nativeArtifacts: [],
    staticSignals: [],
    credentialPathReads: [],
  };
}

describe("finding model", () => {
  it("makes credential-path runtime reads critical", () => {
    const evidence = emptyEvidence();
    evidence.credentialPathReads.push("<home>/.aws/credentials");
    const findings = buildFindings(evidence, true, []);
    const summary = summarize(findings, true);
    expect(findings[0]?.id).toBe("credentials.path-read");
    expect(findings[0]?.severity).toBe("critical");
    expect(summary.riskScore).toBe(45);
    expect(summary.verdict).toBe("review-recommended");
  });

  it("does not confuse no observed evidence with a certification", () => {
    const findings = buildFindings(emptyEvidence(), true, []);
    expect(summarize(findings, true)).toMatchObject({ riskScore: 0, verdict: "low-observed-risk" });
  });
});
