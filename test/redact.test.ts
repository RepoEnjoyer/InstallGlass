import { describe, expect, it } from "vitest";
import { redact, redactArguments } from "../src/redact.js";

describe("privacy redaction", () => {
  it("removes token-like values and URL credentials", () => {
    const githubLike = `ghp_${"A".repeat(30)}`;
    const credentialUrl = ["https://person", "password@example.invalid"].join(":");
    const result = redact(`token=topvalue ${githubLike} ${credentialUrl}`);
    expect(result).not.toContain("topvalue");
    expect(result).not.toContain(githubLike);
    expect(result).not.toContain("person:password");
  });

  it("does not retain decoys or high-entropy child arguments", () => {
    expect(redactArguments(["INSTALLGLASS_DECOY_PRIVATE_KEY", "A".repeat(100)])).toEqual([
      "[REDACTED_DECOY]",
      "[REDACTED_HIGH_ENTROPY_ARGUMENT]",
    ]);
  });
});
