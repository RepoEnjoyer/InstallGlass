const replacements: [RegExp, string][] = [
  [/\b(?:gh[pousr]|github_pat)_[A-Za-z0-9_]{12,}\b/giu, "[REDACTED_GITHUB_TOKEN]"],
  [/\bAKIA[0-9A-Z]{16}\b/gu, "[REDACTED_AWS_KEY]"],
  [/\b(npm|token|secret|password|passwd|api[_-]?key|authorization)=[^\s&]+/giu, "$1=[REDACTED]"],
  [/\bBearer\s+[A-Za-z0-9._~+/-]+=*/giu, "Bearer [REDACTED]"],
  [/(https?:\/\/)[^\s/@:]+:[^\s/@]+@/giu, "$1[REDACTED]@"],
  [/INSTALLGLASS_DECOY[A-Z0-9_-]*/gu, "[REDACTED_DECOY]"],
];

export function redact(value: string, maxLength = 500): string {
  let result = value;
  for (const [pattern, replacement] of replacements) {
    result = result.replace(pattern, replacement);
  }
  result = Array.from(result)
    .map((character) => {
      const codePoint = character.codePointAt(0) ?? 0;
      return (codePoint < 32 && ![9, 10, 13].includes(codePoint)) || codePoint === 127 ? "?" : character;
    })
    .join("");
  return result.length > maxLength ? `${result.slice(0, maxLength)}…` : result;
}

export function redactArguments(values: readonly string[]): string[] {
  return values.slice(0, 40).map((value) => {
    const redacted = redact(value, 240);
    if (/^[A-Za-z0-9+/_=-]{96,}$/u.test(redacted)) return "[REDACTED_HIGH_ENTROPY_ARGUMENT]";
    return redacted;
  });
}
