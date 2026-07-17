"use strict";

const fs = require("node:fs");
const childProcess = require("node:child_process");

const originalEnv = process.env;
const logPath = originalEnv.INSTALLGLASS_HOOK_LOG;
let logFd = null;

function redact(value) {
  if (typeof value !== "string") return String(value);
  return value
    .replace(/\b(?:gh[pousr]|github_pat)_[A-Za-z0-9_]{12,}\b/giu, "[REDACTED_TOKEN]")
    .replace(/\b(npm|token|secret|password|passwd|api[_-]?key|authorization)=[^\s&]+/giu, "$1=[REDACTED]")
    .replace(/\bBearer\s+[A-Za-z0-9._~+\/-]+=*/giu, "Bearer [REDACTED]")
    .replace(/(https?:\/\/)[^\s/@:]+:[^\s/@]+@/giu, "$1[REDACTED]@")
    .replace(/INSTALLGLASS_DECOY[A-Z0-9_\-]*/gu, "[REDACTED_DECOY]")
    .replace(/^[A-Za-z0-9+/_=-]{96,}$/u, "[REDACTED_HIGH_ENTROPY_ARGUMENT]")
    .slice(0, 500);
}

function context() {
  return {
    pid: process.pid,
    packageName: originalEnv.npm_package_name || null,
    packageVersion: originalEnv.npm_package_version || null,
    lifecycle: originalEnv.npm_lifecycle_event || null,
    cwd: (() => {
      try { return process.cwd(); } catch { return null; }
    })(),
  };
}

function record(entry) {
  if (!logPath) return;
  try {
    if (logFd === null) logFd = fs.openSync(logPath, "a", 0o600);
    fs.writeSync(logFd, `${JSON.stringify({ ...entry, ...context() })}\n`);
  } catch {
    // Evidence collection must never change package behavior.
  }
}

record({ type: "process_start", executable: process.execPath, arguments: process.argv.slice(1).map(redact) });

try {
  let enumeratingEnv = false;
  const proxiedEnv = new Proxy(originalEnv, {
    get(target, property, receiver) {
      if (!enumeratingEnv && typeof property === "string" && property !== "INSTALLGLASS_HOOK_LOG") {
        record({ type: "env_access", operation: "get", variable: property });
      }
      return Reflect.get(target, property, receiver);
    },
    has(target, property) {
      if (typeof property === "string" && property !== "INSTALLGLASS_HOOK_LOG") {
        record({ type: "env_access", operation: "has", variable: property });
      }
      return Reflect.has(target, property);
    },
    ownKeys(target) {
      record({ type: "env_access", operation: "list", variable: "*" });
      enumeratingEnv = true;
      queueMicrotask(() => { enumeratingEnv = false; });
      return Reflect.ownKeys(target);
    },
  });
  Object.defineProperty(process, "env", { configurable: true, enumerable: true, value: proxiedEnv });
} catch {
  record({ type: "hook_error", operation: "env_proxy" });
}

for (const method of ["spawn", "execFile", "fork"]) {
  const original = childProcess[method];
  if (typeof original !== "function") continue;
  childProcess[method] = function instrumented(command, args, options) {
    const result = Reflect.apply(original, this, arguments);
    const values = Array.isArray(args) ? args : [];
    record({
      type: "child_process",
      executable: redact(command),
      arguments: values.slice(0, 40).map(redact),
      childPid: result && typeof result.pid === "number" ? result.pid : null,
    });
    return result;
  };
}

for (const method of ["spawnSync", "execFileSync"]) {
  const original = childProcess[method];
  if (typeof original !== "function") continue;
  childProcess[method] = function instrumentedSync(command, args) {
    const values = Array.isArray(args) ? args : [];
    record({ type: "child_process", executable: redact(command), arguments: values.slice(0, 40).map(redact), childPid: null });
    return Reflect.apply(original, this, arguments);
  };
}
