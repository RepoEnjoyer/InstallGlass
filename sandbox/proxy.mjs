import dns from "node:dns/promises";
import http from "node:http";
import net from "node:net";
import { appendFileSync, mkdirSync } from "node:fs";

const logPath = "/proxy-output/network.jsonl";
mkdirSync("/proxy-output", { recursive: true });

function record(entry) {
  try {
    appendFileSync(logPath, `${JSON.stringify(entry)}\n`, { encoding: "utf8", mode: 0o600 });
  } catch {
    // Logging must not turn a blocked request into an allowed request or crash the proxy.
  }
}

function isPrivateIpv4(address) {
  const parts = address.split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return true;
  const [a, b] = parts;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && (b === 0 || b === 168)) ||
    (a === 198 && (b === 18 || b === 19 || b === 51)) ||
    (a === 203 && b === 0) ||
    a >= 224
  );
}

function ipv6ToBigInt(address) {
  const normalized = address.toLowerCase().split("%")[0];
  const [headText, tailText] = normalized.split("::");
  if (normalized.split("::").length > 2) return null;
  const parseSide = (text) => {
    if (!text) return [];
    const parts = text.split(":");
    const result = [];
    for (const part of parts) {
      if (part.includes(".")) {
        if (!net.isIPv4(part)) return null;
        const bytes = part.split(".").map(Number);
        result.push((bytes[0] << 8) | bytes[1], (bytes[2] << 8) | bytes[3]);
      } else {
        if (!/^[0-9a-f]{1,4}$/u.test(part)) return null;
        result.push(Number.parseInt(part, 16));
      }
    }
    return result;
  };
  const head = parseSide(headText);
  const tail = parseSide(tailText);
  if (!head || !tail) return null;
  const omitted = 8 - head.length - tail.length;
  if ((normalized.includes("::") && omitted < 1) || (!normalized.includes("::") && omitted !== 0)) return null;
  const groups = [...head, ...Array.from({ length: omitted }, () => 0), ...tail];
  if (groups.length !== 8) return null;
  return groups.reduce((value, group) => (value << 16n) | BigInt(group), 0n);
}

function inIpv6Range(address, base, prefixLength) {
  const value = ipv6ToBigInt(address);
  const range = ipv6ToBigInt(base);
  if (value === null || range === null) return true;
  const shift = BigInt(128 - prefixLength);
  return value >> shift === range >> shift;
}

function isPrivateAddress(address) {
  const normalized = address.toLowerCase().split("%")[0];
  if (net.isIPv4(normalized)) return isPrivateIpv4(normalized);
  if (!net.isIPv6(normalized)) return true;
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/u.exec(normalized)?.[1];
  if (mapped) return isPrivateIpv4(mapped);
  return [
    ["::", 128],
    ["::1", 128],
    ["::ffff:0:0", 96],
    ["64:ff9b:1::", 48],
    ["100::", 64],
    ["2001::", 23],
    ["2001:db8::", 32],
    ["2002::", 16],
    ["fc00::", 7],
    ["fe80::", 10],
    ["ff00::", 8],
  ].some(([base, prefix]) => inIpv6Range(normalized, base, prefix));
}

function parseAuthority(authority, fallbackPort) {
  try {
    const parsed = new URL(`http://${authority}`);
    const port = parsed.port ? Number(parsed.port) : fallbackPort;
    if (!parsed.hostname || !Number.isInteger(port) || port < 1 || port > 65535) return null;
    return { hostname: parsed.hostname.replace(/^\[|\]$/gu, "").toLowerCase(), port };
  } catch {
    return null;
  }
}

async function resolvePublic(hostname) {
  if (hostname === "localhost" || hostname === "proxy" || hostname.endsWith(".local")) {
    return { allowed: false, reason: "local hostname", addresses: [] };
  }
  if (net.isIP(hostname)) {
    return isPrivateAddress(hostname)
      ? { allowed: false, reason: "private or reserved address", addresses: [] }
      : { allowed: true, addresses: [{ address: hostname, family: net.isIPv6(hostname) ? 6 : 4 }] };
  }
  try {
    const addresses = await dns.lookup(hostname, { all: true, verbatim: true });
    if (!addresses.length) return { allowed: false, reason: "hostname did not resolve", addresses: [] };
    if (addresses.some(({ address }) => isPrivateAddress(address))) {
      return { allowed: false, reason: "hostname resolved to a private or reserved address", addresses: [] };
    }
    return { allowed: true, addresses };
  } catch {
    return { allowed: false, reason: "DNS resolution failed", addresses: [] };
  }
}

const server = http.createServer(async (request, response) => {
  let url;
  try {
    url = new URL(request.url ?? "");
  } catch {
    response.writeHead(400).end("Invalid proxy request");
    return;
  }
  if (url.protocol !== "http:") {
    response.writeHead(400).end("HTTPS must use CONNECT");
    return;
  }
  const port = url.port ? Number(url.port) : 80;
  const resolution = await resolvePublic(url.hostname);
  record({ hostname: url.hostname.toLowerCase(), port, method: "HTTP", blocked: !resolution.allowed, ...(resolution.reason ? { reason: resolution.reason } : {}) });
  if (!resolution.allowed) {
    response.writeHead(403).end("Destination blocked by InstallGlass");
    return;
  }
  const address = resolution.addresses[0];
  const headers = { ...request.headers, host: url.host };
  delete headers["proxy-authorization"];
  delete headers["proxy-connection"];
  const upstream = http.request(
    {
      host: address.address,
      family: address.family,
      port,
      method: request.method,
      path: `${url.pathname}${url.search}`,
      headers,
    },
    (upstreamResponse) => {
      response.writeHead(upstreamResponse.statusCode ?? 502, upstreamResponse.headers);
      upstreamResponse.pipe(response);
    },
  );
  upstream.on("error", () => {
    if (!response.headersSent) response.writeHead(502);
    response.end("Upstream request failed");
  });
  request.pipe(upstream);
});

server.on("connect", async (request, clientSocket, head) => {
  const target = parseAuthority(request.url ?? "", 443);
  if (!target) {
    clientSocket.end("HTTP/1.1 400 Bad Request\r\n\r\n");
    return;
  }
  const resolution = await resolvePublic(target.hostname);
  record({ hostname: target.hostname, port: target.port, method: "CONNECT", blocked: !resolution.allowed, ...(resolution.reason ? { reason: resolution.reason } : {}) });
  if (!resolution.allowed) {
    clientSocket.end("HTTP/1.1 403 Forbidden\r\n\r\n");
    return;
  }
  const address = resolution.addresses[0];
  const upstream = net.connect({ host: address.address, port: target.port, family: address.family }, () => {
    clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
    if (head.length) upstream.write(head);
    upstream.pipe(clientSocket);
    clientSocket.pipe(upstream);
  });
  upstream.on("error", () => clientSocket.end("HTTP/1.1 502 Bad Gateway\r\n\r\n"));
  clientSocket.on("error", () => upstream.destroy());
});

server.on("clientError", (_error, socket) => socket.end("HTTP/1.1 400 Bad Request\r\n\r\n"));
server.listen(8080, "0.0.0.0", () => process.stdout.write("READY\n"));
