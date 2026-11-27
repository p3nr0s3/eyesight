import net from "node:net";
import type { IocType } from "@/lib/providers/catalog";

export interface ParsedIoc {
  raw: string;
  normalized: string;
  type: IocType;
  hashAlgorithm?: "md5" | "sha1" | "sha256";
  isPrivateIp?: boolean;
}

/** Converts defanged IOCs (e.g., hxxps[:]//evil[.]com) back into canonical form. */
export function refangIoc(input: string): string {
  let s = input.trim();
  s = s.replace(/^hxxps/i, "https");
  s = s.replace(/^hxxp/i, "http");
  s = s.replace(/\[:\]/g, ":");
  s = s.replace(/\[\.\]/g, ".");
  s = s.replace(/\(\.\)/g, ".");
  s = s.replace(/\{\.\}/g, ".");
  s = s.replace(/\[@\]/g, "@");
  s = s.replace(/^["'`<(\[]+|["'`>)\],;]+$/g, "");
  return s.trim();
}

/** Defangs an IOC safely for sharing in reports/chat. */
export function defangIoc(value: string, type: IocType): string {
  if (type === "hash") return value;
  let s = value.replace(/^https:/i, "hxxps:").replace(/^http:/i, "hxxp:");
  s = s.replace(/\./g, "[.]");
  return s;
}

/** Checks if an IPv4 or IPv6 address belongs to private, loopback, link-local, or reserved space. */
export function isPrivateOrReservedIp(ip: string): boolean {
  if (net.isIPv4(ip)) {
    const parts = ip.split(".").map(Number);
    const [a, b] = parts;
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
    if (a === 169 && b === 254) return true; // Link-local / cloud metadata
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 192 && b === 0 && parts[2] === 2) return true; // TEST-NET-1
    if (a === 198 && (b === 18 || b === 19)) return true; // Benchmarking
    if (a >= 224) return true; // Multicast & reserved
    return false;
  }
  if (net.isIPv6(ip)) {
    const lower = ip.toLowerCase();
    if (lower === "::1" || lower === "::") return true;
    if (lower.startsWith("fe80:") || lower.startsWith("fc") || lower.startsWith("fd")) {
      return true;
    }
    if (lower.startsWith("::ffff:")) {
      const mapped = lower.slice(7);
      if (net.isIPv4(mapped)) return isPrivateOrReservedIp(mapped);
    }
    return false;
  }
  return false;
}

const DOMAIN_REGEX =
  /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

/** Detects and normalizes a single IOC string, returning null if invalid/unsupported. */
export function parseIoc(rawInput: string): ParsedIoc | null {
  const refanged = refangIoc(rawInput);
  if (!refanged || refanged.length > 2048) return null;

  // Strip optional port from IPv4:port if someone pastes 1.2.3.4:443
  const ipv4PortMatch = refanged.match(/^(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}$/);
  if (ipv4PortMatch && net.isIPv4(ipv4PortMatch[1])) {
    const ip = ipv4PortMatch[1];
    return {
      raw: rawInput,
      normalized: ip,
      type: "ip",
      isPrivateIp: isPrivateOrReservedIp(ip),
    };
  }

  // 1. IPv4 or IPv6
  if (net.isIP(refanged)) {
    const normalized = refanged.toLowerCase();
    return {
      raw: rawInput,
      normalized,
      type: "ip",
      isPrivateIp: isPrivateOrReservedIp(normalized),
    };
  }

  // 2. File Hash (MD5 / SHA-1 / SHA-256)
  if (/^[a-fA-F0-9]{32}$/.test(refanged)) {
    return {
      raw: rawInput,
      normalized: refanged.toLowerCase(),
      type: "hash",
      hashAlgorithm: "md5",
    };
  }
  if (/^[a-fA-F0-9]{40}$/.test(refanged)) {
    return {
      raw: rawInput,
      normalized: refanged.toLowerCase(),
      type: "hash",
      hashAlgorithm: "sha1",
    };
  }
  if (/^[a-fA-F0-9]{64}$/.test(refanged)) {
    return {
      raw: rawInput,
      normalized: refanged.toLowerCase(),
      type: "hash",
      hashAlgorithm: "sha256",
    };
  }

  // 3. URL (http:// or https://)
  if (/^https?:\/\//i.test(refanged)) {
    try {
      const parsed = new URL(refanged);
      if (parsed.hostname && (net.isIP(parsed.hostname) || DOMAIN_REGEX.test(parsed.hostname))) {
        parsed.hostname = parsed.hostname.toLowerCase();
        return {
          raw: rawInput,
          normalized: parsed.toString(),
          type: "url",
        };
      }
    } catch {
      return null;
    }
  }

  // 4. Domain (strip trailing dot or path if pasted like evil.com/login without scheme -> treat as domain if no path, or URL if path)
  const cleanDomain = refanged.replace(/\.$/, "").toLowerCase();
  if (DOMAIN_REGEX.test(cleanDomain)) {
    return {
      raw: rawInput,
      normalized: cleanDomain,
      type: "domain",
    };
  }

  // Host/path without scheme like evil.com/payload.exe
  if (/^[a-z0-9.-]+\.[a-z]{2,63}\/\S+$/i.test(refanged)) {
    try {
      const parsed = new URL(`http://${refanged}`);
      if (DOMAIN_REGEX.test(parsed.hostname)) {
        return {
          raw: rawInput,
          normalized: parsed.toString(),
          type: "url",
        };
      }
    } catch {
      return null;
    }
  }

  return null;
}

/** Parses multi-line, comma-separated, or space-separated bulk text into unique valid IOCs. */
export function parseBulkIocs(text: string, maxItems = 200): {
  iocs: ParsedIoc[];
  invalidTokens: string[];
  duplicatesRemoved: number;
} {
  const tokens = text
    .split(/[\r\n,\s;|]+/)
    .map((t) => t.trim())
    .filter(Boolean);

  const seen = new Set<string>();
  const iocs: ParsedIoc[] = [];
  const invalidTokens: string[] = [];
  let duplicatesRemoved = 0;

  for (const token of tokens) {
    const parsed = parseIoc(token);
    if (!parsed) {
      invalidTokens.push(token);
      continue;
    }
    const key = `${parsed.type}:${parsed.normalized}`;
    if (seen.has(key)) {
      duplicatesRemoved++;
      continue;
    }
    seen.add(key);
    iocs.push(parsed);
    if (iocs.length >= maxItems) break;
  }

  return { iocs, invalidTokens, duplicatesRemoved };
}

export function extractHostnameFromUrl(urlStr: string): string | null {
  try {
    return new URL(urlStr).hostname.toLowerCase();
  } catch {
    return null;
  }
}
