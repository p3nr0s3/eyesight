export interface ExtractedArtifacts {
  ips: string[];
  domains: string[];
  urls: string[];
  hashes: Array<{ value: string; algorithm: "MD5" | "SHA-1" | "SHA-256" }>;
  emails: string[];
  cves: string[];
}

export interface EmailAuthVerdict {
  mechanism: "SPF" | "DKIM" | "DMARC";
  status: string;
  detail: string;
}

export interface EmailRelayHop {
  hop: number;
  fromHost: string | null;
  byHost: string | null;
  ips: string[];
  timestamp: string | null;
  raw: string;
}

export interface EmailHeaderAnalysis {
  from: string | null;
  returnPath: string | null;
  replyTo: string | null;
  subject: string | null;
  date: string | null;
  messageId: string | null;
  originatingIp: string | null;
  authVerdicts: EmailAuthVerdict[];
  anomalies: string[];
  hops: EmailRelayHop[];
  extractedIps: string[];
  extractedDomains: string[];
}

export interface SubnetInspection {
  cidr: string;
  ip: string;
  prefix: number;
  networkAddress: string;
  broadcastAddress: string;
  netmask: string;
  wildcardMask: string;
  firstUsable: string;
  lastUsable: string;
  totalAddresses: number;
  usableHosts: number;
  classification: string;
}

export interface PayloadDecodeResult {
  detectedMode: string;
  decodedText: string;
  secondaryNote: string | null;
  jwtHeader?: Record<string, unknown> | null;
  jwtPayload?: Record<string, unknown> | null;
  jwtExpired?: boolean | null;
}

export interface SocPlaybookTemplate {
  id: string;
  title: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM";
  summary: string;
  steps: string[];
}

const IPV4_OCTET = "(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)";
const IPV4_GLOBAL_RE = new RegExp(
  `\\b(${IPV4_OCTET}(?:\\.${IPV4_OCTET}){3})\\b`,
  "g",
);

export function isValidIpv4(ip: string): boolean {
  const parts = ip.split(".");
  if (parts.length !== 4) return false;
  return parts.every((p) => /^\d+$/.test(p) && Number(p) >= 0 && Number(p) <= 255);
}

export function isPrivateIpv4(ip: string): boolean {
  if (!isValidIpv4(ip)) return false;
  const [a, b] = ip.split(".").map(Number);
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    a >= 224
  );
}

export function refangText(input: string): string {
  return input
    .replace(/hxxps/gi, "https")
    .replace(/hxxp/gi, "http")
    .replace(/\[:\]/g, ":")
    .replace(/\[\.\]/g, ".")
    .replace(/\(\.\)/g, ".")
    .replace(/\{\.\}/g, ".")
    .replace(/\[@\]/g, "@");
}

export function defangValue(value: string): string {
  const trimmed = value.trim();
  if (/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(trimmed)) {
    return trimmed;
  }
  return trimmed
    .replace(/^https:/i, "hxxps:")
    .replace(/^http:/i, "hxxp:")
    .replace(/@/g, "[@]")
    .replace(/\./g, "[.]");
}

export function extractSocArtifacts(rawText: string): ExtractedArtifacts {
  const normalized = refangText(rawText);

  const cves = Array.from(
    new Set(
      (normalized.match(/\bCVE-\d{4}-\d{4,7}\b/gi) || []).map((c) =>
        c.toUpperCase(),
      ),
    ),
  );

  const urls = Array.from(
    new Set(
      (normalized.match(/https?:\/\/[^\s"'<>)\]]+/gi) || []).map((u) =>
        u.replace(/[.,;!?]+$/, ""),
      ),
    ),
  );

  const emails = Array.from(
    new Set(
      (
        normalized.match(
          /\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,24}\b/gi,
        ) || []
      ).map((e) => e.toLowerCase()),
    ),
  );

  const ips = Array.from(
    new Set(
      (normalized.match(IPV4_GLOBAL_RE) || []).filter((ip) => isValidIpv4(ip)),
    ),
  );

  const hashMatches =
    normalized.match(/\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b/gi) || [];
  const hashSeen = new Set<string>();
  const hashes: ExtractedArtifacts["hashes"] = [];
  for (const h of hashMatches) {
    const lower = h.toLowerCase();
    if (hashSeen.has(lower)) continue;
    hashSeen.add(lower);
    hashes.push({
      value: lower,
      algorithm:
        lower.length === 64 ? "SHA-256" : lower.length === 40 ? "SHA-1" : "MD5",
    });
  }

  const domainCandidates =
    normalized.match(
      /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi,
    ) || [];
  const commonFileExts = new Set([
    "exe",
    "dll",
    "ps1",
    "bat",
    "vbs",
    "js",
    "json",
    "xml",
    "txt",
    "csv",
    "pdf",
    "doc",
    "docx",
    "xls",
    "xlsx",
    "zip",
    "rar",
    "7z",
    "png",
    "jpg",
    "jpeg",
    "gif",
    "eml",
    "msg",
    "log",
    "sys",
    "tmp",
  ]);
  const domainsSet = new Set<string>();
  for (const cand of domainCandidates) {
    const lower = cand.toLowerCase();
    if (isValidIpv4(lower)) continue;
    const tld = lower.split(".").pop() || "";
    if (commonFileExts.has(tld)) continue;
    domainsSet.add(lower);
  }
  for (const u of urls) {
    try {
      const host = new URL(u).hostname.toLowerCase();
      if (!isValidIpv4(host)) domainsSet.add(host);
    } catch {
      // Ignore malformed URLs
    }
  }

  return {
    ips,
    domains: Array.from(domainsSet),
    urls,
    hashes,
    emails,
    cves,
  };
}

function extractEmailDomain(headerVal: string | null): string | null {
  if (!headerVal) return null;
  const m = headerVal.match(/@([a-z0-9.-]+\.[a-z]{2,24})/i);
  return m?.[1]?.toLowerCase() || null;
}

export function analyzeEmailHeaders(rawHeaders: string): EmailHeaderAnalysis {
  const unfolded = rawHeaders.replace(/\r?\n[ \t]+/g, " ");
  const lines = unfolded.split(/\r?\n/);

  const getFirstHeader = (name: string): string | null => {
    const re = new RegExp(`^${name}:\\s*(.+)$`, "i");
    for (const line of lines) {
      const m = line.match(re);
      if (m?.[1]) return m[1].trim();
    }
    return null;
  };

  const from = getFirstHeader("From");
  const returnPath = getFirstHeader("Return-Path");
  const replyTo = getFirstHeader("Reply-To");
  const subject = getFirstHeader("Subject");
  const date = getFirstHeader("Date");
  const messageId = getFirstHeader("Message-ID");
  const originatingIpRaw = getFirstHeader("X-Originating-IP");
  const originatingIp =
    originatingIpRaw?.match(IPV4_GLOBAL_RE)?.[0] || null;

  const authLines = lines.filter((l) =>
    /^(Authentication-Results|ARC-Authentication-Results|Received-SPF):/i.test(
      l,
    ),
  );
  const authJoined = authLines.join(" ; ");

  const parseAuthStatus = (
    mech: "SPF" | "DKIM" | "DMARC",
    re: RegExp,
  ): EmailAuthVerdict => {
    const m = authJoined.match(re);
    if (m?.[1]) {
      return {
        mechanism: mech,
        status: m[1].toUpperCase(),
        detail: m[0],
      };
    }
    return {
      mechanism: mech,
      status: "NOT FOUND",
      detail: `No ${mech} header verdict observed`,
    };
  };

  const authVerdicts: EmailAuthVerdict[] = [
    parseAuthStatus("SPF", /\bspf=(pass|fail|softfail|neutral|none|temperror|permerror)\b/i),
    parseAuthStatus("DKIM", /\bdkim=(pass|fail|neutral|none|policy|temperror|permerror)\b/i),
    parseAuthStatus("DMARC", /\bdmarc=(pass|fail|bestguesspass|none|temperror|permerror)\b/i),
  ];

  const anomalies: string[] = [];
  const fromDom = extractEmailDomain(from);
  const rpDom = extractEmailDomain(returnPath);
  const rtDom = extractEmailDomain(replyTo);

  if (fromDom && rpDom && fromDom !== rpDom) {
    anomalies.push(
      `RETURN-PATH MISMATCH: From domain (${fromDom}) differs from Return-Path (${rpDom}).`,
    );
  }
  if (fromDom && rtDom && fromDom !== rtDom) {
    anomalies.push(
      `REPLY-TO SPOOFING INDICATOR: Reply-To (${rtDom}) diverges from From (${fromDom}).`,
    );
  }
  for (const v of authVerdicts) {
    if (v.status === "FAIL" || v.status === "SOFTFAIL") {
      anomalies.push(`${v.mechanism} CHECK FAILED (${v.status}).`);
    }
  }

  const receivedLines = lines
    .filter((l) => /^Received:/i.test(l))
    .reverse(); // Chronological oldest hop first
  const hops: EmailRelayHop[] = receivedLines.map((line, idx) => {
    const fromHost = line.match(/\bfrom\s+([^\s(]+)/i)?.[1] || null;
    const byHost = line.match(/\bby\s+([^\s(]+)/i)?.[1] || null;
    const timestamp = line.includes(";")
      ? line.slice(line.lastIndexOf(";") + 1).trim()
      : null;
    const ips = Array.from(new Set(line.match(IPV4_GLOBAL_RE) || []));
    return {
      hop: idx + 1,
      fromHost,
      byHost,
      ips,
      timestamp,
      raw: line,
    };
  });

  const extractedIps = Array.from(
    new Set(
      (unfolded.match(IPV4_GLOBAL_RE) || []).filter(
        (ip) => isValidIpv4(ip) && !isPrivateIpv4(ip),
      ),
    ),
  );
  const artifacts = extractSocArtifacts(unfolded);

  return {
    from,
    returnPath,
    replyTo,
    subject,
    date,
    messageId,
    originatingIp,
    authVerdicts,
    anomalies,
    hops,
    extractedIps,
    extractedDomains: artifacts.domains,
  };
}

function intToIpv4(num: number): string {
  return [
    (num >>> 24) & 255,
    (num >>> 16) & 255,
    (num >>> 8) & 255,
    num & 255,
  ].join(".");
}

function ipv4ToInt(ip: string): number {
  const parts = ip.split(".").map(Number);
  return (
    (((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0)
  );
}

export function inspectSubnetCidr(input: string): SubnetInspection | null {
  const trimmed = input.trim();
  const m = trimmed.match(/^(\d{1,3}(?:\.\d{1,3}){3})(?:\/(\d{1,2}))?$/);
  if (!m || !isValidIpv4(m[1])) return null;
  const ip = m[1];
  const prefix = m[2] !== undefined ? Number(m[2]) : 24;
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null;

  const ipInt = ipv4ToInt(ip);
  const maskInt = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const wildcardInt = (~maskInt) >>> 0;
  const networkInt = (ipInt & maskInt) >>> 0;
  const broadcastInt = (networkInt | wildcardInt) >>> 0;
  const totalAddresses = Math.pow(2, 32 - prefix);
  const usableHosts = prefix >= 31 ? totalAddresses : Math.max(0, totalAddresses - 2);
  const firstUsableInt = prefix >= 31 ? networkInt : (networkInt + 1) >>> 0;
  const lastUsableInt = prefix >= 31 ? broadcastInt : (broadcastInt - 1) >>> 0;

  let classification = "PUBLIC ROUTABLE";
  const [a, b] = ip.split(".").map(Number);
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) {
    classification = "PRIVATE (RFC 1918)";
  } else if (a === 127) {
    classification = "LOOPBACK (RFC 1122)";
  } else if (a === 100 && b >= 64 && b <= 127) {
    classification = "CGNAT (RFC 6598)";
  } else if (a === 169 && b === 254) {
    classification = "LINK-LOCAL / METADATA (RFC 3927)";
  }

  return {
    cidr: `${intToIpv4(networkInt)}/${prefix}`,
    ip,
    prefix,
    networkAddress: intToIpv4(networkInt),
    broadcastAddress: intToIpv4(broadcastInt),
    netmask: intToIpv4(maskInt),
    wildcardMask: intToIpv4(wildcardInt),
    firstUsable: intToIpv4(firstUsableInt),
    lastUsable: intToIpv4(lastUsableInt),
    totalAddresses,
    usableHosts,
    classification,
  };
}

function decodeBase64ToBytes(b64: string): Uint8Array {
  const padded = b64.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(padded);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    bytes[i] = bin.charCodeAt(i);
  }
  return bytes;
}

export function decodeCyberPayload(
  rawInput: string,
  mode: "auto" | "base64" | "ps_b64" | "url" | "hex" | "jwt",
): PayloadDecodeResult {
  const trimmed = rawInput.trim();
  if (!trimmed) {
    return { detectedMode: "EMPTY", decodedText: "", secondaryNote: null };
  }

  // Extract inline PowerShell -EncodedCommand argument if pasted as full command
  const psMatch = trimmed.match(/(?:-enc|-encodedcommand)\s+([A-Za-z0-9+/=]+)/i);
  const effectiveInput = psMatch?.[1] || trimmed;

  let chosen = mode;
  if (chosen === "auto") {
    if (psMatch) chosen = "ps_b64";
    else if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(trimmed)) {
      chosen = "jwt";
    } else if (/^(?:0x)?(?:[0-9a-f]{2}[\s:,-]*){4,}$/i.test(trimmed)) {
      chosen = "hex";
    } else if (/%[0-9a-f]{2}/i.test(trimmed)) {
      chosen = "url";
    } else {
      chosen = "base64";
    }
  }

  try {
    if (chosen === "jwt") {
      const parts = trimmed.split(".");
      if (parts.length < 2) throw new Error("Invalid JWT format");
      const headerStr = new TextDecoder().decode(decodeBase64ToBytes(parts[0]));
      const payloadStr = new TextDecoder().decode(decodeBase64ToBytes(parts[1]));
      const jwtHeader = JSON.parse(headerStr) as Record<string, unknown>;
      const jwtPayload = JSON.parse(payloadStr) as Record<string, unknown>;
      const exp = typeof jwtPayload.exp === "number" ? jwtPayload.exp : null;
      const jwtExpired = exp !== null ? exp * 1000 < Date.now() : null;
      return {
        detectedMode: "JWT TOKEN",
        decodedText: JSON.stringify({ header: jwtHeader, payload: jwtPayload }, null, 2),
        secondaryNote:
          exp !== null
            ? `TOKEN EXPIRATION: ${new Date(exp * 1000).toISOString()} (${jwtExpired ? "EXPIRED" : "VALID"})`
            : "NO EXP CLAIM PRESENT",
        jwtHeader,
        jwtPayload,
        jwtExpired,
      };
    }

    if (chosen === "hex") {
      const cleanHex = trimmed.replace(/0x|[\s:,-]/gi, "");
      const bytes = new Uint8Array(Math.floor(cleanHex.length / 2));
      for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(cleanHex.slice(i * 2, i * 2 + 2), 16);
      }
      return {
        detectedMode: "HEX BYTES -> UTF-8",
        decodedText: new TextDecoder("utf-8", { fatal: false }).decode(bytes),
        secondaryNote: `DECODED ${bytes.length} BYTE(S)`,
      };
    }

    if (chosen === "url") {
      return {
        detectedMode: "URL PERCENT-DECODE",
        decodedText: decodeURIComponent(trimmed),
        secondaryNote: null,
      };
    }

    if (chosen === "ps_b64") {
      const bytes = decodeBase64ToBytes(effectiveInput);
      const utf16Text = new TextDecoder("utf-16le", { fatal: false }).decode(bytes);
      return {
        detectedMode: "POWERSHELL UTF-16LE BASE64",
        decodedText: utf16Text,
        secondaryNote: `DECODED ${bytes.length} BYTES VIA UTF-16LE`,
      };
    }

    const bytes = decodeBase64ToBytes(effectiveInput);
    // Auto-detect UTF-16LE null-byte pattern often used by PowerShell payloads
    const looksUtf16Le =
      bytes.length >= 4 && bytes[1] === 0 && bytes[3] === 0;
    const text = new TextDecoder(looksUtf16Le ? "utf-16le" : "utf-8", {
      fatal: false,
    }).decode(bytes);
    return {
      detectedMode: looksUtf16Le ? "BASE64 (AUTO UTF-16LE)" : "BASE64 -> UTF-8",
      decodedText: text,
      secondaryNote: `DECODED ${bytes.length} BYTE(S)`,
    };
  } catch (err) {
    return {
      detectedMode: `${chosen.toUpperCase()} ERROR`,
      decodedText:
        err instanceof Error ? `Unable to decode payload: ${err.message}` : "Invalid encoding",
      secondaryNote: null,
    };
  }
}

export function generateDetectionRules(
  iocsText: string,
  platform: "splunk" | "kql" | "elastic" | "sigma" | "yara",
): string {
  const art = extractSocArtifacts(iocsText);
  const allNet = [...art.ips, ...art.domains];

  if (platform === "splunk") {
    const clauses: string[] = [];
    if (art.ips.length) {
      clauses.push(
        `(${art.ips.map((ip) => `src_ip="${ip}" OR dest_ip="${ip}"`).join(" OR ")})`,
      );
    }
    if (art.domains.length) {
      clauses.push(
        `(${art.domains.map((d) => `query="${d}" OR dest_host="${d}" OR url="*${d}*"`).join(" OR ")})`,
      );
    }
    if (art.hashes.length) {
      clauses.push(
        `(${art.hashes.map((h) => `file_hash="${h.value}"`).join(" OR ")})`,
      );
    }
    if (clauses.length === 0) {
      return `index=* ("${iocsText.trim() || "indicator"}") | stats count by host, user, src_ip, dest_ip`;
    }
    return `index=* (${clauses.join(" OR ")})\n| stats count min(_time) as first_seen max(_time) as last_seen by sourcetype, host, user, src_ip, dest_ip\n| sort -count`;
  }

  if (platform === "kql") {
    const parts: string[] = [];
    if (art.ips.length) {
      parts.push(
        `let MaliciousIPs = dynamic([${art.ips.map((i) => `"${i}"`).join(", ")}]);\nDeviceNetworkEvents\n| where RemoteIP in (MaliciousIPs)\n| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl`,
      );
    }
    if (art.domains.length) {
      parts.push(
        `let MaliciousDomains = dynamic([${art.domains.map((d) => `"${d}"`).join(", ")}]);\nDnsEvents\n| where Name has_any (MaliciousDomains)\n| project TimeGenerated, Computer, ClientIP, Name`,
      );
    }
    if (art.hashes.length) {
      parts.push(
        `let MaliciousHashes = dynamic([${art.hashes.map((h) => `"${h.value}"`).join(", ")}]);\nDeviceFileEvents\n| where SHA256 in~ (MaliciousHashes) or MD5 in~ (MaliciousHashes) or SHA1 in~ (MaliciousHashes)\n| project Timestamp, DeviceName, FolderPath, FileName, SHA256`,
      );
    }
    return (
      parts.join("\n\n// ---\n\n") ||
      `search "${iocsText.trim() || "indicator"}" | take 100`
    );
  }

  if (platform === "elastic") {
    const terms: string[] = [];
    for (const ip of art.ips) terms.push(`destination.ip : "${ip}" or source.ip : "${ip}"`);
    for (const d of art.domains) terms.push(`dns.question.name : "*${d}" or url.domain : "*${d}"`);
    for (const h of art.hashes) terms.push(`file.hash.* : "${h.value}"`);
    return terms.join(" or ") || `message : "*${iocsText.trim() || "indicator"}*"`;
  }

  if (platform === "sigma") {
    const destIps = art.ips.length
      ? `    DestinationIp:\n${art.ips.map((i) => `      - '${i}'`).join("\n")}\n`
      : "";
    const destHost = art.domains.length
      ? `    DestinationHostname|endswith:\n${art.domains.map((d) => `      - '${d}'`).join("\n")}\n`
      : "";
    const hashes = art.hashes.length
      ? `    Hashes|contains:\n${art.hashes.map((h) => `      - '${h.value}'`).join("\n")}\n`
      : "";

    return `title: EYESIGHT Threat Hunt - Suspicious IOC Activity
status: experimental
description: Auto-generated Sigma hunting rule from SOC Workbench indicators
logsource:
  category: network_connection
  product: windows
detection:
  selection:
${destIps}${destHost}${hashes || (!destIps && !destHost ? `    CommandLine|contains: '${iocsText.trim() || "indicator"}'\n` : "")}  condition: selection
level: high
tags:
  - attack.command_and_control`;
  }

  // YARA rule
  const stringsList = allNet.length ? allNet : [iocsText.trim() || "malicious_c2"];
  const yaraStrings = stringsList
    .slice(0, 15)
    .map((s, idx) => `        $s${idx} = "${s.replace(/"/g, '\\"')}" ascii wide nocase`)
    .join("\n");
  return `rule EYESIGHT_SOC_IOC_Hunt {
    meta:
        author = "EYESIGHT SOC Workbench"
        description = "Auto-generated YARA string match rule"
        date = "${new Date().toISOString().slice(0, 10)}"
    strings:
${yaraStrings}
    condition:
        any of them
}`;
}

export const SOC_PLAYBOOKS: SocPlaybookTemplate[] = [
  {
    id: "phishing",
    title: "PHISHING EMAIL COMPROMISE (T1566)",
    severity: "HIGH",
    summary: "Triage suspected credential harvesting or malicious attachment delivery.",
    steps: [
      "Extract and inspect SMTP headers (SPF, DKIM, DMARC, Return-Path vs From, X-Originating-IP).",
      "Enrich sender IP, URLs, and attachment hashes via EYESIGHT IOC Lookup / Bulk Queue.",
      "Search SIEM / email gateway logs for all internal recipients who received or clicked the URL.",
      "Quarantine message across all mailboxes & block sender domain / malicious URLs on proxy.",
      "Reset passwords & revoke active OAuth/session tokens for any clicking/submitting users.",
    ],
  },
  {
    id: "c2_ransomware",
    title: "C2 BEACON / RANSOMWARE PRECURSOR (T1071 / T1486)",
    severity: "CRITICAL",
    summary: "Contain active Command-and-Control traffic or lateral extortion precursor activity.",
    steps: [
      "Verify destination IP/domain in Live Attack IOCs, AbuseIPDB, VirusTotal & Feodo Tracker.",
      "Isolate affected endpoint from corporate network via EDR host containment immediately.",
      "Inspect running processes, parent-child tree, persistence keys, and scheduled tasks.",
      "Hunt across firewall/EDR telemetry for lateral SMB/RDP/WinRM movement from the host.",
      "Block C2 IP/domain/ports on perimeter firewall & capture volatile forensic triage package.",
    ],
  },
  {
    id: "stealer_leak",
    title: "CREDENTIAL LEAK / INFOSTEALER INFECTION",
    severity: "CRITICAL",
    summary: "Respond to exposed corporate credentials detected in Hudson Rock, LeakCheck, or COMB.",
    steps: [
      "Verify exposure scope & timestamp in Darkweb -> Credential Leaks (Hudson Rock / LeakCheck / XON).",
      "Force immediate password reset + MFA re-enrollment & invalidate active SSO/VPN sessions.",
      "Identify infected corporate/BYOD workstation from computer name, OS, and malware path.",
      "Run full EDR remediation / OS re-image on confirmed infostealer-infected endpoints.",
      "Audit SSO, VPN, and OWA sign-in logs for anomalous logins prior to credential rotation.",
    ],
  },
  {
    id: "bruteforce",
    title: "EXTERNAL BRUTE-FORCE / CVE EXPLOITATION PROBE",
    severity: "HIGH",
    summary: "Investigate high-volume external scanners or active CISA KEV exploitation attempts.",
    steps: [
      "Enrich attacking IP in GreyNoise, Shodan InternetDB, SANS DShield & AbuseIPDB.",
      "Verify targeted external service ports & check CVE Lookup / CISA KEV for unpatched vulns.",
      "Correlate authentication logs for any successful logins (`Event 4624` / SSH Accepted) from source IP.",
      "Apply perimeter IP/CIDR blocklist & enforce MFA / rate-limiting on exposed authentication endpoints.",
      "Schedule emergency patching if any exposed internet asset matches an active CISA KEV entry.",
    ],
  },
];
