export type IocType = "ip" | "domain" | "url" | "hash";

export type ProviderId =
  | "virustotal"
  | "abuseipdb"
  | "urlhaus"
  | "threatfox"
  | "malwarebazaar"
  | "otx"
  | "shodan"
  | "greynoise"
  | "network_rdap";

export type ToolCategoryId =
  | "all"
  | "reputation"
  | "malware_feeds"
  | "exposure_noise"
  | "network_osint";

export interface ToolCategoryMeta {
  id: ToolCategoryId;
  label: string;
  shortLabel: string;
  description: string;
}

export const TOOL_CATEGORIES: ToolCategoryMeta[] = [
  {
    id: "all",
    label: "ALL TOOLS",
    shortLabel: "ALL",
    description: "Every threat intelligence & OSINT engine active in eyesight.",
  },
  {
    id: "reputation",
    label: "REPUTATION & AV",
    shortLabel: "REPUTATION",
    description: "Multi-engine AV verdicts and crowdsourced IP abuse confidence.",
  },
  {
    id: "malware_feeds",
    label: "MALWARE FEEDS",
    shortLabel: "MALWARE",
    description: "abuse.ch URLhaus, ThreatFox C2 indicators, and MalwareBazaar payloads.",
  },
  {
    id: "exposure_noise",
    label: "EXPOSURE & NOISE",
    shortLabel: "EXPOSURE",
    description: "OTX pulses, Shodan open ports/CVEs, and GreyNoise scanner classification.",
  },
  {
    id: "network_osint",
    label: "NETWORK & OSINT",
    shortLabel: "NETWORK",
    description: "Zero-key live DNS records, RDAP/WHOIS registration, GeoIP, and ASN.",
  },
];

export interface ProviderMeta {
  id: ProviderId;
  name: string;
  shortName: string;
  category: Exclude<ToolCategoryId, "all">;
  description: string;
  supportedTypes: IocType[];
  keyRequirement: "required" | "optional" | "none";
  envVarName?: string;
  defaultWeight: number;
  defaultTtlSeconds: number;
  homepage: string;
  isInformational?: boolean;
}

export const PROVIDER_CATALOG: ProviderMeta[] = [
  {
    id: "virustotal",
    name: "VirusTotal",
    shortName: "VT",
    category: "reputation",
    description:
      "Multi-engine malware & URL/IP/domain reputation scanning (70+ AV engines).",
    supportedTypes: ["ip", "domain", "url", "hash"],
    keyRequirement: "required",
    envVarName: "VT_API_KEY",
    defaultWeight: 30,
    defaultTtlSeconds: 3600,
    homepage: "https://www.virustotal.com",
  },
  {
    id: "abuseipdb",
    name: "AbuseIPDB",
    shortName: "AbuseIPDB",
    category: "reputation",
    description:
      "Crowdsourced IP abuse confidence score, attack categories, and report volume.",
    supportedTypes: ["ip"],
    keyRequirement: "required",
    envVarName: "ABUSEIPDB_API_KEY",
    defaultWeight: 20,
    defaultTtlSeconds: 3600,
    homepage: "https://www.abuseipdb.com",
  },
  {
    id: "urlhaus",
    name: "abuse.ch URLhaus",
    shortName: "URLhaus",
    category: "malware_feeds",
    description:
      "Malware distribution URLs, malicious hosts, and payload hashes.",
    supportedTypes: ["url", "domain", "ip", "hash"],
    keyRequirement: "optional",
    envVarName: "ABUSECH_AUTH_KEY",
    defaultWeight: 18,
    defaultTtlSeconds: 1800,
    homepage: "https://urlhaus.abuse.ch",
  },
  {
    id: "threatfox",
    name: "abuse.ch ThreatFox",
    shortName: "ThreatFox",
    category: "malware_feeds",
    description:
      "C2 servers, malware IOCs, threat types, and confidence ratings.",
    supportedTypes: ["ip", "domain", "url", "hash"],
    keyRequirement: "optional",
    envVarName: "ABUSECH_AUTH_KEY",
    defaultWeight: 18,
    defaultTtlSeconds: 1800,
    homepage: "https://threatfox.abuse.ch",
  },
  {
    id: "malwarebazaar",
    name: "abuse.ch MalwareBazaar",
    shortName: "MalwareBazaar",
    category: "malware_feeds",
    description:
      "Malware sample intelligence, signatures, YARA matches, and tags by file hash.",
    supportedTypes: ["hash"],
    keyRequirement: "optional",
    envVarName: "ABUSECH_AUTH_KEY",
    defaultWeight: 22,
    defaultTtlSeconds: 3600,
    homepage: "https://bazaar.abuse.ch",
  },
  {
    id: "otx",
    name: "AlienVault OTX",
    shortName: "OTX",
    category: "exposure_noise",
    description:
      "Open Threat Exchange pulses, adversary attribution, and passive indicator context.",
    supportedTypes: ["ip", "domain", "url", "hash"],
    keyRequirement: "required",
    envVarName: "OTX_API_KEY",
    defaultWeight: 15,
    defaultTtlSeconds: 3600,
    homepage: "https://otx.alienvault.com",
  },
  {
    id: "shodan",
    name: "Shodan",
    shortName: "Shodan",
    category: "exposure_noise",
    description:
      "Exposed ports, service banners, CVEs, and internet-facing host metadata.",
    supportedTypes: ["ip", "domain"],
    keyRequirement: "required",
    envVarName: "SHODAN_API_KEY",
    defaultWeight: 12,
    defaultTtlSeconds: 7200,
    homepage: "https://www.shodan.io",
  },
  {
    id: "greynoise",
    name: "GreyNoise",
    shortName: "GreyNoise",
    category: "exposure_noise",
    description:
      "Distinguishes internet background noise/RIOT benign scanners from targeted malicious IPs.",
    supportedTypes: ["ip"],
    keyRequirement: "optional",
    envVarName: "GREYNOISE_API_KEY",
    defaultWeight: 15,
    defaultTtlSeconds: 3600,
    homepage: "https://viz.greynoise.io",
  },
  {
    id: "network_rdap",
    name: "DNS / RDAP / GeoIP",
    shortName: "Net/RDAP",
    category: "network_osint",
    description:
      "Zero-key live DNS records, RDAP registration/WHOIS, GeoIP, and ASN ownership.",
    supportedTypes: ["ip", "domain", "url"],
    keyRequirement: "none",
    defaultWeight: 0,
    defaultTtlSeconds: 7200,
    homepage: "https://about.rdap.org",
    isInformational: true,
  },
];

export const PROVIDER_MAP: Record<ProviderId, ProviderMeta> = Object.fromEntries(
  PROVIDER_CATALOG.map((p) => [p.id, p]),
) as Record<ProviderId, ProviderMeta>;
