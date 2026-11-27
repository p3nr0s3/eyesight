import {
  PROVIDER_CATALOG,
  type IocType,
  type ProviderId,
  type ToolCategoryId,
} from "./catalog";

export interface ToolSample {
  label: string;
  desc: string;
}

export interface ToolProfile {
  title: string;
  subtitle: string;
  acceptedTypes: IocType[];
  placeholder: string;
  submitLabel: string;
  samples: ToolSample[];
  providerIds?: ProviderId[];
  defaultTab: "summary" | "providers" | "network" | "raw";
}

const SINGLE_TOOL_PROFILES: Record<ProviderId, ToolProfile> = {
  virustotal: {
    title: "VIRUSTOTAL MULTI-ENGINE SCANNER",
    subtitle:
      "QUERY 70+ ANTIVIRUS ENGINES, REPUTATION SCORES, AND PASSIVE DNS ATTRIBUTES VIA VIRUSTOTAL V3.",
    acceptedTypes: ["ip", "domain", "url", "hash"],
    placeholder: "ENTER IP, DOMAIN, URL, OR MD5/SHA1/SHA256 FOR VIRUSTOTAL...",
    submitLabel: "SCAN VIRUSTOTAL",
    samples: [
      { label: "1.1.1.1", desc: "IP REPUTATION" },
      { label: "example.com", desc: "DOMAIN SCAN" },
      { label: "44d88612fea8a8f36de82e1278abb02f", desc: "EICAR MD5 HASH" },
    ],
    providerIds: ["virustotal"],
    defaultTab: "providers",
  },
  abuseipdb: {
    title: "ABUSEIPDB IP REPUTATION CHECK",
    subtitle:
      "INSPECT CROWDSOURCED IP ABUSE CONFIDENCE SCORES, ISP METADATA, TOR EXIT STATUS, AND REPORT HISTORY.",
    acceptedTypes: ["ip"],
    placeholder: "ENTER IPV4 OR IPV6 ADDRESS ONLY (E.G. 1.1.1.1)...",
    submitLabel: "CHECK ABUSEIPDB",
    samples: [
      { label: "1.1.1.1", desc: "CLOUDFLARE DNS" },
      { label: "8.8.8.8", desc: "GOOGLE DNS" },
      { label: "45.155.205.233", desc: "PUBLIC IP CHECK" },
    ],
    providerIds: ["abuseipdb"],
    defaultTab: "providers",
  },
  urlhaus: {
    title: "ABUSE.CH URLHAUS MALWARE DISTRIBUTION",
    subtitle:
      "CHECK WHETHER A URL, HOSTNAME, IP, OR PAYLOAD HASH IS TRACKED FOR ACTIVE MALWARE DISTRIBUTION.",
    acceptedTypes: ["url", "domain", "ip", "hash"],
    placeholder: "ENTER URL, DOMAIN, IP, OR MD5/SHA256 PAYLOAD HASH...",
    submitLabel: "QUERY URLHAUS",
    samples: [
      { label: "hxxps[:]//example[.]com/payload", desc: "DEFANGED URL" },
      { label: "example.com", desc: "HOST CHECK" },
      { label: "44d88612fea8a8f36de82e1278abb02f", desc: "PAYLOAD MD5" },
    ],
    providerIds: ["urlhaus"],
    defaultTab: "providers",
  },
  threatfox: {
    title: "ABUSE.CH THREATFOX C2 & IOC SEARCH",
    subtitle:
      "SEARCH CONFIRMED COMMAND-AND-CONTROL (C2) SERVERS, BOTNET IOCS, AND MALWARE FAMILY CONFIDENCE.",
    acceptedTypes: ["ip", "domain", "url", "hash"],
    placeholder: "ENTER C2 IP, DOMAIN, URL, OR MALWARE HASH FOR THREATFOX...",
    submitLabel: "SEARCH THREATFOX",
    samples: [
      { label: "1.1.1.1", desc: "IP IOC CHECK" },
      { label: "example.com", desc: "DOMAIN IOC CHECK" },
      { label: "44d88612fea8a8f36de82e1278abb02f", desc: "HASH CHECK" },
    ],
    providerIds: ["threatfox"],
    defaultTab: "providers",
  },
  malwarebazaar: {
    title: "ABUSE.CH MALWAREBAZAAR SAMPLE INSPECTOR",
    subtitle:
      "LOOK UP MALWARE SIGNATURES, FILE TYPES, DELIVERY METHODS, AND RELATED HASHES BY FILE HASH ONLY.",
    acceptedTypes: ["hash"],
    placeholder: "ENTER MD5 (32), SHA-1 (40), OR SHA-256 (64) FILE HASH ONLY...",
    submitLabel: "INSPECT HASH",
    samples: [
      { label: "44d88612fea8a8f36de82e1278abb02f", desc: "EICAR MD5" },
      {
        label: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        desc: "EICAR SHA-256",
      },
    ],
    providerIds: ["malwarebazaar"],
    defaultTab: "providers",
  },
  otx: {
    title: "ALIENVAULT OTX THREAT PULSE LOOKUP",
    subtitle:
      "CORRELATE INDICATORS AGAINST COMMUNITY THREAT PULSES, ADVERSARY ATTRIBUTION, AND VALIDATION TAGS.",
    acceptedTypes: ["ip", "domain", "url", "hash"],
    placeholder: "ENTER IP, DOMAIN, URL, OR FILE HASH FOR OTX PULSES...",
    submitLabel: "QUERY OTX PULSES",
    samples: [
      { label: "8.8.8.8", desc: "IP PULSES" },
      { label: "example.com", desc: "DOMAIN PULSES" },
      { label: "44d88612fea8a8f36de82e1278abb02f", desc: "FILE PULSES" },
    ],
    providerIds: ["otx"],
    defaultTab: "providers",
  },
  shodan: {
    title: "SHODAN EXPOSED PORTS & CVE RECON",
    subtitle:
      "DISCOVER OPEN PORTS, SERVICE BANNERS, HOSTNAMES, ASN OWNERSHIP, AND KNOWN CVES FOR IPS OR DOMAINS.",
    acceptedTypes: ["ip", "domain"],
    placeholder: "ENTER TARGET IP OR DOMAIN ONLY FOR SHODAN RECON...",
    submitLabel: "RECON SHODAN",
    samples: [
      { label: "1.1.1.1", desc: "HOST PORTS & BANNERS" },
      { label: "8.8.8.8", desc: "DNS INFRASTRUCTURE" },
      { label: "example.com", desc: "DOMAIN RESOLVE" },
    ],
    providerIds: ["shodan"],
    defaultTab: "providers",
  },
  greynoise: {
    title: "GREYNOISE INTERNET NOISE & RIOT CHECK",
    subtitle:
      "SEPARATE BENIGN RIOT INFRASTRUCTURE FROM MASS INTERNET SCANNERS AND TARGETED THREAT ACTORS.",
    acceptedTypes: ["ip"],
    placeholder: "ENTER SOURCE IPV4 OR IPV6 ADDRESS ONLY FOR GREYNOISE...",
    submitLabel: "CHECK GREYNOISE",
    samples: [
      { label: "8.8.8.8", desc: "RIOT BENIGN CHECK" },
      { label: "1.1.1.1", desc: "RIOT CLOUDFLARE" },
    ],
    providerIds: ["greynoise"],
    defaultTab: "providers",
  },
  network_rdap: {
    title: "DNS RECORDS, RDAP / WHOIS & GEOIP / ASN",
    subtitle:
      "ZERO-KEY LIVE RECONNAISSANCE FOR A/AAAA/MX/NS/TXT/PTR RECORDS, REGISTRAR DATES, NETBLOCKS & GEOIP.",
    acceptedTypes: ["ip", "domain", "url"],
    placeholder: "ENTER IP, DOMAIN, OR URL FOR LIVE DNS, RDAP & GEOIP...",
    submitLabel: "RESOLVE NETWORK",
    samples: [
      { label: "example.com", desc: "DOMAIN DNS + RDAP" },
      { label: "cloudflare.com", desc: "NS / MX / RDAP" },
      { label: "1.1.1.1", desc: "IP GEOIP + PTR + RDAP" },
    ],
    providerIds: ["network_rdap"],
    defaultTab: "network",
  },
};

const CATEGORY_PROFILES: Record<ToolCategoryId, ToolProfile> = {
  all: {
    title: "UNIFIED IOC INVESTIGATION",
    subtitle:
      "ENRICH ANY IPV4/IPV6, DOMAIN, URL, OR FILE HASH ACROSS ALL 9 THREAT INTEL & OSINT ENGINES.",
    acceptedTypes: ["ip", "domain", "url", "hash"],
    placeholder: "ENTER IP, DOMAIN, URL, OR MD5/SHA1/SHA256 HASH...",
    submitLabel: "ANALYZE ALL SOURCES",
    samples: [
      { label: "1.1.1.1", desc: "CLOUDFLARE DNS (IP)" },
      { label: "8.8.8.8", desc: "GOOGLE DNS (IP)" },
      { label: "example.com", desc: "DOMAIN + DNS/RDAP" },
      { label: "44d88612fea8a8f36de82e1278abb02f", desc: "EICAR MD5 HASH" },
    ],
    providerIds: undefined,
    defaultTab: "summary",
  },
  reputation: {
    title: "REPUTATION & AV ENGINES",
    subtitle:
      "SCOPED LOOKUP ACROSS VIRUSTOTAL AND ABUSEIPDB FOR MULTI-ENGINE VERDICTS AND IP ABUSE CONFIDENCE.",
    acceptedTypes: ["ip", "domain", "url", "hash"],
    placeholder: "ENTER IP, DOMAIN, URL, OR HASH FOR REPUTATION ENGINES...",
    submitLabel: "RUN REPUTATION CHECK",
    samples: [
      { label: "1.1.1.1", desc: "VT + ABUSEIPDB" },
      { label: "example.com", desc: "VT DOMAIN CHECK" },
      { label: "44d88612fea8a8f36de82e1278abb02f", desc: "VT HASH SCAN" },
    ],
    providerIds: PROVIDER_CATALOG.filter((p) => p.category === "reputation").map(
      (p) => p.id,
    ),
    defaultTab: "summary",
  },
  malware_feeds: {
    title: "ABUSE.CH MALWARE FEEDS SUITE",
    subtitle:
      "SCOPED LOOKUP ACROSS URLHAUS, THREATFOX, AND MALWAREBAZAAR FOR MALICIOUS URLS, C2S & SAMPLES.",
    acceptedTypes: ["ip", "domain", "url", "hash"],
    placeholder: "ENTER URL, DOMAIN, IP, OR FILE HASH FOR ABUSE.CH FEEDS...",
    submitLabel: "QUERY MALWARE FEEDS",
    samples: [
      { label: "hxxps[:]//example[.]com/payload", desc: "URLHAUS + THREATFOX" },
      { label: "44d88612fea8a8f36de82e1278abb02f", desc: "MALWAREBAZAAR + URLHAUS" },
      { label: "1.1.1.1", desc: "HOST / C2 CHECK" },
    ],
    providerIds: PROVIDER_CATALOG.filter(
      (p) => p.category === "malware_feeds",
    ).map((p) => p.id),
    defaultTab: "summary",
  },
  exposure_noise: {
    title: "EXPOSURE, PULSES & NOISE SUITE",
    subtitle:
      "SCOPED LOOKUP ACROSS ALIENVAULT OTX, SHODAN, AND GREYNOISE FOR PULSES, PORTS, CVES & SCANNER NOISE.",
    acceptedTypes: ["ip", "domain", "url", "hash"],
    placeholder: "ENTER IP OR DOMAIN (OR URL/HASH FOR OTX)...",
    submitLabel: "CHECK EXPOSURE & NOISE",
    samples: [
      { label: "8.8.8.8", desc: "OTX + SHODAN + GREYNOISE" },
      { label: "1.1.1.1", desc: "INFRASTRUCTURE RECON" },
      { label: "example.com", desc: "OTX + SHODAN DNS" },
    ],
    providerIds: PROVIDER_CATALOG.filter(
      (p) => p.category === "exposure_noise",
    ).map((p) => p.id),
    defaultTab: "summary",
  },
  network_osint: SINGLE_TOOL_PROFILES.network_rdap,
};

export function resolveToolProfile(
  category: ToolCategoryId,
  tool: ProviderId | null,
): ToolProfile {
  if (tool && SINGLE_TOOL_PROFILES[tool]) {
    return SINGLE_TOOL_PROFILES[tool];
  }
  return CATEGORY_PROFILES[category] || CATEGORY_PROFILES.all;
}
