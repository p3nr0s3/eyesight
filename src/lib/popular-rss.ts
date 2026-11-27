export interface PopularRssPreset {
  id: string;
  name: string;
  url: string;
  category: string;
  description: string;
}

export const POPULAR_RSS_FEEDS: PopularRssPreset[] = [
  {
    id: "preset-bleeping",
    name: "BleepingComputer",
    url: "https://www.bleepingcomputer.com/feed/",
    category: "THREAT NEWS",
    description: "Breaking ransomware, malware, and vulnerability coverage.",
  },
  {
    id: "preset-thn",
    name: "The Hacker News",
    url: "https://feeds.feedburner.com/TheHackersNews",
    category: "CYBER NEWS",
    description: "Daily cybersecurity breaches, zero-days, and threat alerts.",
  },
  {
    id: "preset-cisa",
    name: "CISA Advisories",
    url: "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    category: "ADVISORY",
    description: "Official US CISA ICS & cybersecurity vulnerability advisories.",
  },
  {
    id: "preset-krebs",
    name: "Krebs on Security",
    url: "https://krebsonsecurity.com/feed/",
    category: "INVESTIGATIONS",
    description: "Deep-dive cybercrime, fraud, and threat actor investigations.",
  },
  {
    id: "preset-sans",
    name: "SANS ISC Diary",
    url: "https://isc.sans.edu/rssfeed.xml",
    category: "THREAT INTEL",
    description: "Internet Storm Center handler diaries and traffic anomalies.",
  },
  {
    id: "preset-darkreading",
    name: "Dark Reading",
    url: "https://www.darkreading.com/rss.xml",
    category: "ENTERPRISE SEC",
    description: "Enterprise SecOps, cloud security, and threat intelligence.",
  },
  {
    id: "preset-unit42",
    name: "Palo Alto Unit 42",
    url: "https://unit42.paloaltonetworks.com/feed/",
    category: "THREAT RESEARCH",
    description: "APT group tracking, malware reverse engineering, and TTPs.",
  },
  {
    id: "preset-google-ti",
    name: "Google Cloud Threat Intel",
    url: "https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/",
    category: "APT INTEL",
    description: "Mandiant & Google TAG nation-state and ransomware briefings.",
  },
  {
    id: "preset-msrc",
    name: "Microsoft Security Blog",
    url: "https://www.microsoft.com/en-us/security/blog/feed/",
    category: "VENDOR INTEL",
    description: "Microsoft Threat Intelligence, Defender, and Patch advisories.",
  },
  {
    id: "preset-schneier",
    name: "Schneier on Security",
    url: "https://www.schneier.com/feed/atom/",
    category: "RESEARCH",
    description: "Cryptography, policy, and security architecture commentary.",
  },
  {
    id: "preset-securityweek",
    name: "SecurityWeek",
    url: "https://www.securityweek.com/feed/",
    category: "CYBER NEWS",
    description: "ICS/OT security, enterprise vulnerabilities, and vendor news.",
  },
  {
    id: "preset-talos",
    name: "Cisco Talos Intelligence",
    url: "https://blog.talosintelligence.com/rss/",
    category: "THREAT RESEARCH",
    description: "Talos vulnerability discoveries, malware analysis, and actor tracking.",
  },
  {
    id: "preset-malwarebytes",
    name: "Malwarebytes Labs",
    url: "https://www.malwarebytes.com/blog/feed/index.xml",
    category: "MALWARE",
    description: "Malware teardowns, phishing campaigns, and threat advisories.",
  },
];
