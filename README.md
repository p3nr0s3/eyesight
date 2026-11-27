# eyesight — Threat Intelligence & SOC Operations Hub

**eyesight** is a Threat Intelligence, Attack Surface, Darkweb Monitoring, and SOC Workbench console built with **Next.js (App Router, TypeScript, Tailwind CSS)** and **Drizzle ORM** (embedded **PGlite** locally, **PostgreSQL** in production).

## Core Modules

### 1. Unified IOC Investigation & Bulk Queue (`/`, `/bulk`)
- **Auto-Detection & Refang:** Detects and normalizes IPv4/IPv6, Domains, URLs, and MD5/SHA-1/SHA-256 hashes (`hxxps[:]//evil[.]com` → `https://evil.com`).
- **Multi-Provider Enrichment:** Zero-key live DNS/RDAP/GeoIP/ASN, GreyNoise, and abuse.ch feeds (URLhaus, ThreatFox, MalwareBazaar), enhanced optionally via VirusTotal, AbuseIPDB, AlienVault OTX, Shodan, GreyNoise, and abuse.ch Auth-Key.
- **Hybrid Key Management & Scoring:** Server environment keys, Admin DB encrypted keys, personal profile keys, browser BYOK overrides, configurable provider weights, TTL cache, and **JSON / CSV / STIX 2.1** export.
- **Client-Driven Bulk Queue (`/bulk`):** Chunked multi-IOC batch enrichment with Pause/Resume/Cancel controls and export.

### 2. Live Attack IOC Stream (`/attacks`)
- Real-time auto-syncing threat telemetry (`15s / 30s / 60s`) aggregating **SANS DShield**, **Shodan InternetDB** (open ports, CVEs, CPEs), **SANS IP ASN/Geo**, **abuse.ch Feodo Tracker**, **C2IntelFeeds** (30-day C2 IPs/Domains), **OpenPhish**, and **ThreatView** payload hashes with full forensic dossier modals and CSV/JSON export.

### 3. SOC Analyst Workbench (`/soc-tools`)
- **IOC Extractor & Defanger:** Extract and defang/refang IPs, domains, URLs, hashes, emails, and CVEs from raw logs/tickets.
- **Email Header Phishing Analyzer:** Inspect SPF/DKIM/DMARC verdicts, From/Return-Path/Reply-To spoofing mismatches, and chronological SMTP relay hops.
- **Payload Decoder & Hash Calculator:** Static Base64, PowerShell `-EncodedCommand` (UTF-16LE), URL, Hex, JWT inspector, plus Web Crypto SHA-256 / SHA-1 / SHA-512 hashing.
- **Subnet / CIDR Inspector:** Network/Broadcast/Netmask/Wildcard ACL masks & RFC1918 classification.
- **SIEM & Rule Generator:** Instant **Splunk SPL**, **Microsoft Sentinel KQL**, **Elastic KQL**, **Sigma YAML**, and **YARA** rules.
- **Incident Triage Playbooks:** Interactive checklists (Phishing, C2/Ransomware, Infostealer, Brute-Force) with Markdown report export.

### 4. Darkweb & Real-Time Credential Leak Monitoring (`/darkweb`)
- **Ransomware Leak Sites:** Country/sector/group analytics, victim pagination, CSV/JSON export, and near-fullscreen Victim Dossier modals (MISP UUID, Tor `.onion` paths, RansomLook links, proof previews, and IOC pivot).
- **Real-Time Credential Leaks (`?tab=credentials`):** Live **LeakCheck** breach & stealer log sources, **XposedOrNot** 2026 global breaches & email analytics, **Hudson Rock Cavalier** domain/email/username infostealer telemetry, **RansomLook** dump metadata (`/leak/<id>`), and uncensored historical **ProxyNova COMB** verification.
- **Watchlist Monitors:** Track organization domains, brands, VIP emails, and keywords continuously across darkweb feeds.

### 5. CVE Lookup & CISA KEV (`/cve`)
- Top 10 latest CVEs (`NVD` / `CIRCL`), confirmed in-the-wild exploited vulnerabilities (**CISA KEV**), latest-first search, pagination, and near-fullscreen CVE Dossier inspector.

### 6. Cybersecurity News & RSS Feeds (`/news`)
- Real-time security news & advisory aggregator with configurable popular/custom RSS feeds (`/settings/rss-feeds`), topic filtering, and pagination.

### 7. Investigation History, Theme & Appearance (`/history`, `/settings/*`)
- Searchable audit log (`/history`), multi-theme engine (`Obsidian Cyan`, `Midnight Matrix`, `Crimson Sentinel`, `Synthwave Violet`, `Arctic Slate`), custom fonts/sizing/corners (`/settings/appearance`), tools watchlist (`/settings/watchlist`), and REST API keys (`ey_...`).

## Local Development

```bash
npm install
npm run dev
```

No external database or Docker is required locally—**eyesight** automatically boots an embedded PostgreSQL instance via **PGlite** in `.eyesight-data/pglite`.

## Deployment

### Render
1. Connect this repository in Render and use the included `render.yaml` Blueprint (provisions the Node web service + managed PostgreSQL).
2. Add optional provider API keys (`VT_API_KEY`, `ABUSEIPDB_API_KEY`, etc.) in the Render dashboard.

### Vercel
1. Import this repository in Vercel.
2. Attach a PostgreSQL database (Neon, Supabase, or Vercel Postgres) and set `DATABASE_URL` + `ENCRYPTION_SECRET`.
3. Optionally set `AUTH_REQUIRED=true` and provider API keys in Environment Variables.

## Scripts

- `npm run dev` — Start local Next.js dev server
- `npm run build` — Production build
- `npm run lint` — Run ESLint (`eslint .`)
- `npm run typecheck` — Run TypeScript check (`tsc --noEmit`)
- `npm test` — Run Node test suite (`node --import ./scripts/register-alias.mjs --test src/lib/__tests__/*.test.ts`)
- `npm run db:push` — Push Drizzle schema to PostgreSQL
