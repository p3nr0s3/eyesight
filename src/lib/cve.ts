import { fetchJsonWithTimeout } from "@/lib/providers/http";

export type CveSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE" | "UNKNOWN";

export interface KevEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction: string;
  dueDate: string;
  knownRansomwareCampaignUse: string;
  notes?: string;
}

export interface CveRecord {
  id: string;
  published: string;
  lastModified: string;
  description: string;
  cvssScore: number | null;
  cvssVector: string | null;
  severity: CveSeverity;
  cwes: string[];
  references: string[];
  affectedProducts: string[];
  activeExploit: KevEntry | null;
  source: "nvd" | "circl" | "kev";
}

export interface CveDashboardData {
  top10Latest: CveRecord[];
  activeExploits: KevEntry[];
  stats: {
    totalKevCount: number;
    ransomwareKevCount: number;
    latestPublishedAt: string | null;
    latestKevDateAdded: string | null;
    criticalInLatestCount: number;
    highestCvssInLatest: number | null;
  };
  fetchedAt: string;
}

interface CacheEntry<T> {
  data: T;
  expiresAt: number;
}

const globalForCve = globalThis as unknown as {
  __eyesightKevCache?: CacheEntry<{ list: KevEntry[]; map: Map<string, KevEntry> }>;
  __eyesightDashboardCache?: CacheEntry<CveDashboardData>;
  __eyesightSearchCache?: Map<string, CacheEntry<CveRecord[]>>;
};

const KEV_TTL_MS = 15 * 60 * 1000;
const DASHBOARD_TTL_MS = 10 * 60 * 1000;
const SEARCH_TTL_MS = 5 * 60 * 1000;

export function scoreToSeverity(score: number | null): CveSeverity {
  if (score === null || Number.isNaN(score)) return "UNKNOWN";
  if (score >= 9.0) return "CRITICAL";
  if (score >= 7.0) return "HIGH";
  if (score >= 4.0) return "MEDIUM";
  if (score > 0) return "LOW";
  return "NONE";
}

export function sortCvesLatestFirst(items: CveRecord[]): CveRecord[] {
  return [...items].sort((a, b) => {
    const ta = Date.parse(a.published) || 0;
    const tb = Date.parse(b.published) || 0;
    if (tb !== ta) return tb - ta;
    return b.id.localeCompare(a.id);
  });
}

export function sortKevLatestFirst(items: KevEntry[]): KevEntry[] {
  return [...items].sort((a, b) => {
    const ta = Date.parse(a.dateAdded) || 0;
    const tb = Date.parse(b.dateAdded) || 0;
    if (tb !== ta) return tb - ta;
    return b.cveID.localeCompare(a.cveID);
  });
}

function getNvdHeaders(): Record<string, string> {
  const apiKey = process.env.NVD_API_KEY?.trim();
  return apiKey ? { apiKey } : {};
}

interface NvdCveWrapper {
  cve?: {
    id?: string;
    published?: string;
    lastModified?: string;
    descriptions?: Array<{ lang?: string; value?: string }>;
    metrics?: {
      cvssMetricV31?: Array<{
        cvssData?: { baseScore?: number; vectorString?: string; baseSeverity?: string };
      }>;
      cvssMetricV30?: Array<{
        cvssData?: { baseScore?: number; vectorString?: string; baseSeverity?: string };
      }>;
      cvssMetricV2?: Array<{
        cvssData?: { baseScore?: number; vectorString?: string };
        baseSeverity?: string;
      }>;
    };
    weaknesses?: Array<{
      description?: Array<{ lang?: string; value?: string }>;
    }>;
    references?: Array<{ url?: string }>;
    configurations?: Array<{
      nodes?: Array<{
        cpeMatch?: Array<{ criteria?: string }>;
      }>;
    }>;
  };
}

function parseNvdVulnerability(
  wrapper: NvdCveWrapper,
  kevMap: Map<string, KevEntry>,
): CveRecord | null {
  const cve = wrapper.cve;
  if (!cve?.id) return null;

  const desc =
    cve.descriptions?.find((d) => d.lang === "en")?.value ||
    cve.descriptions?.[0]?.value ||
    "No description available.";

  const v31 = cve.metrics?.cvssMetricV31?.[0]?.cvssData;
  const v30 = cve.metrics?.cvssMetricV30?.[0]?.cvssData;
  const v2 = cve.metrics?.cvssMetricV2?.[0];

  const cvssScore =
    v31?.baseScore ?? v30?.baseScore ?? v2?.cvssData?.baseScore ?? null;
  const cvssVector =
    v31?.vectorString ?? v30?.vectorString ?? v2?.cvssData?.vectorString ?? null;
  const rawSeverity = (
    v31?.baseSeverity ||
    v30?.baseSeverity ||
    v2?.baseSeverity ||
    ""
  ).toUpperCase();

  const severity: CveSeverity = (
    ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"].includes(rawSeverity)
      ? rawSeverity
      : scoreToSeverity(cvssScore)
  ) as CveSeverity;

  const cwes = Array.from(
    new Set(
      (cve.weaknesses || [])
        .flatMap((w) => w.description || [])
        .map((d) => d.value)
        .filter((v): v is string => Boolean(v && v !== "NVD-CWE-noinfo")),
    ),
  ).slice(0, 5);

  const references = Array.from(
    new Set(
      (cve.references || [])
        .map((r) => r.url)
        .filter((u): u is string => Boolean(u)),
    ),
  ).slice(0, 8);

  const cpes = Array.from(
    new Set(
      (cve.configurations || [])
        .flatMap((c) => c.nodes || [])
        .flatMap((n) => n.cpeMatch || [])
        .map((m) => {
          const parts = (m.criteria || "").split(":");
          return parts.length >= 5 ? `${parts[3]} ${parts[4]}` : null;
        })
        .filter((v): v is string => Boolean(v && v !== "* *")),
    ),
  ).slice(0, 8);

  return {
    id: cve.id.toUpperCase(),
    published: cve.published || new Date(0).toISOString(),
    lastModified: cve.lastModified || cve.published || new Date(0).toISOString(),
    description: desc,
    cvssScore,
    cvssVector,
    severity,
    cwes,
    references,
    affectedProducts: cpes,
    activeExploit: kevMap.get(cve.id.toUpperCase()) ?? null,
    source: "nvd",
  };
}

interface CirclCve {
  id?: string;
  Published?: string;
  Modified?: string;
  summary?: string;
  cvss?: number | string;
  cvss3?: number | string;
  "cvss-vector"?: string;
  cwe?: string;
  references?: string[];
  cveMetadata?: {
    cveId?: string;
    datePublished?: string;
    dateUpdated?: string;
  };
  containers?: {
    cna?: {
      descriptions?: Array<{ lang?: string; value?: string }>;
      metrics?: Array<{
        cvssV3_1?: { baseScore?: number; vectorString?: string; baseSeverity?: string };
        cvssV3_0?: { baseScore?: number; vectorString?: string; baseSeverity?: string };
      }>;
      references?: Array<{ url?: string }>;
      affected?: Array<{ vendor?: string; product?: string }>;
    };
  };
}

function parseCirclVulnerability(
  item: CirclCve,
  kevMap: Map<string, KevEntry>,
): CveRecord | null {
  const id = (item.id || item.cveMetadata?.cveId || "").toUpperCase();
  if (!id.startsWith("CVE-")) return null;

  const cna = item.containers?.cna;
  const metricV31 = cna?.metrics?.find((m) => m.cvssV3_1)?.cvssV3_1;
  const metricV30 = cna?.metrics?.find((m) => m.cvssV3_0)?.cvssV3_0;

  const rawScore =
    metricV31?.baseScore ??
    metricV30?.baseScore ??
    (item.cvss3 !== undefined ? Number(item.cvss3) : undefined) ??
    (item.cvss !== undefined ? Number(item.cvss) : undefined);

  const cvssScore =
    rawScore !== undefined && !Number.isNaN(rawScore) ? rawScore : null;
  const cvssVector =
    metricV31?.vectorString ??
    metricV30?.vectorString ??
    item["cvss-vector"] ??
    null;

  const description =
    cna?.descriptions?.find((d) => d.lang?.startsWith("en"))?.value ||
    cna?.descriptions?.[0]?.value ||
    item.summary ||
    "No description available.";

  const published =
    item.cveMetadata?.datePublished ||
    item.Published ||
    new Date(0).toISOString();
  const lastModified =
    item.cveMetadata?.dateUpdated || item.Modified || published;

  const references = Array.from(
    new Set([
      ...(item.references || []),
      ...(cna?.references || []).map((r) => r.url).filter((u): u is string => Boolean(u)),
    ]),
  ).slice(0, 8);

  const affectedProducts = Array.from(
    new Set(
      (cna?.affected || [])
        .map((a) => [a.vendor, a.product].filter(Boolean).join(" ").trim())
        .filter(Boolean),
    ),
  ).slice(0, 8);

  return {
    id,
    published,
    lastModified,
    description,
    cvssScore,
    cvssVector,
    severity: scoreToSeverity(cvssScore),
    cwes: item.cwe && item.cwe !== "Unknown" ? [item.cwe] : [],
    references,
    affectedProducts,
    activeExploit: kevMap.get(id) ?? null,
    source: "circl",
  };
}

export async function getCisaKevCatalog(): Promise<{
  list: KevEntry[];
  map: Map<string, KevEntry>;
}> {
  const cached = globalForCve.__eyesightKevCache;
  if (cached && cached.expiresAt > Date.now()) {
    return cached.data;
  }

  const res = await fetchJsonWithTimeout<{
    vulnerabilities?: KevEntry[];
  }>(
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    {},
    9000,
  );

  if (res.ok && res.data?.vulnerabilities) {
    const sorted = sortKevLatestFirst(res.data.vulnerabilities);
    const map = new Map<string, KevEntry>();
    for (const v of sorted) {
      map.set(v.cveID.toUpperCase(), v);
    }
    const result = { list: sorted, map };
    globalForCve.__eyesightKevCache = {
      data: result,
      expiresAt: Date.now() + KEV_TTL_MS,
    };
    return result;
  }

  return cached?.data ?? { list: [], map: new Map() };
}

async function fetchLatestFromNvd(
  kevMap: Map<string, KevEntry>,
): Promise<CveRecord[]> {
  const now = new Date();
  const daysAgo = new Date(now.getTime() - 21 * 24 * 60 * 60 * 1000);
  const startIso = daysAgo.toISOString().replace(/\.\d{3}Z$/, ".000");
  const endIso = now.toISOString().replace(/\.\d{3}Z$/, ".000");

  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${encodeURIComponent(startIso)}&pubEndDate=${encodeURIComponent(endIso)}&resultsPerPage=100`;
  const res = await fetchJsonWithTimeout<{
    vulnerabilities?: NvdCveWrapper[];
  }>(url, { headers: getNvdHeaders() }, 8500);

  if (!res.ok || !res.data?.vulnerabilities?.length) {
    return [];
  }

  const parsed = res.data.vulnerabilities
    .map((v) => parseNvdVulnerability(v, kevMap))
    .filter((v): v is CveRecord => Boolean(v));

  return sortCvesLatestFirst(parsed);
}

async function fetchLatestFromCircl(
  kevMap: Map<string, KevEntry>,
): Promise<CveRecord[]> {
  const res = await fetchJsonWithTimeout<CirclCve[]>(
    "https://cve.circl.lu/api/last/25",
    {},
    8000,
  );
  if (!res.ok || !Array.isArray(res.data)) {
    return [];
  }
  const parsed = res.data
    .map((item) => parseCirclVulnerability(item, kevMap))
    .filter((v): v is CveRecord => Boolean(v));

  return sortCvesLatestFirst(parsed);
}

export async function getCveDashboardData(): Promise<CveDashboardData> {
  const cached = globalForCve.__eyesightDashboardCache;
  if (cached && cached.expiresAt > Date.now()) {
    return cached.data;
  }

  const kev = await getCisaKevCatalog();

  let latest = await fetchLatestFromNvd(kev.map);
  if (latest.length < 10) {
    const circl = await fetchLatestFromCircl(kev.map);
    if (circl.length > latest.length) {
      latest = circl;
    }
  }

  // Fallback to KEV-synthesized entries only if both NVD and CIRCL are unreachable
  if (latest.length === 0 && kev.list.length > 0) {
    latest = kev.list.slice(0, 10).map((k) => ({
      id: k.cveID,
      published: k.dateAdded,
      lastModified: k.dateAdded,
      description: k.shortDescription,
      cvssScore: null,
      cvssVector: null,
      severity: "HIGH" as CveSeverity,
      cwes: [],
      references: [],
      affectedProducts: [`${k.vendorProject} ${k.product}`.trim()],
      activeExploit: k,
      source: "kev" as const,
    }));
  }

  const top10Latest = sortCvesLatestFirst(latest).slice(0, 10);
  const scores = top10Latest
    .map((c) => c.cvssScore)
    .filter((s): s is number => s !== null);

  const dashboard: CveDashboardData = {
    top10Latest,
    activeExploits: kev.list.slice(0, 100),
    stats: {
      totalKevCount: kev.list.length,
      ransomwareKevCount: kev.list.filter(
        (k) => k.knownRansomwareCampaignUse?.toLowerCase() === "known",
      ).length,
      latestPublishedAt: top10Latest[0]?.published ?? null,
      latestKevDateAdded: kev.list[0]?.dateAdded ?? null,
      criticalInLatestCount: top10Latest.filter((c) => c.severity === "CRITICAL")
        .length,
      highestCvssInLatest: scores.length ? Math.max(...scores) : null,
    },
    fetchedAt: new Date().toISOString(),
  };

  globalForCve.__eyesightDashboardCache = {
    data: dashboard,
    expiresAt: Date.now() + DASHBOARD_TTL_MS,
  };

  return dashboard;
}

export async function searchCves(options: {
  query: string;
  severity?: string;
  kevOnly?: boolean;
}): Promise<CveRecord[]> {
  const q = options.query.trim();
  const kev = await getCisaKevCatalog();

  if (!q) {
    const dash = await getCveDashboardData();
    let base = dash.top10Latest;
    if (options.kevOnly) {
      base = kev.list.slice(0, 50).map((k) => ({
        id: k.cveID,
        published: k.dateAdded,
        lastModified: k.dateAdded,
        description: k.shortDescription,
        cvssScore: null,
        cvssVector: null,
        severity: "HIGH" as CveSeverity,
        cwes: [],
        references: [],
        affectedProducts: [`${k.vendorProject} ${k.product}`.trim()],
        activeExploit: k,
        source: "kev" as const,
      }));
    }
    if (options.severity && options.severity !== "ALL") {
      base = base.filter((c) => c.severity === options.severity);
    }
    return sortCvesLatestFirst(base);
  }

  const cacheKey = `${q.toLowerCase()}|${options.severity || "ALL"}|${Boolean(options.kevOnly)}`;
  if (!globalForCve.__eyesightSearchCache) {
    globalForCve.__eyesightSearchCache = new Map();
  }
  const hit = globalForCve.__eyesightSearchCache.get(cacheKey);
  if (hit && hit.expiresAt > Date.now()) {
    return hit.data;
  }

  const isExactCveId = /^CVE-\d{4}-\d{4,}$/i.test(q);
  let results: CveRecord[] = [];

  if (isExactCveId) {
    const cveUpper = q.toUpperCase();
    const nvdRes = await fetchJsonWithTimeout<{
      vulnerabilities?: NvdCveWrapper[];
    }>(
      `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveUpper)}`,
      { headers: getNvdHeaders() },
      8500,
    );
    if (nvdRes.ok && nvdRes.data?.vulnerabilities?.length) {
      results = nvdRes.data.vulnerabilities
        .map((v) => parseNvdVulnerability(v, kev.map))
        .filter((v): v is CveRecord => Boolean(v));
    }

    if (results.length === 0) {
      const circlRes = await fetchJsonWithTimeout<CirclCve>(
        `https://cve.circl.lu/api/cve/${encodeURIComponent(cveUpper)}`,
        {},
        7500,
      );
      if (circlRes.ok && circlRes.data) {
        const parsed = parseCirclVulnerability(circlRes.data, kev.map);
        if (parsed) results = [parsed];
      }
    }
  } else {
    const nvdRes = await fetchJsonWithTimeout<{
      vulnerabilities?: NvdCveWrapper[];
    }>(
      `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(q)}&resultsPerPage=60`,
      { headers: getNvdHeaders() },
      8500,
    );
    if (nvdRes.ok && nvdRes.data?.vulnerabilities?.length) {
      results = nvdRes.data.vulnerabilities
        .map((v) => parseNvdVulnerability(v, kev.map))
        .filter((v): v is CveRecord => Boolean(v));
    }

    // Merge matching KEV entries so active exploits matching vendor/product appear too
    const lowerQ = q.toLowerCase();
    const seenIds = new Set(results.map((r) => r.id));
    for (const k of kev.list) {
      if (
        k.cveID.toLowerCase().includes(lowerQ) ||
        k.vendorProject.toLowerCase().includes(lowerQ) ||
        k.product.toLowerCase().includes(lowerQ) ||
        k.vulnerabilityName.toLowerCase().includes(lowerQ)
      ) {
        if (!seenIds.has(k.cveID.toUpperCase())) {
          seenIds.add(k.cveID.toUpperCase());
          results.push({
            id: k.cveID.toUpperCase(),
            published: k.dateAdded,
            lastModified: k.dateAdded,
            description: k.shortDescription,
            cvssScore: null,
            cvssVector: null,
            severity: "HIGH",
            cwes: [],
            references: [],
            affectedProducts: [`${k.vendorProject} ${k.product}`.trim()],
            activeExploit: k,
            source: "kev",
          });
        }
      }
    }
  }

  let filtered = sortCvesLatestFirst(results);
  if (options.kevOnly) {
    filtered = filtered.filter((r) => Boolean(r.activeExploit));
  }
  if (options.severity && options.severity !== "ALL") {
    filtered = filtered.filter((r) => r.severity === options.severity);
  }

  globalForCve.__eyesightSearchCache.set(cacheKey, {
    data: filtered,
    expiresAt: Date.now() + SEARCH_TTL_MS,
  });

  return filtered;
}
