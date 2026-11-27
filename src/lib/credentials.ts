import { fetchJsonWithTimeout } from "@/lib/providers/http";
import {
  getDarkwebIntelSnapshot,
  type BreachRecord,
  type RansomwareVictim,
} from "@/lib/darkweb";

export interface CombCredentialRecord {
  index: number;
  identifier: string;
  domain: string | null;
  secret: string;
  rawLine: string;
  sourceCorpus: string;
  leakDate: string | null;
  evidenceSource: string | null;
  evidenceUrl: string | null;
}

export interface RansomLookDumpEvidence {
  id: number | string;
  domain: string;
  indexedDate: string | null;
  records: string | null;
  size: string | null;
  columns: string[];
  sourceUrl: string;
}

export interface CredentialLeakEvidence {
  timelineSummary: {
    earliestDate: string | null;
    latestDate: string | null;
    totalEvidenceSources: number;
  };
  ransomLookDumps: RansomLookDumpEvidence[];
  hibpMatches: BreachRecord[];
  xonCatalogMatches: LiveGlobalBreachItem[];
  ransomwareHits: RansomwareVictim[];
}

export interface InfostealerHostHit {
  dateCompromised: string;
  stealerFamily: string | null;
  computerName: string;
  operatingSystem: string;
  malwarePath: string;
  antiviruses: string[];
  ip: string;
  totalCorporateServices: number;
  totalUserServices: number;
  topLogins: string[];
  topPasswords: string[];
}

export interface LeakCheckSource {
  name: string;
  date: string;
}

export interface LeakCheckIntel {
  found: number;
  fields: string[];
  sources: LeakCheckSource[];
}

export interface LiveGlobalBreachItem {
  breachId: string;
  domain: string;
  breachedDate: string;
  addedDate: string;
  exposedRecords: number;
  passwordRisk: string;
  industry: string;
  breachType: string;
  verified: boolean;
  exposedData: string[];
  description: string;
  referenceUrl: string | null;
}

export interface InfostealerDomainIntel {
  domain: string;
  total: number;
  employees: number;
  users: number;
  thirdParties: number;
  lastEmployeeCompromised: string | null;
  lastUserCompromised: string | null;
  stealerFamilies: Array<{ family: string; count: number }>;
  employeePasswords: {
    total: number;
    tooWeakPct: number;
    weakPct: number;
    mediumPct: number;
    strongPct: number;
  } | null;
  employeeUrls: Array<{ url: string; occurrence: number }>;
  clientUrls: Array<{ url: string; occurrence: number }>;
  antivirusStats: {
    total: number;
    foundPct: number;
    notFoundPct: number;
    topAvs: Array<{ name: string; count: number }>;
  } | null;
  exposedApplications: Array<{ keyword: string; count: number }>;
}

export interface XonExposedBreach {
  breach: string;
  domain: string;
  xposedDate: string;
  added: string;
  xposedRecords: number;
  passwordRisk: string;
  industry: string;
  verified: boolean;
  xposedData: string[];
  details: string;
  reference: string | null;
}

export interface XonEmailIntel {
  email: string;
  riskScore: number | null;
  riskLabel: string | null;
  passwordStrength: {
    easyToCrack: number;
    plainText: number;
    strongHash: number;
    unknown: number;
  } | null;
  breaches: XonExposedBreach[];
}

export interface CredentialLeakReport {
  query: string;
  queryKind: "email" | "domain" | "username";
  comb: {
    available: boolean;
    totalCount: number;
    start: number;
    limit: number;
    records: CombCredentialRecord[];
    note: string | null;
  };
  hudsonRockDomain: InfostealerDomainIntel | null;
  hudsonRockEmail: {
    message: string | null;
    totalCorporateServices: number;
    totalUserServices: number;
    hosts: InfostealerHostHit[];
  } | null;
  xposedOrNot: XonEmailIntel | null;
  leakCheck: LeakCheckIntel | null;
  evidence: CredentialLeakEvidence;
  fetchedAt: string;
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const DOMAIN_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;

export function detectCredentialQueryKind(
  q: string,
): "email" | "domain" | "username" {
  const trimmed = q.trim();
  if (EMAIL_RE.test(trimmed)) return "email";
  if (DOMAIN_RE.test(trimmed)) return "domain";
  return "username";
}

export function parseCombLine(
  line: string,
  index: number,
): CombCredentialRecord {
  const sepIdx = line.indexOf(":");
  const identifier = sepIdx >= 0 ? line.slice(0, sepIdx) : line;
  const secret = sepIdx >= 0 ? line.slice(sepIdx + 1) : "";
  const atIdx = identifier.indexOf("@");
  const domain =
    atIdx >= 0 && atIdx < identifier.length - 1
      ? identifier.slice(atIdx + 1).toLowerCase()
      : null;

  return {
    index,
    identifier,
    domain,
    secret,
    rawLine: line,
    sourceCorpus: "COMB (Compilation of Many Breaches · 2021)",
    leakDate: null,
    evidenceSource: "COMB 2021 Merged Breach Corpus",
    evidenceUrl: null,
  };
}

interface RawCombResponse {
  count?: number;
  lines?: string[];
  error?: string;
}

interface RawRansomLookLeakDetail {
  id?: string | number;
  name?: string;
  group?: {
    columns?: string[];
    indexed?: string;
    records?: string | number;
    size?: string;
  };
}

interface RawHudsonRockDomain {
  total?: number;
  employees?: number;
  users?: number;
  third_parties?: number;
  last_employee_compromised?: string;
  last_user_compromised?: string;
  stealerFamilies?: Record<string, number>;
  antiviruses?: {
    total?: number;
    found?: number;
    not_found?: number;
    list?: Array<{ name?: string; count?: number }>;
  };
  applications?: Array<{ keyword?: string; count?: number }>;
  employeePasswords?: {
    totalPass?: number;
    too_weak?: { perc?: number };
    weak?: { perc?: number };
    medium?: { perc?: number };
    strong?: { perc?: number };
  };
  data?: {
    employees_urls?: Array<{ url?: string; occurrence?: number }>;
    clients_urls?: Array<{ url?: string; occurrence?: number }>;
  };
}

interface RawHudsonRockEmail {
  message?: string;
  total_corporate_services?: number;
  total_user_services?: number;
  stealers?: Array<{
    date_compromised?: string;
    stealer_family?: string;
    computer_name?: string;
    operating_system?: string;
    malware_path?: string;
    antiviruses?: string[];
    ip?: string;
    total_corporate_services?: number;
    total_user_services?: number;
    top_logins?: string[];
    top_passwords?: string[];
  }>;
}

interface RawLeakCheckResponse {
  success?: boolean;
  found?: number;
  fields?: string[];
  sources?: Array<{ name?: string; date?: string }>;
}

interface RawXonGlobalBreachesResponse {
  exposedBreaches?: Array<{
    breachID?: string;
    domain?: string;
    breachedDate?: string;
    addedDate?: string;
    exposedRecords?: number;
    passwordRisk?: string;
    industry?: string;
    breachType?: string;
    verified?: boolean;
    exposedData?: string[];
    exposureDescription?: string;
    referenceURL?: string;
  }>;
}

const globalForGlobalBreaches = globalThis as unknown as {
  __eyesightXonGlobalCache?: {
    data: LiveGlobalBreachItem[];
    expiresAt: number;
  };
};

export async function getLiveGlobalBreachesSnapshot(
  forceRefresh = false,
): Promise<LiveGlobalBreachItem[]> {
  if (
    !forceRefresh &&
    globalForGlobalBreaches.__eyesightXonGlobalCache &&
    globalForGlobalBreaches.__eyesightXonGlobalCache.expiresAt > Date.now()
  ) {
    return globalForGlobalBreaches.__eyesightXonGlobalCache.data;
  }

  const res = await fetchJsonWithTimeout<RawXonGlobalBreachesResponse>(
    "https://api.xposedornot.com/v1/breaches",
    { cache: "no-store" },
    9000,
  );
  const rawList =
    res.ok && Array.isArray(res.data?.exposedBreaches)
      ? res.data.exposedBreaches
      : [];

  const sorted = rawList
    .filter((b) => b.breachID)
    .map((b) => ({
      breachId: b.breachID!,
      domain: (b.domain || "").trim(),
      breachedDate: b.breachedDate || "",
      addedDate: b.addedDate || b.breachedDate || "",
      exposedRecords: Number(b.exposedRecords || 0),
      passwordRisk: b.passwordRisk || "unknown",
      industry: b.industry || "",
      breachType: b.breachType || "DataBreach",
      verified: Boolean(b.verified),
      exposedData: Array.isArray(b.exposedData) ? b.exposedData : [],
      description: (b.exposureDescription || "").trim(),
      referenceUrl: b.referenceURL?.trim() || null,
    }))
    .sort((a, b) => {
      const tb = Date.parse(b.addedDate || b.breachedDate) || 0;
      const ta = Date.parse(a.addedDate || a.breachedDate) || 0;
      return tb - ta;
    });

  if (sorted.length > 0) {
    globalForGlobalBreaches.__eyesightXonGlobalCache = {
      data: sorted,
      expiresAt: Date.now() + 60 * 1000,
    };
  }
  return sorted;
}

interface RawXonResponse {
  Error?: string;
  BreachMetrics?: {
    risk?: Array<{ risk_label?: string; risk_score?: number }>;
    passwords_strength?: Array<{
      EasyToCrack?: number;
      PlainText?: number;
      StrongHash?: number;
      Unknown?: number;
    }>;
  };
  ExposedBreaches?: {
    breaches_details?: Array<{
      breach?: string;
      domain?: string;
      xposed_date?: string;
      added?: string;
      xposed_records?: number;
      password_risk?: string;
      industry?: string;
      verified?: string;
      xposed_data?: string;
      details?: string;
      references?: string;
    }>;
  } | null;
}

export async function searchCredentialLeaks(
  query: string,
  options?: { start?: number; limit?: number; forceRefresh?: boolean },
): Promise<CredentialLeakReport> {
  const cleanQuery = query.trim();
  const start = Math.max(0, Math.floor(options?.start ?? 0));
  const limit = Math.min(100, Math.max(10, Math.floor(options?.limit ?? 50)));
  const forceRefresh = Boolean(options?.forceRefresh);
  const queryKind = detectCredentialQueryKind(cleanQuery);

  const combUrl = `https://api.proxynova.com/comb?query=${encodeURIComponent(cleanQuery)}&start=${start}&limit=${limit}`;
  const domainTarget =
    queryKind === "domain"
      ? cleanQuery.toLowerCase()
      : queryKind === "email"
        ? cleanQuery.split("@")[1]?.toLowerCase() || null
        : null;

  const hrHostUrl =
    queryKind === "email"
      ? `https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email=${encodeURIComponent(cleanQuery)}`
      : queryKind === "username"
        ? `https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-username?username=${encodeURIComponent(cleanQuery)}`
        : null;

  const [
    combRes,
    hrDomainRes,
    hrEmailRes,
    xonRes,
    leakCheckRes,
    xonGlobalList,
    darkwebSnap,
  ] = await Promise.all([
    fetchJsonWithTimeout<RawCombResponse>(combUrl, { cache: "no-store" }, 10000),
    domainTarget
      ? fetchJsonWithTimeout<RawHudsonRockDomain>(
          `https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain=${encodeURIComponent(domainTarget)}`,
          { cache: "no-store" },
          9000,
        )
      : Promise.resolve(null),
    hrHostUrl
      ? fetchJsonWithTimeout<RawHudsonRockEmail>(
          hrHostUrl,
          { cache: "no-store" },
          9000,
        )
      : Promise.resolve(null),
    queryKind === "email"
      ? fetchJsonWithTimeout<RawXonResponse>(
          `https://api.xposedornot.com/v1/breach-analytics?email=${encodeURIComponent(cleanQuery)}`,
          { cache: "no-store" },
          10000,
        )
      : Promise.resolve(null),
    fetchJsonWithTimeout<RawLeakCheckResponse>(
      `https://leakcheck.io/api/public?check=${encodeURIComponent(cleanQuery)}`,
      { cache: "no-store" },
      9000,
    ),
    getLiveGlobalBreachesSnapshot(forceRefresh).catch(() => []),
    getDarkwebIntelSnapshot(forceRefresh).catch(() => null),
  ]);

  const combLines =
    combRes.ok && Array.isArray(combRes.data?.lines) ? combRes.data.lines : [];
  const rawCombRecords = combLines.map((line, i) =>
    parseCombLine(String(line), start + i + 1),
  );

  // Correlate HIBP breaches, RansomLook indexed DB dumps, and ransomware hits for leak dates & evidence
  const needle = (domainTarget || cleanQuery).toLowerCase();
  const baseBrand = needle.includes(".") ? needle.split(".")[0] : needle;

  const hibpMatches: BreachRecord[] = darkwebSnap
    ? darkwebSnap.breaches
        .filter((b) => {
          const dom = b.domain.toLowerCase();
          const title = b.title.toLowerCase();
          const name = b.name.toLowerCase();
          return (
            (domainTarget && (dom === domainTarget || dom.endsWith(`.${domainTarget}`))) ||
            dom.includes(needle) ||
            name === baseBrand ||
            title.toLowerCase().includes(needle)
          );
        })
        .slice(0, 15)
    : [];

  const matchedLeakEntries = darkwebSnap
    ? darkwebSnap.leakedDomains
        .filter((d) => {
          const dom = d.domain.toLowerCase();
          return (
            (domainTarget && dom === domainTarget) ||
            dom.includes(needle) ||
            rawCombRecords.some((r) => r.domain && dom === r.domain)
          );
        })
        .slice(0, 3)
    : [];

  const ransomLookDumps: RansomLookDumpEvidence[] = await Promise.all(
    matchedLeakEntries.map(async (entry) => {
      const url = `https://www.ransomlook.io/leak/${encodeURIComponent(String(entry.id))}`;
      const meta = await fetchJsonWithTimeout<RawRansomLookLeakDetail>(
        url,
        {},
        5000,
      );
      return {
        id: entry.id,
        domain: entry.domain,
        indexedDate: meta.data?.group?.indexed || null,
        records:
          meta.data?.group?.records !== undefined
            ? String(meta.data.group.records)
            : null,
        size: meta.data?.group?.size || null,
        columns: Array.isArray(meta.data?.group?.columns)
          ? meta.data.group.columns
          : [],
        sourceUrl: url,
      };
    }),
  );

  const xonCatalogMatches: LiveGlobalBreachItem[] = xonGlobalList
    .filter((b) => {
      const dom = b.domain.toLowerCase();
      const id = b.breachId.toLowerCase();
      return (
        (domainTarget &&
          (dom === domainTarget || dom.endsWith(`.${domainTarget}`))) ||
        dom.includes(needle) ||
        id.includes(baseBrand)
      );
    })
    .slice(0, 15);

  const ransomwareHits: RansomwareVictim[] = darkwebSnap
    ? darkwebSnap.victims
        .filter(
          (v) =>
            v.victim.toLowerCase().includes(needle) ||
            (v.extractedDomain &&
              v.extractedDomain.toLowerCase().includes(needle)) ||
            v.description.toLowerCase().includes(needle),
        )
        .slice(0, 10)
    : [];

  // Map domain -> best breach evidence & date for enriching COMB rows
  const domainEvidenceMap = new Map<
    string,
    { date: string | null; source: string; url: string | null }
  >();
  for (const dump of ransomLookDumps) {
    const key = dump.domain.toLowerCase();
    const parts = [
      `RansomLook Dump`,
      dump.indexedDate ? `Indexed: ${dump.indexedDate}` : null,
      dump.records ? `${dump.records} rows` : null,
      dump.size ? dump.size : null,
    ].filter(Boolean);
    domainEvidenceMap.set(key, {
      date: dump.indexedDate,
      source: parts.join(" · "),
      url: dump.sourceUrl,
    });
  }
  for (const b of hibpMatches) {
    const key = b.domain.toLowerCase();
    if (!key) continue;
    const prev = domainEvidenceMap.get(key);
    const hibpSummary = `HIBP ${b.title} (${b.breachDate || b.addedDate.slice(0, 10)} · ${b.pwnCount.toLocaleString()} records)`;
    domainEvidenceMap.set(key, {
      date: b.breachDate || prev?.date || null,
      source: prev ? `${hibpSummary} · ${prev.source}` : hibpSummary,
      url: prev?.url || `https://haveibeenpwned.com/PwnedWebsites#${encodeURIComponent(b.name)}`,
    });
  }

  const enrichedCombRecords: CombCredentialRecord[] = rawCombRecords.map((rec) => {
    const domEv = rec.domain ? domainEvidenceMap.get(rec.domain) : undefined;
    const queryEv = !domEv && domainTarget ? domainEvidenceMap.get(domainTarget) : undefined;
    const ev = domEv || queryEv;
    return {
      ...rec,
      leakDate: ev?.date || null,
      evidenceSource: ev?.source || rec.evidenceSource,
      evidenceUrl: ev?.url || null,
    };
  });

  const comb = {
    available: combRes.ok && !combRes.data?.error,
    totalCount: Number(combRes.data?.count || 0),
    start,
    limit,
    records: enrichedCombRecords,
    note: !combRes.ok
      ? `PROXYNOVA COMB RETURNED HTTP ${combRes.status || "ERROR"}.`
      : combRes.data?.error || null,
  };

  let hudsonRockDomain: InfostealerDomainIntel | null = null;
  if (hrDomainRes?.ok && hrDomainRes.data && domainTarget) {
    const d = hrDomainRes.data;
    const families = Object.entries(d.stealerFamilies || {})
      .filter(([name]) => name.toLowerCase() !== "total")
      .map(([family, count]) => ({ family, count: Number(count || 0) }))
      .filter((f) => f.count > 0)
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    hudsonRockDomain = {
      domain: domainTarget,
      total: Number(d.total || 0),
      employees: Number(d.employees || 0),
      users: Number(d.users || 0),
      thirdParties: Number(d.third_parties || 0),
      lastEmployeeCompromised: d.last_employee_compromised || null,
      lastUserCompromised: d.last_user_compromised || null,
      stealerFamilies: families,
      employeePasswords: d.employeePasswords?.totalPass
        ? {
            total: Number(d.employeePasswords.totalPass || 0),
            tooWeakPct: Number(d.employeePasswords.too_weak?.perc || 0),
            weakPct: Number(d.employeePasswords.weak?.perc || 0),
            mediumPct: Number(d.employeePasswords.medium?.perc || 0),
            strongPct: Number(d.employeePasswords.strong?.perc || 0),
          }
        : null,
      employeeUrls: (d.data?.employees_urls || [])
        .filter((u) => u.url)
        .slice(0, 12)
        .map((u) => ({ url: u.url!, occurrence: Number(u.occurrence || 0) })),
      clientUrls: (d.data?.clients_urls || [])
        .filter((u) => u.url)
        .slice(0, 12)
        .map((u) => ({ url: u.url!, occurrence: Number(u.occurrence || 0) })),
      antivirusStats: d.antiviruses
        ? {
            total: Number(d.antiviruses.total || 0),
            foundPct: Number(d.antiviruses.found || 0),
            notFoundPct: Number(d.antiviruses.not_found || 0),
            topAvs: (d.antiviruses.list || [])
              .filter((a) => a.name && a.name !== "-")
              .slice(0, 6)
              .map((a) => ({ name: a.name!, count: Number(a.count || 0) })),
          }
        : null,
      exposedApplications: (d.applications || [])
        .filter((a) => a.keyword)
        .slice(0, 8)
        .map((a) => ({
          keyword: a.keyword!,
          count: Number(a.count || 0),
        })),
    };
  }

  let hudsonRockEmail: CredentialLeakReport["hudsonRockEmail"] = null;
  if (hrEmailRes?.ok && hrEmailRes.data) {
    const d = hrEmailRes.data;
    const hosts: InfostealerHostHit[] = (d.stealers || []).map((s) => ({
      dateCompromised: s.date_compromised || "",
      stealerFamily: s.stealer_family || null,
      computerName: s.computer_name || "Unknown",
      operatingSystem: s.operating_system || "Unknown",
      malwarePath: s.malware_path || "Unknown",
      antiviruses: Array.isArray(s.antiviruses) ? s.antiviruses : [],
      ip: s.ip || "Unknown",
      totalCorporateServices: Number(s.total_corporate_services || 0),
      totalUserServices: Number(s.total_user_services || 0),
      topLogins: (s.top_logins || []).filter(Boolean),
      topPasswords: (s.top_passwords || []).filter(Boolean),
    }));
    hudsonRockEmail = {
      message: d.message || null,
      totalCorporateServices: Number(d.total_corporate_services || 0),
      totalUserServices: Number(d.total_user_services || 0),
      hosts,
    };
  }

  let leakCheck: LeakCheckIntel | null = null;
  if (leakCheckRes?.ok && leakCheckRes.data?.success) {
    const lc = leakCheckRes.data;
    const sources: LeakCheckSource[] = (lc.sources || [])
      .filter((s) => s.name)
      .map((s) => ({
        name: s.name!,
        date: (s.date || "").trim(),
      }))
      .sort((a, b) => (b.date || "0000").localeCompare(a.date || "0000"));
    leakCheck = {
      found: Number(lc.found || 0),
      fields: Array.isArray(lc.fields) ? lc.fields : [],
      sources,
    };
  }

  let xposedOrNot: XonEmailIntel | null = null;
  if (xonRes?.ok && xonRes.data && !xonRes.data.Error) {
    const rawRisk = xonRes.data.BreachMetrics?.risk?.[0];
    const rawStrength = xonRes.data.BreachMetrics?.passwords_strength?.[0];
    const details = xonRes.data.ExposedBreaches?.breaches_details || [];
    const breaches: XonExposedBreach[] = [...details]
      .sort((a, b) => {
        const ta = Date.parse(a.added || a.xposed_date || "") || 0;
        const tb = Date.parse(b.added || b.xposed_date || "") || 0;
        return tb - ta;
      })
      .map((b) => ({
        breach: b.breach || "Unknown",
        domain: b.domain || "",
        xposedDate: b.xposed_date || "",
        added: b.added || "",
        xposedRecords: Number(b.xposed_records || 0),
        passwordRisk: b.password_risk || "unknown",
        industry: b.industry || "",
        verified: String(b.verified || "").toLowerCase() === "yes",
        xposedData: (b.xposed_data || "")
          .split(";")
          .map((s) => s.trim())
          .filter(Boolean),
        details: (b.details || "").trim(),
        reference: b.references?.trim() || null,
      }));

    xposedOrNot = {
      email: cleanQuery,
      riskScore:
        rawRisk?.risk_score !== undefined ? Number(rawRisk.risk_score) : null,
      riskLabel: rawRisk?.risk_label || null,
      passwordStrength: rawStrength
        ? {
            easyToCrack: Number(rawStrength.EasyToCrack || 0),
            plainText: Number(rawStrength.PlainText || 0),
            strongHash: Number(rawStrength.StrongHash || 0),
            unknown: Number(rawStrength.Unknown || 0),
          }
        : null,
      breaches,
    };
  }

  const candidateDates: Array<{ ts: number; label: string }> = [];
  const pushDate = (raw: string | null | undefined) => {
    if (!raw) return;
    const ms = Date.parse(raw);
    if (!Number.isNaN(ms) && ms > 0) {
      candidateDates.push({ ts: ms, label: raw.slice(0, 10) });
    }
  };

  for (const b of hibpMatches) pushDate(b.breachDate || b.addedDate);
  for (const b of xonCatalogMatches) pushDate(b.addedDate || b.breachedDate);
  for (const d of ransomLookDumps) pushDate(d.indexedDate);
  for (const v of ransomwareHits) pushDate(v.discovered);
  if (leakCheck) {
    for (const s of leakCheck.sources) {
      if (s.date) pushDate(s.date.length === 7 ? `${s.date}-01` : s.date);
    }
  }
  if (hudsonRockDomain) {
    pushDate(hudsonRockDomain.lastEmployeeCompromised);
    pushDate(hudsonRockDomain.lastUserCompromised);
  }
  if (hudsonRockEmail) {
    for (const h of hudsonRockEmail.hosts) pushDate(h.dateCompromised);
  }
  if (xposedOrNot) {
    for (const b of xposedOrNot.breaches) pushDate(b.added || b.xposedDate);
  }
  candidateDates.sort((a, b) => a.ts - b.ts);

  const totalEvidenceSources =
    (comb.records.length > 0 ? 1 : 0) +
    (ransomLookDumps.length > 0 ? 1 : 0) +
    (hibpMatches.length > 0 ? 1 : 0) +
    (xonCatalogMatches.length > 0 ? 1 : 0) +
    (leakCheck && leakCheck.found > 0 ? 1 : 0) +
    (hudsonRockDomain && hudsonRockDomain.total > 0 ? 1 : 0) +
    (hudsonRockEmail && hudsonRockEmail.hosts.length > 0 ? 1 : 0) +
    (xposedOrNot && xposedOrNot.breaches.length > 0 ? 1 : 0) +
    (ransomwareHits.length > 0 ? 1 : 0);

  return {
    query: cleanQuery,
    queryKind,
    comb,
    hudsonRockDomain,
    hudsonRockEmail,
    xposedOrNot,
    leakCheck,
    evidence: {
      timelineSummary: {
        earliestDate: candidateDates[0]?.label || null,
        latestDate: candidateDates[candidateDates.length - 1]?.label || null,
        totalEvidenceSources,
      },
      ransomLookDumps,
      hibpMatches,
      xonCatalogMatches,
      ransomwareHits,
    },
    fetchedAt: new Date().toISOString(),
  };
}
