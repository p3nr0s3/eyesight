import { fetchJsonWithTimeout } from "@/lib/providers/http";

export interface RansomwareVictim {
  victim: string;
  group: string;
  discovered: string;
  description: string;
  countryCode: string; // ISO alpha-2 or 'UNSPECIFIED'
  countryName: string;
  sector: string;
  extractedDomain: string | null;
  mispUuid: string | null;
  onionLink: string | null;
  hasMagnet: boolean;
  screenshotUrl: string | null;
  sourceUrl: string | null;
}

export interface BreachRecord {
  name: string;
  title: string;
  domain: string;
  breachDate: string;
  addedDate: string;
  pwnCount: number;
  description: string;
  dataClasses: string[];
  isVerified: boolean;
  isStealerLog: boolean;
}

export interface LeakedDomainEntry {
  id: number | string;
  domain: string;
  sourceUrl?: string;
}

export interface DarkwebInfraStats {
  groups: number;
  locations: number;
  dlsSites: number;
  fileServers: number;
  negotiationChats: number;
}

export interface DarkwebIntelSnapshot {
  victims: RansomwareVictim[];
  groups: string[];
  markets: string[];
  breaches: BreachRecord[];
  leakedDomains: LeakedDomainEntry[];
  infraStats: DarkwebInfraStats | null;
  topGroups: Array<{ name: string; count: number }>;
  topSectors: Array<{ name: string; count: number }>;
  topCountries: Array<{ code: string; name: string; count: number }>;
  stats: {
    recentVictimsCount: number;
    groupsCount: number;
    marketsCount: number;
    breachesCount: number;
    stealerBreachesCount: number;
    leakedDomainsCount: number;
    latestVictimDate: string | null;
    latestBreachDate: string | null;
  };
  fetchedAt: string;
}

export interface DarkwebSearchResult {
  query: string;
  victims: RansomwareVictim[];
  breaches: BreachRecord[];
  leakedDomains: LeakedDomainEntry[];
  groups: string[];
  markets: string[];
  emailBreaches: BreachRecord[] | null;
  emailLookupNote: string | null;
}

export interface MonitorEvaluation {
  matchCount: number;
  victimHits: RansomwareVictim[];
  breachHits: BreachRecord[];
  leakedDomainHits: LeakedDomainEntry[];
}

export const COUNTRY_CATALOG: Array<{ code: string; name: string }> = [
  { code: "ALL", name: "ALL COUNTRIES" },
  { code: "US", name: "UNITED STATES" },
  { code: "GB", name: "UNITED KINGDOM" },
  { code: "DE", name: "GERMANY" },
  { code: "FR", name: "FRANCE" },
  { code: "CA", name: "CANADA" },
  { code: "AU", name: "AUSTRALIA" },
  { code: "ID", name: "INDONESIA" },
  { code: "SG", name: "SINGAPORE" },
  { code: "JP", name: "JAPAN" },
  { code: "KR", name: "SOUTH KOREA" },
  { code: "IN", name: "INDIA" },
  { code: "BR", name: "BRAZIL" },
  { code: "NL", name: "NETHERLANDS" },
  { code: "IT", name: "ITALY" },
  { code: "ES", name: "SPAIN" },
  { code: "CH", name: "SWITZERLAND" },
  { code: "AE", name: "UNITED ARAB EMIRATES" },
  { code: "MY", name: "MALAYSIA" },
  { code: "TH", name: "THAILAND" },
  { code: "TW", name: "TAIWAN" },
  { code: "MX", name: "MEXICO" },
  { code: "PL", name: "POLAND" },
  { code: "SE", name: "SWEDEN" },
];

const COUNTRY_NAME_MAP = Object.fromEntries(
  COUNTRY_CATALOG.map((c) => [c.code, c.name]),
);

const TLD_COUNTRY_RULES: Array<[RegExp, string]> = [
  [/\.co\.id$|\.id$/i, "ID"],
  [/\.sg$|\.com\.sg$/i, "SG"],
  [/\.my$|\.com\.my$/i, "MY"],
  [/\.th$|\.co\.th$/i, "TH"],
  [/\.de$/i, "DE"],
  [/\.co\.uk$|\.uk$|\.org\.uk$/i, "GB"],
  [/\.fr$/i, "FR"],
  [/\.ca$/i, "CA"],
  [/\.com\.au$|\.au$/i, "AU"],
  [/\.co\.jp$|\.jp$/i, "JP"],
  [/\.co\.kr$|\.kr$/i, "KR"],
  [/\.in$|\.co\.in$/i, "IN"],
  [/\.com\.br$|\.br$/i, "BR"],
  [/\.nl$/i, "NL"],
  [/\.it$/i, "IT"],
  [/\.es$/i, "ES"],
  [/\.ch$/i, "CH"],
  [/\.ae$/i, "AE"],
  [/\.com\.tw$|\.tw$/i, "TW"],
  [/\.com\.mx$|\.mx$/i, "MX"],
  [/\.pl$/i, "PL"],
  [/\.se$/i, "SE"],
  [/\.gov$|\.mil$/i, "US"],
];

const TEXT_COUNTRY_RULES: Array<[RegExp, string]> = [
  [/\b(indonesia|jakarta|surabaya|bandung)\b/i, "ID"],
  [/\b(singapore)\b/i, "SG"],
  [/\b(malaysia|kuala lumpur)\b/i, "MY"],
  [/\b(thailand|bangkok)\b/i, "TH"],
  [/\b(united states|u\.s\.a\.|usa|california|texas|new york|florida|illinois|ohio|virginia|massachusetts|washington)\b/i, "US"],
  [/\b(united kingdom|england|scotland|london|manchester|birmingham)\b/i, "GB"],
  [/\b(germany|deutschland|berlin|munich|bremen|hamburg|frankfurt|gmbh)\b/i, "DE"],
  [/\b(france|paris|lyon|marseille|s\.a\.s\.|sarl)\b/i, "FR"],
  [/\b(canada|toronto|ontario|quebec|vancouver|alberta)\b/i, "CA"],
  [/\b(australia|sydney|melbourne|brisbane|pty ltd)\b/i, "AU"],
  [/\b(japan|tokyo|osaka)\b/i, "JP"],
  [/\b(south korea|seoul)\b/i, "KR"],
  [/\b(india|mumbai|bangalore|bengaluru|delhi|hyderabad)\b/i, "IN"],
  [/\b(brazil|brasil|sao paulo|rio de janeiro|ltda)\b/i, "BR"],
  [/\b(netherlands|holland|amsterdam|rotterdam|b\.v\.)\b/i, "NL"],
  [/\b(italy|italia|milan|rome|s\.r\.l\.|s\.p\.a\.)\b/i, "IT"],
  [/\b(spain|madrid|barcelona|s\.l\.)\b/i, "ES"],
  [/\b(switzerland|zurich|geneva|basel)\b/i, "CH"],
  [/\b(united arab emirates|dubai|abu dhabi|uae)\b/i, "AE"],
  [/\b(taiwan|taipei)\b/i, "TW"],
  [/\b(mexico|ciudad de mexico)\b/i, "MX"],
  [/\b(poland|warsaw)\b/i, "PL"],
  [/\b(sweden|stockholm)\b/i, "SE"],
];

const SECTOR_RULES: Array<[RegExp, string]> = [
  [/\b(health|hospital|clinic|medical|pharma|dental|patient|care|klinik|biotech)\b/i, "HEALTHCARE"],
  [/\b(university|school|college|academy|education|student|campus)\b/i, "EDUCATION"],
  [/\b(bank|finance|financial|insurance|capital|credit|invest|accounting|tax|fintech)\b/i, "FINANCE"],
  [/\b(government|ministry|city of|municipality|county|police|public sector|council|defense)\b/i, "GOVERNMENT"],
  [/\b(manufactur|industrial|steel|automotive|aerospace|factory|machinery|engineering|chemical)\b/i, "MANUFACTURING"],
  [/\b(software|tech|cloud|saas|it services|cyber|telecom|data center|hosting|digital)\b/i, "TECHNOLOGY"],
  [/\b(retail|ecommerce|store|supermarket|consumer|apparel|fashion|restaurant|hotel|hospitality)\b/i, "RETAIL & HOSPITALITY"],
  [/\b(energy|oil|gas|power|utility|electric|solar|mining|water)\b/i, "ENERGY & UTILITIES"],
  [/\b(law|legal|attorney|llp|solicitor|advocate)\b/i, "LEGAL"],
  [/\b(transport|logistics|freight|shipping|aviation|airline|cargo|supply chain)\b/i, "LOGISTICS"],
  [/\b(construction|real estate|property|architect|builder)\b/i, "CONSTRUCTION"],
];

export function extractDomainFromText(text: string): string | null {
  const urlMatch = text.match(/https?:\/\/([a-z0-9.-]+\.[a-z]{2,})/i);
  if (urlMatch?.[1]) {
    const host = urlMatch[1].toLowerCase().replace(/^www\./, "");
    if (!host.endsWith(".onion")) return host;
  }
  const domMatch = text.match(/\b([a-z0-9-]+\.(?:com|net|org|io|co|de|uk|id|sg|jp|fr|au|ca|br|nl|it|es|in|ch|my|th|edu|gov)(?:\.[a-z]{2})?)\b/i);
  if (domMatch?.[1]) {
    return domMatch[1].toLowerCase().replace(/^www\./, "");
  }
  return null;
}

export function inferVictimCountry(
  title: string,
  description: string,
  domain: string | null,
): { code: string; name: string } {
  if (domain) {
    for (const [re, code] of TLD_COUNTRY_RULES) {
      if (re.test(domain)) {
        return { code, name: COUNTRY_NAME_MAP[code] || code };
      }
    }
  }
  const combined = `${title} ${description}`;
  for (const [re, code] of TEXT_COUNTRY_RULES) {
    if (re.test(combined)) {
      return { code, name: COUNTRY_NAME_MAP[code] || code };
    }
  }
  return { code: "UNSPECIFIED", name: "UNSPECIFIED" };
}

export function inferVictimSector(title: string, description: string): string {
  const combined = `${title} ${description}`;
  for (const [re, sector] of SECTOR_RULES) {
    if (re.test(combined)) return sector;
  }
  return "OTHER";
}

const globalForDarkweb = globalThis as unknown as {
  __eyesightDarkwebCache?: {
    data: DarkwebIntelSnapshot;
    expiresAt: number;
  };
};

// Real-time 45s TTL; bypass anytime with refresh=true
const DARKWEB_TTL_MS = 45 * 1000;

interface RawRansomLookVictim {
  post_title?: string;
  group_name?: string;
  discovered?: string;
  description?: string;
  website?: string;
  link?: string;
  magnet?: string | null;
  screen?: string | null;
  misp_uuid?: string | null;
}

interface RawHibpBreach {
  Name?: string;
  Title?: string;
  Domain?: string;
  BreachDate?: string;
  AddedDate?: string;
  PwnCount?: number;
  Description?: string;
  DataClasses?: string[];
  IsVerified?: boolean;
  IsStealerLog?: boolean;
}

function stripHtml(text: string): string {
  return text.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
}

export function sortVictimsLatestFirst(
  list: RansomwareVictim[],
): RansomwareVictim[] {
  return [...list].sort((a, b) => {
    const ta = Date.parse(a.discovered) || 0;
    const tb = Date.parse(b.discovered) || 0;
    return tb - ta;
  });
}

export function sortBreachesLatestFirst(list: BreachRecord[]): BreachRecord[] {
  return [...list].sort((a, b) => {
    const ta = Date.parse(a.addedDate || a.breachDate) || 0;
    const tb = Date.parse(b.addedDate || b.breachDate) || 0;
    return tb - ta;
  });
}

function topCounts(values: string[], limit = 6): Array<{ name: string; count: number }> {
  const map = new Map<string, number>();
  for (const val of values) {
    if (!val) continue;
    map.set(val, (map.get(val) || 0) + 1);
  }
  return Array.from(map.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit)
    .map(([name, count]) => ({ name, count }));
}

export async function getDarkwebIntelSnapshot(
  forceRefresh = false,
): Promise<DarkwebIntelSnapshot> {
  if (
    !forceRefresh &&
    globalForDarkweb.__eyesightDarkwebCache &&
    globalForDarkweb.__eyesightDarkwebCache.expiresAt > Date.now()
  ) {
    return globalForDarkweb.__eyesightDarkwebCache.data;
  }

  const [victimsRes, groupsRes, marketsRes, leaksRes, hibpRes, statsRes] =
    await Promise.all([
      fetchJsonWithTimeout<RawRansomLookVictim[]>(
        "https://www.ransomlook.io/api/recent/300",
        {},
        10000,
      ),
      fetchJsonWithTimeout<string[]>(
        "https://www.ransomlook.io/api/groups",
        {},
        9000,
      ),
      fetchJsonWithTimeout<string[]>(
        "https://www.ransomlook.io/api/markets",
        {},
        9000,
      ),
      fetchJsonWithTimeout<Array<{ id?: number; name?: string }>>(
        "https://www.ransomlook.io/api/leaks/leaks",
        {},
        9000,
      ),
      fetchJsonWithTimeout<RawHibpBreach[]>(
        "https://haveibeenpwned.com/api/v3/breaches",
        {},
        10000,
      ),
      fetchJsonWithTimeout<{
        groups?: number;
        groups_locations?: number;
        groups_dls?: number;
        groups_fs?: number;
        groups_chat?: number;
      }>("https://www.ransomlook.io/api/stats", {}, 8000),
    ]);

  let rawVictims: RawRansomLookVictim[] = [];
  if (victimsRes.ok && Array.isArray(victimsRes.data)) {
    rawVictims = victimsRes.data;
  } else {
    const rwRes = await fetchJsonWithTimeout<RawRansomLookVictim[]>(
      "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json",
      {},
      9000,
    );
    if (rwRes.ok && Array.isArray(rwRes.data)) {
      rawVictims = rwRes.data.slice(-250);
    }
  }

  const victims: RansomwareVictim[] = sortVictimsLatestFirst(
    rawVictims
      .filter((v) => v.post_title)
      .map((v) => {
        const title = v.post_title!.trim();
        const desc = (v.description || "").trim();
        const extractedDomain =
          v.website?.trim() ||
          extractDomainFromText(`${title} ${desc}`);
        const country = inferVictimCountry(title, desc, extractedDomain);
        const sector = inferVictimSector(title, desc);
        const groupName = (v.group_name || "unknown").trim();
        const rawLink = v.link?.trim() || null;
        const onionLink =
          rawLink && (rawLink.includes(".onion") || rawLink.startsWith("/"))
            ? rawLink
            : null;
        const sourceUrl =
          rawLink && rawLink.startsWith("http") && !rawLink.includes(".onion")
            ? rawLink
            : groupName && groupName !== "unknown"
              ? `https://www.ransomlook.io/group/${encodeURIComponent(groupName)}`
              : "https://www.ransomlook.io/recent";

        return {
          victim: title,
          group: groupName,
          discovered: v.discovered || "",
          description: desc,
          countryCode: country.code,
          countryName: country.name,
          sector,
          extractedDomain,
          mispUuid: v.misp_uuid?.trim() || null,
          onionLink,
          hasMagnet: Boolean(v.magnet),
          screenshotUrl: v.screen
            ? encodeURI(`https://www.ransomlook.io/${v.screen.replace(/^\/+/, "")}`)
            : null,
          sourceUrl,
        };
      }),
  );

  const groups =
    groupsRes.ok && Array.isArray(groupsRes.data)
      ? groupsRes.data.filter((g): g is string => typeof g === "string")
      : [];

  const markets =
    marketsRes.ok && Array.isArray(marketsRes.data)
      ? marketsRes.data.filter((m): m is string => typeof m === "string")
      : [];

  const leakedDomains: LeakedDomainEntry[] =
    leaksRes.ok && Array.isArray(leaksRes.data)
      ? leaksRes.data
          .filter((l) => l.name)
          .map((l, idx) => {
            const id = l.id ?? idx;
            return {
              id,
              domain: l.name!.trim(),
              sourceUrl:
                l.id !== undefined
                  ? `https://www.ransomlook.io/leak/${encodeURIComponent(String(l.id))}`
                  : "https://www.ransomlook.io/leaks",
            };
          })
      : [];

  const breaches: BreachRecord[] =
    hibpRes.ok && Array.isArray(hibpRes.data)
      ? sortBreachesLatestFirst(
          hibpRes.data
            .filter((b) => b.Name && b.Title)
            .map((b) => ({
              name: b.Name!,
              title: b.Title!,
              domain: (b.Domain || "").trim(),
              breachDate: b.BreachDate || "",
              addedDate: b.AddedDate || b.BreachDate || "",
              pwnCount: Number(b.PwnCount || 0),
              description: stripHtml(b.Description || "").slice(0, 320),
              dataClasses: b.DataClasses || [],
              isVerified: Boolean(b.IsVerified),
              isStealerLog: Boolean(b.IsStealerLog),
            })),
        )
      : [];

  const infraStats: DarkwebInfraStats | null =
    statsRes.ok && statsRes.data
      ? {
          groups: Number(statsRes.data.groups || 0),
          locations: Number(statsRes.data.groups_locations || 0),
          dlsSites: Number(statsRes.data.groups_dls || 0),
          fileServers: Number(statsRes.data.groups_fs || 0),
          negotiationChats: Number(statsRes.data.groups_chat || 0),
        }
      : null;

  const countryMap = new Map<string, { code: string; name: string; count: number }>();
  for (const v of victims) {
    if (v.countryCode === "UNSPECIFIED") continue;
    const prev = countryMap.get(v.countryCode);
    if (prev) prev.count++;
    else countryMap.set(v.countryCode, { code: v.countryCode, name: v.countryName, count: 1 });
  }

  const snapshot: DarkwebIntelSnapshot = {
    victims,
    groups,
    markets,
    breaches,
    leakedDomains,
    infraStats,
    topGroups: topCounts(victims.map((v) => v.group), 8),
    topSectors: topCounts(
      victims.map((v) => v.sector).filter((s) => s !== "OTHER"),
      8,
    ),
    topCountries: Array.from(countryMap.values())
      .sort((a, b) => b.count - a.count)
      .slice(0, 8),
    stats: {
      recentVictimsCount: victims.length,
      groupsCount: groups.length,
      marketsCount: markets.length,
      breachesCount: breaches.length,
      stealerBreachesCount: breaches.filter((b) => b.isStealerLog).length,
      leakedDomainsCount: leakedDomains.length,
      latestVictimDate: victims[0]?.discovered ?? null,
      latestBreachDate: breaches[0]?.addedDate ?? null,
    },
    fetchedAt: new Date().toISOString(),
  };

  if (victims.length > 0 || breaches.length > 0) {
    globalForDarkweb.__eyesightDarkwebCache = {
      data: snapshot,
      expiresAt: Date.now() + DARKWEB_TTL_MS,
    };
  }

  return snapshot;
}

export function evaluateTargetAgainstSnapshot(
  target: string,
  snapshot: DarkwebIntelSnapshot,
): MonitorEvaluation {
  const needle = target.trim().toLowerCase();
  if (!needle) {
    return {
      matchCount: 0,
      victimHits: [],
      breachHits: [],
      leakedDomainHits: [],
    };
  }

  const victimHits = snapshot.victims.filter(
    (v) =>
      v.victim.toLowerCase().includes(needle) ||
      (v.extractedDomain && v.extractedDomain.toLowerCase().includes(needle)) ||
      v.description.toLowerCase().includes(needle) ||
      v.group.toLowerCase().includes(needle),
  );

  const breachHits = snapshot.breaches.filter(
    (b) =>
      b.domain.toLowerCase().includes(needle) ||
      b.title.toLowerCase().includes(needle) ||
      b.name.toLowerCase().includes(needle),
  );

  const leakedDomainHits = snapshot.leakedDomains.filter((d) =>
    d.domain.toLowerCase().includes(needle),
  );

  return {
    matchCount: victimHits.length + breachHits.length + leakedDomainHits.length,
    victimHits: victimHits.slice(0, 15),
    breachHits: breachHits.slice(0, 15),
    leakedDomainHits: leakedDomainHits.slice(0, 20),
  };
}

export async function searchDarkwebIntel(
  query: string,
  hibpApiKey?: string | null,
): Promise<DarkwebSearchResult> {
  const snapshot = await getDarkwebIntelSnapshot();
  const q = query.trim();
  const needle = q.toLowerCase();
  const evalHits = evaluateTargetAgainstSnapshot(q, snapshot);

  const groups = snapshot.groups.filter((g) =>
    g.toLowerCase().includes(needle),
  );
  const markets = snapshot.markets.filter((m) =>
    m.toLowerCase().includes(needle),
  );

  let emailBreaches: BreachRecord[] | null = null;
  let emailLookupNote: string | null = null;

  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(q)) {
    const key = hibpApiKey?.trim() || process.env.HIBP_API_KEY?.trim();
    if (key) {
      const res = await fetchJsonWithTimeout<RawHibpBreach[]>(
        `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(q)}?truncateResponse=false`,
        {
          headers: {
            "hibp-api-key": key,
            "user-agent": "eyesight-darkweb-monitor",
          },
        },
        8000,
      );
      if (res.status === 404) {
        emailBreaches = [];
        emailLookupNote = "NO HIBP BREACH RECORDS FOUND FOR THIS EMAIL.";
      } else if (res.ok && Array.isArray(res.data)) {
        emailBreaches = sortBreachesLatestFirst(
          res.data.map((b) => ({
            name: b.Name || "",
            title: b.Title || b.Name || "",
            domain: b.Domain || "",
            breachDate: b.BreachDate || "",
            addedDate: b.AddedDate || b.BreachDate || "",
            pwnCount: Number(b.PwnCount || 0),
            description: stripHtml(b.Description || "").slice(0, 320),
            dataClasses: b.DataClasses || [],
            isVerified: Boolean(b.IsVerified),
            isStealerLog: Boolean(b.IsStealerLog),
          })),
        );
      } else {
        emailLookupNote = `HIBP EMAIL CHECK RETURNED HTTP ${res.status}.`;
      }
    } else {
      // Fallback to free public XposedOrNot breach-analytics API when no HIBP key is set
      const xonRes = await fetchJsonWithTimeout<{
        Error?: string;
        ExposedBreaches?: {
          breaches_details?: Array<{
            breach?: string;
            domain?: string;
            xposed_date?: string;
            added?: string;
            xposed_records?: number;
            xposed_data?: string;
            details?: string;
            verified?: string;
          }>;
        } | null;
      }>(
        `https://api.xposedornot.com/v1/breach-analytics?email=${encodeURIComponent(q)}`,
        {},
        9000,
      );

      const details = xonRes.data?.ExposedBreaches?.breaches_details || [];
      if (xonRes.ok && !xonRes.data?.Error && details.length > 0) {
        emailBreaches = sortBreachesLatestFirst(
          details.map((b) => ({
            name: b.breach || "",
            title: b.breach || "",
            domain: b.domain || "",
            breachDate: b.xposed_date || "",
            addedDate: b.added || b.xposed_date || "",
            pwnCount: Number(b.xposed_records || 0),
            description: (b.details || "").trim(),
            dataClasses: (b.xposed_data || "")
              .split(";")
              .map((s) => s.trim())
              .filter(Boolean),
            isVerified: String(b.verified || "").toLowerCase() === "yes",
            isStealerLog: false,
          })),
        );
        emailLookupNote =
          "CHECKED VIA XPOSEDORNOT OSINT (FREE). OPEN THE CREDENTIAL LEAKS TAB FOR FULL COMB & INFOSTEALER TELEMETRY.";
      } else {
        emailLookupNote =
          "NO BREACH RECORDS RETURNED VIA XPOSEDORNOT FOR THIS EMAIL; USE CREDENTIAL LEAKS TAB FOR COMB & HUDSONROCK SCAN.";
      }
    }
  }

  return {
    query: q,
    victims: evalHits.victimHits,
    breaches: evalHits.breachHits,
    leakedDomains: evalHits.leakedDomainHits,
    groups: groups.slice(0, 30),
    markets: markets.slice(0, 30),
    emailBreaches,
    emailLookupNote,
  };
}
