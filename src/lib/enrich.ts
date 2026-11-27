import { and, eq } from "drizzle-orm";
import { getDb, schema } from "@/db";
import type { AuthContext } from "@/lib/auth";
import { decryptSecret } from "@/lib/crypto";
import { defangIoc, parseIoc } from "@/lib/ioc";
import { PROVIDER_ADAPTERS } from "@/lib/providers";
import {
  PROVIDER_CATALOG,
  type IocType,
  type ProviderId,
} from "@/lib/providers/catalog";
import { dedupePivots } from "@/lib/providers/http";
import type { PivotLink, ProviderResult, ThreatVerdict } from "@/lib/providers/types";
import { computeCompositeScore, type ScoringThresholds } from "@/lib/scoring";

export interface EnrichmentReport {
  ioc: string;
  defanged: string;
  type: IocType;
  isPrivateIp: boolean;
  compositeScore: number | null;
  verdict: ThreatVerdict;
  coverageCount: number;
  totalApplicable: number;
  scoredProvidersCount: number;
  thresholds: ScoringThresholds;
  pivots: PivotLink[];
  results: ProviderResult[];
  timestamp: string;
  fromCacheCount: number;
}

export interface EnrichOptions {
  rawIoc: string;
  forceRefresh?: boolean;
  providers?: ProviderId[];
  byokOverrides?: Partial<Record<ProviderId, string>>;
  authContext?: AuthContext;
  recordHistory?: boolean;
}

function getEnvApiKey(providerId: ProviderId): string | null {
  switch (providerId) {
    case "virustotal":
      return process.env.VT_API_KEY?.trim() || null;
    case "abuseipdb":
      return process.env.ABUSEIPDB_API_KEY?.trim() || null;
    case "otx":
      return process.env.OTX_API_KEY?.trim() || null;
    case "shodan":
      return process.env.SHODAN_API_KEY?.trim() || null;
    case "greynoise":
      return process.env.GREYNOISE_API_KEY?.trim() || null;
    case "urlhaus":
    case "threatfox":
    case "malwarebazaar":
      return process.env.ABUSECH_AUTH_KEY?.trim() || null;
    default:
      return null;
  }
}

export async function enrichIoc(options: EnrichOptions): Promise<EnrichmentReport> {
  const parsed = parseIoc(options.rawIoc);
  if (!parsed) {
    throw new Error(
      `Unsupported or invalid IOC format: "${options.rawIoc}". Expected IPv4/IPv6, domain, URL, or MD5/SHA-1/SHA-256 hash.`,
    );
  }

  const db = await getDb();

  // Load scoring thresholds and provider configs
  const [thresholdRows, configRows] = await Promise.all([
    db
      .select()
      .from(schema.scoringSettings)
      .where(eq(schema.scoringSettings.id, "default"))
      .limit(1),
    db.select().from(schema.providerConfigs),
  ]);

  const thresholds: ScoringThresholds = {
    maliciousThreshold: thresholdRows[0]?.maliciousThreshold ?? 70,
    suspiciousThreshold: thresholdRows[0]?.suspiciousThreshold ?? 30,
  };

  const configMap = new Map(configRows.map((c) => [c.providerId as ProviderId, c]));
  const weights: Partial<Record<ProviderId, number>> = {};
  for (const meta of PROVIDER_CATALOG) {
    weights[meta.id] = configMap.get(meta.id)?.weight ?? meta.defaultWeight;
  }

  // Handle private / reserved IPs safely without leaking internal addresses externally
  if (parsed.isPrivateIp) {
    const nowIso = new Date().toISOString();
    const privateResult: ProviderResult = {
      providerId: "network_rdap",
      providerName: "DNS / RDAP / GeoIP",
      status: "ok",
      riskScore: null,
      verdict: "unknown",
      summary:
        "Private, loopback, or reserved IP range (RFC1918 / RFC4193 / Link-Local). External threat-intel queries skipped to avoid leaking internal topology.",
      details: {
        isPrivateOrReserved: true,
        ip: parsed.normalized,
      },
      pivots: [],
      latencyMs: 0,
      cached: false,
      fetchedAt: nowIso,
    };

    return {
      ioc: parsed.normalized,
      defanged: defangIoc(parsed.normalized, parsed.type),
      type: parsed.type,
      isPrivateIp: true,
      compositeScore: null,
      verdict: "unknown",
      coverageCount: 1,
      totalApplicable: 1,
      scoredProvidersCount: 0,
      thresholds,
      pivots: [],
      results: [privateResult],
      timestamp: nowIso,
      fromCacheCount: 0,
    };
  }

  // Load logged-in user's personal encrypted BYOK overrides if authenticated
  const userKeyMap = new Map<ProviderId, string>();
  if (options.authContext?.user?.id) {
    const userKeyRows = await db
      .select()
      .from(schema.userProviderKeys)
      .where(eq(schema.userProviderKeys.userId, options.authContext.user.id));

    for (const row of userKeyRows) {
      const dec = decryptSecret(row.encryptedApiKey);
      if (dec) {
        userKeyMap.set(row.providerId as ProviderId, dec);
      }
    }
  }

  // Load existing cache entries for this IOC unless forceRefresh
  const existingCacheRows = options.forceRefresh
    ? []
    : await db
        .select()
        .from(schema.providerCache)
        .where(
          and(
            eq(schema.providerCache.iocValue, parsed.normalized),
            eq(schema.providerCache.iocType, parsed.type),
          ),
        );
  const cacheMap = new Map(existingCacheRows.map((c) => [c.providerId as ProviderId, c]));

  const now = new Date();
  const providerFilter = options.providers?.length
    ? new Set<ProviderId>(options.providers)
    : null;
  const activeProviders = PROVIDER_CATALOG.filter((meta) => {
    if (providerFilter && !providerFilter.has(meta.id)) return false;
    const cfg = configMap.get(meta.id);
    const enabled = cfg ? cfg.enabled : true;
    return enabled && meta.supportedTypes.includes(parsed.type);
  });

  let fromCacheCount = 0;

  const settled = await Promise.all(
    activeProviders.map(async (meta): Promise<ProviderResult> => {
      const cfg = configMap.get(meta.id);
      const ttlSeconds = cfg?.ttlSeconds ?? meta.defaultTtlSeconds;

      // Resolve API key priority: Request BYOK -> User DB key -> Server DB key -> Env var
      const reqByok = options.byokOverrides?.[meta.id]?.trim() || null;
      const userDbKey = userKeyMap.get(meta.id) || null;
      const serverDbKey = cfg?.encryptedApiKey
        ? decryptSecret(cfg.encryptedApiKey)
        : null;
      const envKey = getEnvApiKey(meta.id);
      const effectiveKey = reqByok || userDbKey || serverDbKey || envKey;

      // Only serve cache if not forceRefresh, cache hasn't expired, and user didn't pass a custom BYOK override that wasn't cached
      const cached = cacheMap.get(meta.id);
      if (
        !options.forceRefresh &&
        !reqByok &&
        cached &&
        cached.expiresAt > now &&
        (cached.status === "ok" || cached.status === "not_found")
      ) {
        fromCacheCount++;
        return {
          providerId: meta.id,
          providerName: meta.name,
          status: cached.status as ProviderResult["status"],
          riskScore: cached.riskScore,
          verdict: cached.verdict as ThreatVerdict,
          summary: cached.summary,
          details: cached.details,
          pivots: cached.pivots as PivotLink[],
          raw: cached.raw,
          latencyMs: 0,
          cached: true,
          fetchedAt: cached.fetchedAt.toISOString(),
          expiresAt: cached.expiresAt.toISOString(),
        };
      }

      const adapter = PROVIDER_ADAPTERS[meta.id];
      const fresh = await adapter.query({
        ioc: parsed.normalized,
        type: parsed.type,
        apiKey: effectiveKey,
      });

      const fetchedAt = new Date();
      const expiresAt = new Date(fetchedAt.getTime() + ttlSeconds * 1000);

      // Persist valid cache responses (ok / not_found) when no ephemeral BYOK key was injected
      if (
        !reqByok &&
        ttlSeconds > 0 &&
        (fresh.status === "ok" || fresh.status === "not_found")
      ) {
        await db
          .insert(schema.providerCache)
          .values({
            id: crypto.randomUUID(),
            iocValue: parsed.normalized,
            iocType: parsed.type,
            providerId: meta.id,
            status: fresh.status,
            riskScore: fresh.riskScore,
            verdict: fresh.verdict,
            summary: fresh.summary,
            details: fresh.details,
            pivots: fresh.pivots,
            raw: fresh.raw ?? null,
            fetchedAt,
            expiresAt,
          })
          .onConflictDoUpdate({
            target: [
              schema.providerCache.iocValue,
              schema.providerCache.iocType,
              schema.providerCache.providerId,
            ],
            set: {
              status: fresh.status,
              riskScore: fresh.riskScore,
              verdict: fresh.verdict,
              summary: fresh.summary,
              details: fresh.details,
              pivots: fresh.pivots,
              raw: fresh.raw ?? null,
              fetchedAt,
              expiresAt,
            },
          });
      }

      return {
        ...fresh,
        cached: false,
        fetchedAt: fetchedAt.toISOString(),
        expiresAt: expiresAt.toISOString(),
      };
    }),
  );

  const summary = computeCompositeScore(
    parsed.type,
    settled,
    weights,
    thresholds,
  );

  const allPivots = dedupePivots(
    settled.flatMap((r) => r.pivots),
    parsed.normalized,
    30,
  );

  const report: EnrichmentReport = {
    ioc: parsed.normalized,
    defanged: defangIoc(parsed.normalized, parsed.type),
    type: parsed.type,
    isPrivateIp: false,
    compositeScore: summary.score,
    verdict: summary.verdict,
    coverageCount: summary.coverageCount,
    totalApplicable: summary.totalApplicable,
    scoredProvidersCount: summary.scoredProvidersCount,
    thresholds,
    pivots: allPivots,
    results: settled,
    timestamp: new Date().toISOString(),
    fromCacheCount,
  };

  if (options.recordHistory !== false) {
    await db.insert(schema.lookupHistory).values({
      id: crypto.randomUUID(),
      userId: options.authContext?.user?.id ?? null,
      iocValue: report.ioc,
      iocType: report.type,
      compositeScore: report.compositeScore,
      verdict: report.verdict,
      coverageCount: report.coverageCount,
      totalApplicable: report.totalApplicable,
      summaryJson: {
        providers: report.results.map((r) => ({
          providerId: r.providerId,
          status: r.status,
          riskScore: r.riskScore,
          verdict: r.verdict,
          summary: r.summary,
        })),
      },
    });
  }

  return report;
}
