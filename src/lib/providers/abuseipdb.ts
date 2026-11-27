import { fetchJsonWithTimeout, dedupePivots } from "./http";
import type { PivotLink, ProviderAdapter, ProviderQueryContext, ThreatVerdict } from "./types";

export const abuseIpDbProvider: ProviderAdapter = {
  id: "abuseipdb",
  async query(ctx: ProviderQueryContext) {
    const start = Date.now();
    if (ctx.type !== "ip") {
      return {
        providerId: "abuseipdb",
        providerName: "AbuseIPDB",
        status: "unsupported",
        riskScore: null,
        verdict: "unknown",
        summary: "AbuseIPDB supports IP addresses only.",
        details: {},
        pivots: [],
        latencyMs: Date.now() - start,
      };
    }

    if (!ctx.apiKey) {
      return {
        providerId: "abuseipdb",
        providerName: "AbuseIPDB",
        status: "unconfigured",
        riskScore: null,
        verdict: "unknown",
        summary: "API key required (ABUSEIPDB_API_KEY or BYOK).",
        details: {},
        pivots: [],
        latencyMs: Date.now() - start,
      };
    }

    const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ctx.ioc)}&maxAgeInDays=90&verbose`;
    const res = await fetchJsonWithTimeout<{
      data?: {
        abuseConfidenceScore?: number;
        totalReports?: number;
        numDistinctUsers?: number;
        countryCode?: string;
        usageType?: string;
        isp?: string;
        domain?: string;
        isTor?: boolean;
        isWhitelisted?: boolean;
        lastReportedAt?: string;
      };
    }>(url, {
      headers: {
        Key: ctx.apiKey,
        Accept: "application/json",
      },
    });

    const latencyMs = Date.now() - start;

    if (res.status === 429) {
      return {
        providerId: "abuseipdb",
        providerName: "AbuseIPDB",
        status: "rate_limited",
        riskScore: null,
        verdict: "unknown",
        summary: "AbuseIPDB daily quota or rate limit exceeded.",
        details: {},
        pivots: [],
        latencyMs,
      };
    }

    if (!res.ok || !res.data?.data) {
      return {
        providerId: "abuseipdb",
        providerName: "AbuseIPDB",
        status: "error",
        riskScore: null,
        verdict: "unknown",
        summary: res.errorText || `AbuseIPDB returned HTTP ${res.status}`,
        details: {},
        pivots: [],
        raw: res.data,
        latencyMs,
      };
    }

    const d = res.data.data;
    const score = Math.max(0, Math.min(100, d.abuseConfidenceScore ?? 0));
    const verdict: ThreatVerdict =
      score >= 70 ? "malicious" : score >= 25 ? "suspicious" : "clean";

    const pivots: PivotLink[] = [];
    if (d.domain) {
      pivots.push({ type: "domain", value: d.domain, label: "ISP Domain" });
    }

    return {
      providerId: "abuseipdb",
      providerName: "AbuseIPDB",
      status: "ok",
      riskScore: score,
      verdict,
      summary: `${score}% abuse confidence across ${d.totalReports ?? 0} reports (${d.numDistinctUsers ?? 0} distinct reporters).`,
      details: {
        abuseConfidenceScore: score,
        totalReports: d.totalReports ?? 0,
        distinctUsers: d.numDistinctUsers ?? 0,
        isp: d.isp ?? null,
        usageType: d.usageType ?? null,
        countryCode: d.countryCode ?? null,
        isTor: d.isTor ?? false,
        isWhitelisted: d.isWhitelisted ?? false,
        lastReportedAt: d.lastReportedAt ?? null,
      },
      pivots: dedupePivots(pivots, ctx.ioc),
      raw: res.data,
      latencyMs,
    };
  },
};
