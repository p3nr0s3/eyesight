import { fetchJsonWithTimeout, dedupePivots } from "./http";
import type { PivotLink, ProviderAdapter, ProviderQueryContext, ThreatVerdict } from "./types";

function vtUrlId(url: string): string {
  return Buffer.from(url).toString("base64url").replace(/=+$/, "");
}

export const virusTotalProvider: ProviderAdapter = {
  id: "virustotal",
  async query(ctx: ProviderQueryContext) {
    const start = Date.now();
    if (!ctx.apiKey) {
      return {
        providerId: "virustotal",
        providerName: "VirusTotal",
        status: "unconfigured",
        riskScore: null,
        verdict: "unknown",
        summary: "API key required (VT_API_KEY or BYOK).",
        details: {},
        pivots: [],
        latencyMs: Date.now() - start,
      };
    }

    let endpoint = "";
    if (ctx.type === "ip") {
      endpoint = `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ctx.ioc)}`;
    } else if (ctx.type === "domain") {
      endpoint = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(ctx.ioc)}`;
    } else if (ctx.type === "url") {
      endpoint = `https://www.virustotal.com/api/v3/urls/${vtUrlId(ctx.ioc)}`;
    } else if (ctx.type === "hash") {
      endpoint = `https://www.virustotal.com/api/v3/files/${encodeURIComponent(ctx.ioc)}`;
    }

    const res = await fetchJsonWithTimeout<{
      data?: {
        id?: string;
        attributes?: {
          last_analysis_stats?: {
            malicious?: number;
            suspicious?: number;
            harmless?: number;
            undetected?: number;
          };
          reputation?: number;
          as_owner?: string;
          asn?: number;
          country?: string;
          meaningful_name?: string;
          popular_threat_classification?: {
            suggested_threat_label?: string;
          };
          tags?: string[];
          categories?: Record<string, string>;
          last_dns_records?: Array<{ type?: string; value?: string }>;
        };
      };
    }>(endpoint, {
      headers: { "x-apikey": ctx.apiKey },
    });

    const latencyMs = Date.now() - start;

    if (res.status === 429) {
      return {
        providerId: "virustotal",
        providerName: "VirusTotal",
        status: "rate_limited",
        riskScore: null,
        verdict: "unknown",
        summary: "VirusTotal API rate limit exceeded.",
        details: {},
        pivots: [],
        latencyMs,
      };
    }

    if (res.status === 404) {
      return {
        providerId: "virustotal",
        providerName: "VirusTotal",
        status: "not_found",
        riskScore: 0,
        verdict: "clean",
        summary: "Not found in VirusTotal database.",
        details: {},
        pivots: [],
        raw: res.data,
        latencyMs,
      };
    }

    if (!res.ok || !res.data?.data?.attributes) {
      return {
        providerId: "virustotal",
        providerName: "VirusTotal",
        status: "error",
        riskScore: null,
        verdict: "unknown",
        summary: res.errorText || `VirusTotal returned HTTP ${res.status}`,
        details: {},
        pivots: [],
        raw: res.data,
        latencyMs,
      };
    }

    const attrs = res.data.data.attributes;
    const stats = attrs.last_analysis_stats || {};
    const malicious = stats.malicious ?? 0;
    const suspicious = stats.suspicious ?? 0;
    const harmless = stats.harmless ?? 0;
    const undetected = stats.undetected ?? 0;
    const total = Math.max(1, malicious + suspicious + harmless + undetected);

    // Scale VT detections: >=5 malicious hits gives high risk even out of 90 engines
    const rawRatio = ((malicious + suspicious * 0.5) / total) * 100;
    const boosted =
      malicious >= 5
        ? Math.max(75, Math.min(100, Math.round(rawRatio * 2.5 + 35)))
        : malicious >= 1
          ? Math.max(35, Math.min(85, Math.round(rawRatio * 3 + 25)))
          : suspicious >= 1
            ? Math.max(20, Math.min(50, Math.round(rawRatio * 2 + 15)))
            : 0;

    const verdict: ThreatVerdict =
      malicious >= 3 || boosted >= 70
        ? "malicious"
        : malicious >= 1 || suspicious >= 2
          ? "suspicious"
          : "clean";

    const pivots: PivotLink[] = [];
    if (attrs.asn) {
      pivots.push({
        type: "asn",
        value: `AS${attrs.asn}`,
        label: attrs.as_owner,
      });
    }
    for (const rec of attrs.last_dns_records || []) {
      if ((rec.type === "A" || rec.type === "AAAA") && rec.value) {
        pivots.push({ type: "ip", value: rec.value, label: rec.type });
      } else if (rec.type === "CNAME" && rec.value) {
        pivots.push({
          type: "domain",
          value: rec.value.replace(/\.$/, ""),
          label: "CNAME",
        });
      }
    }

    const threatLabel =
      attrs.popular_threat_classification?.suggested_threat_label;

    return {
      providerId: "virustotal",
      providerName: "VirusTotal",
      status: "ok",
      riskScore: boosted,
      verdict,
      summary: `${malicious}/${total} engines flagged malicious${suspicious ? `, ${suspicious} suspicious` : ""}${threatLabel ? ` (${threatLabel})` : ""}.`,
      details: {
        malicious,
        suspicious,
        harmless,
        undetected,
        totalEngines: total,
        reputation: attrs.reputation ?? null,
        threatLabel: threatLabel ?? null,
        asOwner: attrs.as_owner ?? null,
        country: attrs.country ?? null,
        tags: attrs.tags ?? [],
      },
      pivots: dedupePivots(pivots, ctx.ioc),
      raw: res.data,
      latencyMs,
    };
  },
};
