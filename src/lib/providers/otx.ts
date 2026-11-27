import net from "node:net";
import { fetchJsonWithTimeout, dedupePivots } from "./http";
import type { PivotLink, ProviderAdapter, ProviderQueryContext, ThreatVerdict } from "./types";

export const otxProvider: ProviderAdapter = {
  id: "otx",
  async query(ctx: ProviderQueryContext) {
    const start = Date.now();
    if (!ctx.apiKey) {
      return {
        providerId: "otx",
        providerName: "AlienVault OTX",
        status: "unconfigured",
        riskScore: null,
        verdict: "unknown",
        summary: "API key required (OTX_API_KEY or BYOK).",
        details: {},
        pivots: [],
        latencyMs: Date.now() - start,
      };
    }

    let sectionPath = "";
    if (ctx.type === "ip") {
      const family = net.isIPv6(ctx.ioc) ? "IPv6" : "IPv4";
      sectionPath = `indicators/${family}/${encodeURIComponent(ctx.ioc)}/general`;
    } else if (ctx.type === "domain") {
      sectionPath = `indicators/domain/${encodeURIComponent(ctx.ioc)}/general`;
    } else if (ctx.type === "url") {
      sectionPath = `indicators/url/${encodeURIComponent(ctx.ioc)}/general`;
    } else if (ctx.type === "hash") {
      sectionPath = `indicators/file/${encodeURIComponent(ctx.ioc)}/general`;
    }

    const res = await fetchJsonWithTimeout<{
      pulse_info?: {
        count?: number;
        pulses?: Array<{
          name?: string;
          tags?: string[];
          adversary?: string;
          malware_families?: Array<{ display_name?: string }>;
        }>;
      };
      reputation?: number;
      country_code?: string;
      asn?: string;
      validation?: Array<{ source?: string; message?: string }>;
    }>(`https://otx.alienvault.com/api/v1/${sectionPath}`, {
      headers: { "X-OTX-API-KEY": ctx.apiKey },
    });

    const latencyMs = Date.now() - start;

    if (res.status === 429) {
      return {
        providerId: "otx",
        providerName: "AlienVault OTX",
        status: "rate_limited",
        riskScore: null,
        verdict: "unknown",
        summary: "AlienVault OTX rate limit exceeded.",
        details: {},
        pivots: [],
        latencyMs,
      };
    }

    if (res.status === 404) {
      return {
        providerId: "otx",
        providerName: "AlienVault OTX",
        status: "not_found",
        riskScore: 0,
        verdict: "clean",
        summary: "No OTX pulses associated with this indicator.",
        details: { pulseCount: 0 },
        pivots: [],
        raw: res.data,
        latencyMs,
      };
    }

    if (!res.ok || !res.data) {
      return {
        providerId: "otx",
        providerName: "AlienVault OTX",
        status: "error",
        riskScore: null,
        verdict: "unknown",
        summary: res.errorText || `OTX returned HTTP ${res.status}`,
        details: {},
        pivots: [],
        latencyMs,
      };
    }

    const pulseCount = res.data.pulse_info?.count ?? 0;
    const pulses = res.data.pulse_info?.pulses || [];
    const validationClean = (res.data.validation || []).some((v) =>
      v.message?.toLowerCase().includes("whitelist"),
    );

    let riskScore = 0;
    if (!validationClean && pulseCount > 0) {
      riskScore = Math.min(95, 25 + pulseCount * 10);
    }

    const verdict: ThreatVerdict =
      riskScore >= 70 ? "malicious" : riskScore >= 30 ? "suspicious" : "clean";

    const pivots: PivotLink[] = [];
    if (res.data.asn) {
      const asnMatch = res.data.asn.match(/AS\d+/i);
      if (asnMatch) {
        pivots.push({
          type: "asn",
          value: asnMatch[0].toUpperCase(),
          label: res.data.asn,
        });
      }
    }

    const topPulses = pulses
      .slice(0, 5)
      .map((p) => p.name)
      .filter(Boolean);

    return {
      providerId: "otx",
      providerName: "AlienVault OTX",
      status: pulseCount === 0 ? "not_found" : "ok",
      riskScore,
      verdict,
      summary:
        pulseCount > 0
          ? `Found in ${pulseCount} OTX threat pulse(s)${topPulses[0] ? `: "${topPulses[0]}"` : ""}.`
          : validationClean
            ? "Whitelisted / known benign indicator in OTX."
            : "0 OTX pulses found.",
      details: {
        pulseCount,
        topPulses,
        countryCode: res.data.country_code ?? null,
        asn: res.data.asn ?? null,
        whitelisted: validationClean,
      },
      pivots: dedupePivots(pivots, ctx.ioc),
      raw: res.data,
      latencyMs,
    };
  },
};
