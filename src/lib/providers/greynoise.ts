import { fetchJsonWithTimeout } from "./http";
import type { ProviderAdapter, ProviderQueryContext, ThreatVerdict } from "./types";

export const greyNoiseProvider: ProviderAdapter = {
  id: "greynoise",
  async query(ctx: ProviderQueryContext) {
    const start = Date.now();
    if (ctx.type !== "ip") {
      return {
        providerId: "greynoise",
        providerName: "GreyNoise",
        status: "unsupported",
        riskScore: null,
        verdict: "unknown",
        summary: "GreyNoise supports IP addresses only.",
        details: {},
        pivots: [],
        latencyMs: Date.now() - start,
      };
    }

    const headers: Record<string, string> = {};
    if (ctx.apiKey) {
      headers.key = ctx.apiKey;
    }

    const res = await fetchJsonWithTimeout<{
      ip?: string;
      noise?: boolean;
      riot?: boolean;
      classification?: string;
      name?: string;
      last_seen?: string;
      message?: string;
    }>(`https://api.greynoise.io/v3/community/${encodeURIComponent(ctx.ioc)}`, {
      headers,
    });

    const latencyMs = Date.now() - start;

    if (res.status === 429) {
      return {
        providerId: "greynoise",
        providerName: "GreyNoise",
        status: "rate_limited",
        riskScore: null,
        verdict: "unknown",
        summary: "GreyNoise Community rate limit exceeded (add GREYNOISE_API_KEY for higher limits).",
        details: {},
        pivots: [],
        latencyMs,
      };
    }

    if (res.status === 404) {
      return {
        providerId: "greynoise",
        providerName: "GreyNoise",
        status: "not_found",
        riskScore: 0,
        verdict: "clean",
        summary: "IP not observed scanning the internet (not in GreyNoise noise/RIOT).",
        details: { noise: false, riot: false },
        pivots: [],
        raw: res.data,
        latencyMs,
      };
    }

    if (!res.ok || !res.data) {
      return {
        providerId: "greynoise",
        providerName: "GreyNoise",
        status: "error",
        riskScore: null,
        verdict: "unknown",
        summary: res.errorText || `GreyNoise returned HTTP ${res.status}`,
        details: {},
        pivots: [],
        latencyMs,
      };
    }

    const classification = (res.data.classification || "unknown").toLowerCase();
    let riskScore = 0;
    let verdict: ThreatVerdict = "clean";
    if (res.data.riot || classification === "benign") {
      riskScore = 0;
      verdict = "clean";
    } else if (classification === "malicious") {
      riskScore = 85;
      verdict = "malicious";
    } else if (res.data.noise) {
      riskScore = 40;
      verdict = "suspicious";
    }

    return {
      providerId: "greynoise",
      providerName: "GreyNoise",
      status: "ok",
      riskScore,
      verdict,
      summary: res.data.riot
        ? `RIOT benign service (${res.data.name || "known trusted infrastructure"}).`
        : res.data.noise
          ? `Classified as "${classification}" internet scanner (${res.data.name || "mass-scanning host"}).`
          : res.data.message || "Observed in GreyNoise.",
      details: {
        noise: res.data.noise ?? false,
        riot: res.data.riot ?? false,
        classification: res.data.classification ?? null,
        actorOrService: res.data.name ?? null,
        lastSeen: res.data.last_seen ?? null,
      },
      pivots: [],
      raw: res.data,
      latencyMs,
    };
  },
};
