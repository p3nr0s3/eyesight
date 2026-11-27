import { fetchJsonWithTimeout, dedupePivots } from "./http";
import type { PivotLink, ProviderAdapter, ProviderQueryContext, ThreatVerdict } from "./types";

export const shodanProvider: ProviderAdapter = {
  id: "shodan",
  async query(ctx: ProviderQueryContext) {
    const start = Date.now();
    if (ctx.type !== "ip" && ctx.type !== "domain") {
      return {
        providerId: "shodan",
        providerName: "Shodan",
        status: "unsupported",
        riskScore: null,
        verdict: "unknown",
        summary: "Shodan supports IP addresses and domains only.",
        details: {},
        pivots: [],
        latencyMs: Date.now() - start,
      };
    }

    if (!ctx.apiKey) {
      return {
        providerId: "shodan",
        providerName: "Shodan",
        status: "unconfigured",
        riskScore: null,
        verdict: "unknown",
        summary: "API key required (SHODAN_API_KEY or BYOK).",
        details: {},
        pivots: [],
        latencyMs: Date.now() - start,
      };
    }

    if (ctx.type === "domain") {
      const dnsRes = await fetchJsonWithTimeout<Record<string, string | null>>(
        `https://api.shodan.io/dns/resolve?hostnames=${encodeURIComponent(ctx.ioc)}&key=${encodeURIComponent(ctx.apiKey)}`,
      );
      const latencyMs = Date.now() - start;
      if (!dnsRes.ok || !dnsRes.data) {
        return {
          providerId: "shodan",
          providerName: "Shodan",
          status: dnsRes.status === 429 ? "rate_limited" : "error",
          riskScore: null,
          verdict: "unknown",
          summary: dnsRes.errorText || `Shodan DNS resolve returned HTTP ${dnsRes.status}`,
          details: {},
          pivots: [],
          latencyMs,
        };
      }
      const resolvedIp = dnsRes.data[ctx.ioc];
      const pivots: PivotLink[] = resolvedIp
        ? [{ type: "ip", value: resolvedIp, label: "Resolved A" }]
        : [];
      return {
        providerId: "shodan",
        providerName: "Shodan",
        status: resolvedIp ? "ok" : "not_found",
        riskScore: 0,
        verdict: "clean",
        summary: resolvedIp
          ? `Shodan DNS resolves to ${resolvedIp} (pivot to IP for ports/CVEs).`
          : "No Shodan DNS resolution found.",
        details: { resolvedIp: resolvedIp ?? null },
        pivots,
        raw: dnsRes.data,
        latencyMs,
      };
    }

    const res = await fetchJsonWithTimeout<{
      ip_str?: string;
      org?: string;
      isp?: string;
      asn?: string;
      os?: string | null;
      ports?: number[];
      vulns?: string[];
      tags?: string[];
      hostnames?: string[];
      domains?: string[];
      country_code?: string;
    }>(
      `https://api.shodan.io/shodan/host/${encodeURIComponent(ctx.ioc)}?key=${encodeURIComponent(ctx.apiKey)}`,
    );

    const latencyMs = Date.now() - start;

    if (res.status === 429) {
      return {
        providerId: "shodan",
        providerName: "Shodan",
        status: "rate_limited",
        riskScore: null,
        verdict: "unknown",
        summary: "Shodan API rate limit exceeded.",
        details: {},
        pivots: [],
        latencyMs,
      };
    }

    if (res.status === 404) {
      return {
        providerId: "shodan",
        providerName: "Shodan",
        status: "not_found",
        riskScore: 0,
        verdict: "clean",
        summary: "No exposed services indexed by Shodan.",
        details: {},
        pivots: [],
        raw: res.data,
        latencyMs,
      };
    }

    if (!res.ok || !res.data) {
      return {
        providerId: "shodan",
        providerName: "Shodan",
        status: "error",
        riskScore: null,
        verdict: "unknown",
        summary: res.errorText || `Shodan returned HTTP ${res.status}`,
        details: {},
        pivots: [],
        latencyMs,
      };
    }

    const ports = res.data.ports || [];
    const vulns = res.data.vulns || [];
    const tags = res.data.tags || [];
    const isMaliciousTag = tags.some((t) =>
      ["malware", "c2", "compromised", "honeypot"].includes(t.toLowerCase()),
    );

    // Heuristic exposure risk from CVEs & suspicious tags
    let riskScore = 0;
    if (isMaliciousTag) riskScore = 80;
    else if (vulns.length >= 5) riskScore = 60;
    else if (vulns.length > 0) riskScore = 35;
    else if (ports.length > 10) riskScore = 20;

    const verdict: ThreatVerdict =
      riskScore >= 70 ? "malicious" : riskScore >= 30 ? "suspicious" : "clean";

    const pivots: PivotLink[] = [];
    if (res.data.asn) {
      pivots.push({
        type: "asn",
        value: res.data.asn.toUpperCase(),
        label: res.data.org,
      });
    }
    for (const host of (res.data.hostnames || []).slice(0, 6)) {
      pivots.push({ type: "domain", value: host, label: "PTR/Hostname" });
    }

    return {
      providerId: "shodan",
      providerName: "Shodan",
      status: "ok",
      riskScore,
      verdict,
      summary: `${ports.length} open port(s)${vulns.length ? `, ${vulns.length} known CVE(s)` : ""}${res.data.org ? ` (${res.data.org})` : ""}.`,
      details: {
        ports,
        vulns: vulns.slice(0, 15),
        org: res.data.org ?? null,
        isp: res.data.isp ?? null,
        asn: res.data.asn ?? null,
        os: res.data.os ?? null,
        tags,
        countryCode: res.data.country_code ?? null,
      },
      pivots: dedupePivots(pivots, ctx.ioc),
      raw: res.data,
      latencyMs,
    };
  },
};
