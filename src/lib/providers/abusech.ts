import { fetchJsonWithTimeout, dedupePivots } from "./http";
import type { PivotLink, ProviderAdapter, ProviderQueryContext } from "./types";

function buildAbuseChHeaders(apiKey?: string | null): Record<string, string> {
  const headers: Record<string, string> = {};
  if (apiKey) {
    headers["Auth-Key"] = apiKey;
  }
  return headers;
}

export const urlhausProvider: ProviderAdapter = {
  id: "urlhaus",
  async query(ctx: ProviderQueryContext) {
    const start = Date.now();
    let endpoint = "";
    const form = new URLSearchParams();

    if (ctx.type === "url") {
      endpoint = "https://urlhaus-api.abuse.ch/v1/url/";
      form.set("url", ctx.ioc);
    } else if (ctx.type === "domain" || ctx.type === "ip") {
      endpoint = "https://urlhaus-api.abuse.ch/v1/host/";
      form.set("host", ctx.ioc);
    } else if (ctx.type === "hash") {
      if (ctx.ioc.length === 32) {
        endpoint = "https://urlhaus-api.abuse.ch/v1/payload/";
        form.set("md5_hash", ctx.ioc);
      } else if (ctx.ioc.length === 64) {
        endpoint = "https://urlhaus-api.abuse.ch/v1/payload/";
        form.set("sha256_hash", ctx.ioc);
      } else {
        return {
          providerId: "urlhaus",
          providerName: "abuse.ch URLhaus",
          status: "unsupported",
          riskScore: null,
          verdict: "unknown",
          summary: "URLhaus payload lookup supports MD5 or SHA-256 hashes.",
          details: {},
          pivots: [],
          latencyMs: Date.now() - start,
        };
      }
    }

    const res = await fetchJsonWithTimeout<{
      query_status?: string;
      url_status?: string;
      threat?: string;
      tags?: string[];
      url_count?: number;
      urls?: Array<{ url?: string; url_status?: string; threat?: string }>;
      file_type?: string;
      signature?: string;
      firstseen?: string;
      lastseen?: string;
    }>(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        ...buildAbuseChHeaders(ctx.apiKey),
      },
      body: form.toString(),
    });

    const latencyMs = Date.now() - start;

    if (res.status === 401 || res.status === 403) {
      return {
        providerId: "urlhaus",
        providerName: "abuse.ch URLhaus",
        status: "unconfigured",
        riskScore: null,
        verdict: "unknown",
        summary: "abuse.ch Auth-Key required for this endpoint (ABUSECH_AUTH_KEY).",
        details: {},
        pivots: [],
        latencyMs,
      };
    }

    if (!res.ok || !res.data) {
      return {
        providerId: "urlhaus",
        providerName: "abuse.ch URLhaus",
        status: "error",
        riskScore: null,
        verdict: "unknown",
        summary: res.errorText || `URLhaus returned HTTP ${res.status}`,
        details: {},
        pivots: [],
        latencyMs,
      };
    }

    const qs = res.data.query_status;
    if (qs === "no_results") {
      return {
        providerId: "urlhaus",
        providerName: "abuse.ch URLhaus",
        status: "not_found",
        riskScore: 0,
        verdict: "clean",
        summary: "Not listed in URLhaus malware distribution feeds.",
        details: { queryStatus: qs },
        pivots: [],
        raw: res.data,
        latencyMs,
      };
    }

    const pivots: PivotLink[] = [];
    for (const u of (res.data.urls || []).slice(0, 8)) {
      if (u.url) pivots.push({ type: "url", value: u.url, label: u.url_status });
    }

    const onlineCount = (res.data.urls || []).filter(
      (u) => u.url_status === "online",
    ).length;
    const isOnline = res.data.url_status === "online" || onlineCount > 0;
    const riskScore = isOnline ? 95 : 80;

    return {
      providerId: "urlhaus",
      providerName: "abuse.ch URLhaus",
      status: "ok",
      riskScore,
      verdict: "malicious",
      summary: `Listed in URLhaus (${res.data.threat || res.data.signature || "malware distribution"}${res.data.url_count ? `, ${res.data.url_count} URLs` : ""}).`,
      details: {
        queryStatus: qs,
        urlStatus: res.data.url_status ?? null,
        threat: res.data.threat ?? null,
        signature: res.data.signature ?? null,
        urlCount: res.data.url_count ?? null,
        tags: res.data.tags ?? [],
        firstSeen: res.data.firstseen ?? null,
      },
      pivots: dedupePivots(pivots, ctx.ioc),
      raw: res.data,
      latencyMs,
    };
  },
};

export const threatFoxProvider: ProviderAdapter = {
  id: "threatfox",
  async query(ctx: ProviderQueryContext) {
    const start = Date.now();
    const payload =
      ctx.type === "hash"
        ? { query: "search_hash", hash: ctx.ioc }
        : { query: "search_ioc", search_term: ctx.ioc };

    const res = await fetchJsonWithTimeout<{
      query_status?: string;
      data?: Array<{
        id?: string;
        ioc?: string;
        threat_type?: string;
        malware_printable?: string;
        confidence_level?: number;
        first_seen?: string;
        last_seen?: string;
        tags?: string[];
      }>;
    }>("https://threatfox-api.abuse.ch/api/v1/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...buildAbuseChHeaders(ctx.apiKey),
      },
      body: JSON.stringify(payload),
    });

    const latencyMs = Date.now() - start;

    if (res.status === 401 || res.status === 403) {
      return {
        providerId: "threatfox",
        providerName: "abuse.ch ThreatFox",
        status: "unconfigured",
        riskScore: null,
        verdict: "unknown",
        summary: "abuse.ch Auth-Key required (ABUSECH_AUTH_KEY).",
        details: {},
        pivots: [],
        latencyMs,
      };
    }

    if (!res.ok || !res.data) {
      return {
        providerId: "threatfox",
        providerName: "abuse.ch ThreatFox",
        status: "error",
        riskScore: null,
        verdict: "unknown",
        summary: res.errorText || `ThreatFox returned HTTP ${res.status}`,
        details: {},
        pivots: [],
        latencyMs,
      };
    }

    if (res.data.query_status === "no_result" || !res.data.data?.length) {
      return {
        providerId: "threatfox",
        providerName: "abuse.ch ThreatFox",
        status: "not_found",
        riskScore: 0,
        verdict: "clean",
        summary: "No matching IOC records in ThreatFox.",
        details: { queryStatus: res.data.query_status },
        pivots: [],
        raw: res.data,
        latencyMs,
      };
    }

    const first = res.data.data[0];
    const conf = Math.max(
      50,
      Math.min(100, first.confidence_level ?? 85),
    );
    const malwareNames = Array.from(
      new Set(
        res.data.data.map((d) => d.malware_printable).filter(Boolean) as string[],
      ),
    );

    return {
      providerId: "threatfox",
      providerName: "abuse.ch ThreatFox",
      status: "ok",
      riskScore: conf,
      verdict: conf >= 70 ? "malicious" : "suspicious",
      summary: `${res.data.data.length} ThreatFox hit(s): ${malwareNames.join(", ") || first.threat_type || "Malicious IOC"} (${conf}% confidence).`,
      details: {
        matches: res.data.data.length,
        malwareFamilies: malwareNames,
        threatType: first.threat_type ?? null,
        confidenceLevel: conf,
        firstSeen: first.first_seen ?? null,
        tags: first.tags ?? [],
      },
      pivots: [],
      raw: res.data,
      latencyMs,
    };
  },
};

export const malwareBazaarProvider: ProviderAdapter = {
  id: "malwarebazaar",
  async query(ctx: ProviderQueryContext) {
    const start = Date.now();
    if (ctx.type !== "hash") {
      return {
        providerId: "malwarebazaar",
        providerName: "abuse.ch MalwareBazaar",
        status: "unsupported",
        riskScore: null,
        verdict: "unknown",
        summary: "MalwareBazaar supports file hashes only.",
        details: {},
        pivots: [],
        latencyMs: Date.now() - start,
      };
    }

    const form = new URLSearchParams();
    form.set("query", "get_info");
    form.set("hash", ctx.ioc);

    const res = await fetchJsonWithTimeout<{
      query_status?: string;
      data?: Array<{
        sha256_hash?: string;
        md5_hash?: string;
        sha1_hash?: string;
        file_name?: string;
        file_type?: string;
        signature?: string;
        first_seen?: string;
        tags?: string[];
        delivery_method?: string;
      }>;
    }>("https://mb-api.abuse.ch/api/v1/", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        ...buildAbuseChHeaders(ctx.apiKey),
      },
      body: form.toString(),
    });

    const latencyMs = Date.now() - start;

    if (res.status === 401 || res.status === 403) {
      return {
        providerId: "malwarebazaar",
        providerName: "abuse.ch MalwareBazaar",
        status: "unconfigured",
        riskScore: null,
        verdict: "unknown",
        summary: "abuse.ch Auth-Key required (ABUSECH_AUTH_KEY).",
        details: {},
        pivots: [],
        latencyMs,
      };
    }

    if (!res.ok || !res.data) {
      return {
        providerId: "malwarebazaar",
        providerName: "abuse.ch MalwareBazaar",
        status: "error",
        riskScore: null,
        verdict: "unknown",
        summary: res.errorText || `MalwareBazaar returned HTTP ${res.status}`,
        details: {},
        pivots: [],
        latencyMs,
      };
    }

    if (
      res.data.query_status === "hash_not_found" ||
      !res.data.data?.length
    ) {
      return {
        providerId: "malwarebazaar",
        providerName: "abuse.ch MalwareBazaar",
        status: "not_found",
        riskScore: 0,
        verdict: "clean",
        summary: "Hash not found in MalwareBazaar sample repository.",
        details: { queryStatus: res.data.query_status },
        pivots: [],
        raw: res.data,
        latencyMs,
      };
    }

    const sample = res.data.data[0];
    const pivots: PivotLink[] = [];
    if (sample.sha256_hash) pivots.push({ type: "hash", value: sample.sha256_hash, label: "SHA-256" });
    if (sample.md5_hash) pivots.push({ type: "hash", value: sample.md5_hash, label: "MD5" });
    if (sample.sha1_hash) pivots.push({ type: "hash", value: sample.sha1_hash, label: "SHA-1" });

    return {
      providerId: "malwarebazaar",
      providerName: "abuse.ch MalwareBazaar",
      status: "ok",
      riskScore: 98,
      verdict: "malicious",
      summary: `Confirmed malware sample: ${sample.signature || sample.file_type || "Malicious payload"} (${sample.file_name || "unnamed"}).`,
      details: {
        signature: sample.signature ?? null,
        fileName: sample.file_name ?? null,
        fileType: sample.file_type ?? null,
        deliveryMethod: sample.delivery_method ?? null,
        firstSeen: sample.first_seen ?? null,
        tags: sample.tags ?? [],
      },
      pivots: dedupePivots(pivots, ctx.ioc),
      raw: res.data,
      latencyMs,
    };
  },
};
