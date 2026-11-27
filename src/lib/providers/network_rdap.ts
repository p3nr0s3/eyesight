import dns from "node:dns/promises";
import { extractHostnameFromUrl } from "@/lib/ioc";
import { fetchJsonWithTimeout, dedupePivots } from "./http";
import type { PivotLink, ProviderAdapter, ProviderQueryContext } from "./types";

async function safeDns<T>(fn: () => Promise<T>): Promise<T | null> {
  try {
    return await Promise.race([
      fn(),
      new Promise<null>((resolve) => setTimeout(() => resolve(null), 3500)),
    ]);
  } catch {
    return null;
  }
}

export const networkRdapProvider: ProviderAdapter = {
  id: "network_rdap",
  async query(ctx: ProviderQueryContext) {
    const start = Date.now();
    if (ctx.type === "hash") {
      return {
        providerId: "network_rdap",
        providerName: "DNS / RDAP / GeoIP",
        status: "unsupported",
        riskScore: null,
        verdict: "unknown",
        summary: "Network/RDAP enrichment applies to IPs, domains, and URLs.",
        details: {},
        pivots: [],
        latencyMs: Date.now() - start,
      };
    }

    const host =
      ctx.type === "url" ? extractHostnameFromUrl(ctx.ioc) || ctx.ioc : ctx.ioc;
    const isIp = ctx.type === "ip" || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) || host.includes(":");

    const pivots: PivotLink[] = [];
    if (ctx.type === "url" && host) {
      pivots.push({
        type: isIp ? "ip" : "domain",
        value: host,
        label: "URL Host",
      });
    }

    if (isIp) {
      const [geoRes, rdapRes, ptrRecords] = await Promise.all([
        fetchJsonWithTimeout<{
          success?: boolean;
          country?: string;
          country_code?: string;
          region?: string;
          city?: string;
          connection?: {
            asn?: number;
            org?: string;
            isp?: string;
            domain?: string;
          };
        }>(`https://ipwho.is/${encodeURIComponent(host)}`),
        fetchJsonWithTimeout<{
          name?: string;
          handle?: string;
          startAddress?: string;
          endAddress?: string;
          country?: string;
          events?: Array<{ eventAction?: string; eventDate?: string }>;
        }>(`https://rdap.org/ip/${encodeURIComponent(host)}`),
        safeDns(() => dns.reverse(host)),
      ]);

      const geo = geoRes.data?.success ? geoRes.data : null;
      if (geo?.connection?.asn) {
        pivots.push({
          type: "asn",
          value: `AS${geo.connection.asn}`,
          label: geo.connection.org || geo.connection.isp,
        });
      }
      if (geo?.connection?.domain) {
        pivots.push({
          type: "domain",
          value: geo.connection.domain,
          label: "ISP Domain",
        });
      }
      for (const ptr of ptrRecords || []) {
        pivots.push({ type: "domain", value: ptr, label: "PTR" });
      }

      const summaryParts: string[] = [];
      if (geo?.country) summaryParts.push(`${geo.city ? `${geo.city}, ` : ""}${geo.country}`);
      if (geo?.connection?.asn) {
        summaryParts.push(`AS${geo.connection.asn} (${geo.connection.org || geo.connection.isp || "ASN"})`);
      }
      if (rdapRes.data?.name) summaryParts.push(`Netblock: ${rdapRes.data.name}`);

      return {
        providerId: "network_rdap",
        providerName: "DNS / RDAP / GeoIP",
        status: "ok",
        riskScore: null, // informational enrichment
        verdict: "unknown",
        summary: summaryParts.join(" • ") || "IP network & RDAP context retrieved.",
        details: {
          geo: geo
            ? {
                country: geo.country,
                countryCode: geo.country_code,
                region: geo.region,
                city: geo.city,
                asn: geo.connection?.asn ? `AS${geo.connection.asn}` : null,
                org: geo.connection?.org ?? null,
                isp: geo.connection?.isp ?? null,
              }
            : null,
          rdap: rdapRes.data
            ? {
                netName: rdapRes.data.name ?? null,
                handle: rdapRes.data.handle ?? null,
                range:
                  rdapRes.data.startAddress && rdapRes.data.endAddress
                    ? `${rdapRes.data.startAddress} - ${rdapRes.data.endAddress}`
                    : null,
              }
            : null,
          dns: {
            PTR: ptrRecords || [],
          },
        },
        pivots: dedupePivots(pivots, ctx.ioc),
        raw: { geo: geoRes.data, rdap: rdapRes.data, ptr: ptrRecords },
        latencyMs: Date.now() - start,
      };
    }

    // Domain or URL host DNS + RDAP
    const [aRecs, aaaaRecs, mxRecs, nsRecs, txtRecs, rdapDom] = await Promise.all([
      safeDns(() => dns.resolve4(host)),
      safeDns(() => dns.resolve6(host)),
      safeDns(() => dns.resolveMx(host)),
      safeDns(() => dns.resolveNs(host)),
      safeDns(() => dns.resolveTxt(host)),
      fetchJsonWithTimeout<{
        ldhName?: string;
        status?: string[];
        events?: Array<{ eventAction?: string; eventDate?: string }>;
        nameservers?: Array<{ ldhName?: string }>;
        entities?: Array<{
          roles?: string[];
          vcardArray?: [string, Array<[string, Record<string, unknown>, string, string]>];
        }>;
      }>(`https://rdap.org/domain/${encodeURIComponent(host)}`),
    ]);

    for (const ip of aRecs || []) {
      pivots.push({ type: "ip", value: ip, label: "A Record" });
    }
    for (const ip6 of aaaaRecs || []) {
      pivots.push({ type: "ip", value: ip6, label: "AAAA Record" });
    }
    for (const ns of nsRecs || []) {
      pivots.push({ type: "domain", value: ns, label: "Nameserver" });
    }

    // GeoIP for first resolved A record
    let primaryIpGeo: Record<string, unknown> | null = null;
    if (aRecs && aRecs[0]) {
      const geoRes = await fetchJsonWithTimeout<{
        success?: boolean;
        country?: string;
        country_code?: string;
        city?: string;
        connection?: { asn?: number; org?: string; isp?: string };
      }>(`https://ipwho.is/${encodeURIComponent(aRecs[0])}`);
      if (geoRes.data?.success) {
        primaryIpGeo = {
          ip: aRecs[0],
          country: geoRes.data.country,
          countryCode: geoRes.data.country_code,
          city: geoRes.data.city,
          asn: geoRes.data.connection?.asn ? `AS${geoRes.data.connection.asn}` : null,
          org: geoRes.data.connection?.org ?? null,
        };
        if (geoRes.data.connection?.asn) {
          pivots.push({
            type: "asn",
            value: `AS${geoRes.data.connection.asn}`,
            label: geoRes.data.connection.org,
          });
        }
      }
    }

    const regEvent = rdapDom.data?.events?.find(
      (e) => e.eventAction === "registration",
    );
    const expEvent = rdapDom.data?.events?.find(
      (e) => e.eventAction === "expiration",
    );
    const registrarEntity = rdapDom.data?.entities?.find((e) =>
      e.roles?.includes("registrar"),
    );
    const registrarFn = registrarEntity?.vcardArray?.[1]?.find(
      (item) => item[0] === "fn",
    )?.[3];

    const summaryParts: string[] = [];
    if (aRecs?.length) summaryParts.push(`A: ${aRecs.slice(0, 2).join(", ")}`);
    if (registrarFn) summaryParts.push(`Registrar: ${registrarFn}`);
    if (regEvent?.eventDate) summaryParts.push(`Registered: ${regEvent.eventDate.slice(0, 10)}`);

    return {
      providerId: "network_rdap",
      providerName: "DNS / RDAP / GeoIP",
      status: "ok",
      riskScore: null,
      verdict: "unknown",
      summary: summaryParts.join(" • ") || "DNS & RDAP lookup completed.",
      details: {
        dns: {
          A: aRecs || [],
          AAAA: aaaaRecs || [],
          MX: (mxRecs || []).map((m) => `${m.exchange} (prio ${m.priority})`),
          NS: nsRecs || [],
          TXT: (txtRecs || []).map((t) => t.join("")).slice(0, 8),
        },
        rdap: rdapDom.data
          ? {
              registrar: registrarFn ?? null,
              registeredAt: regEvent?.eventDate ?? null,
              expiresAt: expEvent?.eventDate ?? null,
              status: rdapDom.data.status ?? [],
            }
          : null,
        geo: primaryIpGeo,
      },
      pivots: dedupePivots(pivots, ctx.ioc),
      raw: {
        dns: { aRecs, aaaaRecs, mxRecs, nsRecs },
        rdap: rdapDom.data,
        geo: primaryIpGeo,
      },
      latencyMs: Date.now() - start,
    };
  },
};
