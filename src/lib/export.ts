import type { EnrichmentReport } from "./enrich";
import type { IocType } from "./providers/catalog";

function escapeCsvCell(value: unknown): string {
  const str = value === null || value === undefined ? "" : String(value);
  if (/[",\r\n]/.test(str)) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

export function exportReportsAsJson(reports: EnrichmentReport[]): string {
  return JSON.stringify(
    reports.length === 1 ? reports[0] : { count: reports.length, reports },
    null,
    2,
  );
}

export function exportReportsAsCsv(reports: EnrichmentReport[]): string {
  const headers = [
    "ioc",
    "defanged",
    "type",
    "composite_score",
    "verdict",
    "coverage",
    "timestamp",
    "provider_findings",
  ];
  const rows = reports.map((r) => {
    const providerSummary = r.results
      .filter((p) => p.status === "ok" || p.status === "not_found")
      .map(
        (p) =>
          `${p.providerName}:${p.verdict}${p.riskScore !== null ? `(${p.riskScore})` : ""}`,
      )
      .join(" | ");

    return [
      r.ioc,
      r.defanged,
      r.type,
      r.compositeScore ?? "",
      r.verdict,
      `${r.coverageCount}/${r.totalApplicable}`,
      r.timestamp,
      providerSummary,
    ]
      .map(escapeCsvCell)
      .join(",");
  });

  return [headers.join(","), ...rows].join("\n");
}

function buildStixPattern(ioc: string, type: IocType): string {
  const escaped = ioc.replace(/'/g, "\\'");
  if (type === "ip") {
    return ioc.includes(":")
      ? `[ipv6-addr:value = '${escaped}']`
      : `[ipv4-addr:value = '${escaped}']`;
  }
  if (type === "domain") {
    return `[domain-name:value = '${escaped}']`;
  }
  if (type === "url") {
    return `[url:value = '${escaped}']`;
  }
  // hash
  if (ioc.length === 32) return `[file:hashes.MD5 = '${escaped}']`;
  if (ioc.length === 40) return `[file:hashes.'SHA-1' = '${escaped}']`;
  return `[file:hashes.'SHA-256' = '${escaped}']`;
}

export function exportReportsAsStix(reports: EnrichmentReport[]): string {
  const identityId = "identity--7a4e6268-9f12-4c2b-9c83-5e77f1d00001";
  const now = new Date().toISOString();

  const objects: Array<Record<string, unknown>> = [
    {
      type: "identity",
      spec_version: "2.1",
      id: identityId,
      created: now,
      modified: now,
      name: "eyesight Threat Intelligence Platform",
      identity_class: "system",
    },
  ];

  for (const r of reports) {
    const indicatorId = `indicator--${crypto.randomUUID()}`;
    const labels = [
      r.verdict,
      ...r.results
        .filter((p) => p.status === "ok" && p.verdict !== "clean")
        .map((p) => `source:${p.providerId}`),
    ];

    objects.push({
      type: "indicator",
      spec_version: "2.1",
      id: indicatorId,
      created: r.timestamp,
      modified: r.timestamp,
      created_by_ref: identityId,
      name: `${r.type.toUpperCase()}: ${r.ioc}`,
      description: r.results
        .filter((p) => p.status === "ok")
        .map((p) => `[${p.providerName}] ${p.summary}`)
        .join("\n"),
      pattern: buildStixPattern(r.ioc, r.type),
      pattern_type: "stix",
      valid_from: r.timestamp,
      confidence: r.compositeScore ?? 0,
      indicator_types:
        r.verdict === "malicious"
          ? ["malicious-activity"]
          : r.verdict === "suspicious"
            ? ["anomalous-activity"]
            : ["benign"],
      labels: Array.from(new Set(labels)),
      extensions: {
        "x-eyesight-enrichment": {
          composite_score: r.compositeScore,
          verdict: r.verdict,
          coverage: `${r.coverageCount}/${r.totalApplicable}`,
        },
      },
    });
  }

  return JSON.stringify(
    {
      type: "bundle",
      id: `bundle--${crypto.randomUUID()}`,
      objects,
    },
    null,
    2,
  );
}
