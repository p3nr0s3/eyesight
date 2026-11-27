import { describe, it } from "node:test";
import assert from "node:assert/strict";
import type { EnrichmentReport } from "@/lib/enrich";
import { exportReportsAsCsv, exportReportsAsStix } from "@/lib/export";

const sampleReport: EnrichmentReport = {
  ioc: "198.51.100.42",
  defanged: "198[.]51[.]100[.]42",
  type: "ip",
  isPrivateIp: false,
  compositeScore: 85,
  verdict: "malicious",
  coverageCount: 2,
  totalApplicable: 2,
  scoredProvidersCount: 2,
  thresholds: { maliciousThreshold: 70, suspiciousThreshold: 30 },
  pivots: [],
  results: [
    {
      providerId: "virustotal",
      providerName: "VirusTotal",
      status: "ok",
      riskScore: 90,
      verdict: "malicious",
      summary: "12/90 engines flagged malicious",
      details: {},
      pivots: [],
      latencyMs: 120,
      cached: false,
      fetchedAt: "2026-11-27T00:00:00.000Z",
    },
  ],
  timestamp: "2026-11-27T00:00:00.000Z",
  fromCacheCount: 0,
};

describe("export formats", () => {
  it("generates valid CSV with headers and escaped rows", () => {
    const csv = exportReportsAsCsv([sampleReport]);
    const lines = csv.split("\n");
    assert.ok(lines[0].includes("ioc,defanged,type,composite_score,verdict"));
    assert.ok(lines[1].includes("198.51.100.42"));
    assert.ok(lines[1].includes("malicious"));
  });

  it("generates a valid STIX 2.1 bundle with ipv4-addr indicator pattern", () => {
    const raw = exportReportsAsStix([sampleReport]);
    const bundle = JSON.parse(raw);
    assert.equal(bundle.type, "bundle");
    assert.equal(bundle.objects.length, 2);
    const indicator = bundle.objects[1];
    assert.equal(indicator.type, "indicator");
    assert.equal(indicator.spec_version, "2.1");
    assert.equal(indicator.pattern, "[ipv4-addr:value = '198.51.100.42']");
    assert.ok(indicator.indicator_types.includes("malicious-activity"));
  });
});
