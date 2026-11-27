import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { computeCompositeScore } from "@/lib/scoring";
import type { ProviderResult } from "@/lib/providers/types";

function makeResult(
  partial: Partial<ProviderResult> & { providerId: ProviderResult["providerId"] },
): ProviderResult {
  return {
    providerName: partial.providerId,
    status: "ok",
    riskScore: 0,
    verdict: "clean",
    summary: "",
    details: {},
    pivots: [],
    latencyMs: 10,
    cached: false,
    fetchedAt: new Date().toISOString(),
    ...partial,
  };
}

describe("computeCompositeScore", () => {
  it("excludes unconfigured, unsupported, error, and zero-weight providers from denominator", () => {
    const results: ProviderResult[] = [
      makeResult({ providerId: "virustotal", status: "ok", riskScore: 80, verdict: "malicious" }),
      makeResult({ providerId: "abuseipdb", status: "ok", riskScore: 40, verdict: "suspicious" }),
      makeResult({ providerId: "otx", status: "unconfigured", riskScore: null, verdict: "unknown" }),
      makeResult({ providerId: "shodan", status: "error", riskScore: null, verdict: "unknown" }),
      makeResult({ providerId: "malwarebazaar", status: "unsupported", riskScore: null, verdict: "unknown" }),
      makeResult({ providerId: "network_rdap", status: "ok", riskScore: null, verdict: "unknown" }),
    ];

    const weights = { virustotal: 30, abuseipdb: 10, network_rdap: 0 };
    const summary = computeCompositeScore("ip", results, weights, {
      maliciousThreshold: 70,
      suspiciousThreshold: 30,
    });

    assert.equal(summary.score, 70);
    assert.equal(summary.verdict, "malicious");
    assert.equal(summary.scoredProvidersCount, 2);
    assert.equal(summary.coverageCount, 3);
    assert.equal(summary.totalApplicable, 5);
  });

  it("returns unknown with null score when no weighted providers respond", () => {
    const results: ProviderResult[] = [
      makeResult({ providerId: "virustotal", status: "unconfigured", riskScore: null }),
      makeResult({ providerId: "network_rdap", status: "ok", riskScore: null }),
    ];
    const summary = computeCompositeScore("domain", results, { virustotal: 30, network_rdap: 0 }, {
      maliciousThreshold: 70,
      suspiciousThreshold: 30,
    });
    assert.equal(summary.score, null);
    assert.equal(summary.verdict, "unknown");
  });
});
