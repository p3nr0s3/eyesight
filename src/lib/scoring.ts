import { PROVIDER_MAP, type IocType, type ProviderId } from "./providers/catalog";
import type { ProviderResult, ThreatVerdict } from "./providers/types";

export interface ScoringThresholds {
  maliciousThreshold: number;
  suspiciousThreshold: number;
}

export interface CompositeScoreSummary {
  score: number | null; // 0..100 or null if zero scoring providers responded
  verdict: ThreatVerdict;
  coverageCount: number; // how many applicable providers returned a valid result (ok / not_found)
  totalApplicable: number; // how many enabled providers support this IOC type
  scoredProvidersCount: number; // how many non-informational providers contributed to the score
}

/**
 * Computes normalized 0-100 composite risk score across providers that returned a
 * valid result (`ok` or `not_found` with a non-null riskScore and weight > 0).
 * Excludes unconfigured, unsupported, rate-limited, and errored providers from denominator.
 */
export function computeCompositeScore(
  iocType: IocType,
  results: ProviderResult[],
  weights: Partial<Record<ProviderId, number>>,
  thresholds: ScoringThresholds,
): CompositeScoreSummary {
  const totalApplicable = results.filter((r) => {
    const meta = PROVIDER_MAP[r.providerId];
    return meta?.supportedTypes.includes(iocType) && r.status !== "unsupported";
  }).length;

  const coverageCount = results.filter(
    (r) => r.status === "ok" || r.status === "not_found",
  ).length;

  let weightedSum = 0;
  let totalWeight = 0;
  let scoredProvidersCount = 0;

  for (const r of results) {
    if (r.status !== "ok" && r.status !== "not_found") continue;
    if (r.riskScore === null || Number.isNaN(r.riskScore)) continue;

    const meta = PROVIDER_MAP[r.providerId];
    const weight = weights[r.providerId] ?? meta?.defaultWeight ?? 0;
    if (weight <= 0) continue;

    weightedSum += r.riskScore * weight;
    totalWeight += weight;
    scoredProvidersCount++;
  }

  if (totalWeight <= 0 || scoredProvidersCount === 0) {
    return {
      score: null,
      verdict: "unknown",
      coverageCount,
      totalApplicable,
      scoredProvidersCount: 0,
    };
  }

  const score = Math.max(0, Math.min(100, Math.round(weightedSum / totalWeight)));
  const verdict: ThreatVerdict =
    score >= thresholds.maliciousThreshold
      ? "malicious"
      : score >= thresholds.suspiciousThreshold
        ? "suspicious"
        : "clean";

  return {
    score,
    verdict,
    coverageCount,
    totalApplicable,
    scoredProvidersCount,
  };
}
