import type { IocType, ProviderId } from "./catalog";

export type ProviderStatus =
  | "ok"
  | "not_found"
  | "unconfigured"
  | "unsupported"
  | "rate_limited"
  | "error";

export type ThreatVerdict = "clean" | "suspicious" | "malicious" | "unknown";

export interface PivotLink {
  type: IocType | "asn";
  value: string;
  label?: string;
}

export interface ProviderQueryContext {
  ioc: string;
  type: IocType;
  apiKey?: string | null;
}

export interface ProviderResult {
  providerId: ProviderId;
  providerName: string;
  status: ProviderStatus;
  riskScore: number | null; // 0..100 when status is ok or not_found (for threat sources), null otherwise
  verdict: ThreatVerdict;
  summary: string;
  details: Record<string, unknown>;
  pivots: PivotLink[];
  raw?: unknown;
  latencyMs: number;
  cached: boolean;
  fetchedAt: string;
  expiresAt?: string;
}

export interface ProviderAdapter {
  id: ProviderId;
  query(ctx: ProviderQueryContext): Promise<Omit<ProviderResult, "cached" | "fetchedAt" | "expiresAt">>;
}
