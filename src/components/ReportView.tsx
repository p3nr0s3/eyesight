"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import {
  Copy,
  Check,
  RefreshCw,
  Download,
  ExternalLink,
  Shield,
  Globe,
  Code2,
  Activity,
  Database,
  Clock,
  ArrowUpRight,
  Filter,
} from "lucide-react";
import type { EnrichmentReport } from "@/lib/enrich";
import { PROVIDER_MAP, TOOL_CATEGORIES } from "@/lib/providers/catalog";
import type { ProviderStatus } from "@/lib/providers/types";
import { useToolCategory } from "./AppShell";
import { RiskGauge } from "./RiskGauge";
import { VerdictBadge } from "./VerdictBadge";

type TabId = "summary" | "providers" | "network" | "raw";

const STATUS_BADGE: Record<ProviderStatus, { label: string; cls: string }> = {
  ok: {
    label: "RESPONDED",
    cls: "bg-cyan-500/15 text-cyan-400 border-cyan-500/30",
  },
  not_found: {
    label: "NOT LISTED",
    cls: "bg-emerald-500/10 text-emerald-400 border-emerald-500/25",
  },
  unconfigured: {
    label: "KEY NEEDED",
    cls: "bg-amber-500/10 text-amber-400 border-amber-500/25",
  },
  unsupported: {
    label: "UNSUPPORTED",
    cls: "bg-slate-500/10 text-slate-400 border-slate-500/25",
  },
  rate_limited: {
    label: "RATE LIMITED",
    cls: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  },
  error: {
    label: "ERROR",
    cls: "bg-rose-500/15 text-rose-400 border-rose-500/30",
  },
};

export function ReportView({
  report,
  onRefresh,
  refreshing = false,
  onPivot,
  defaultTab = "summary",
}: {
  report: EnrichmentReport;
  onRefresh?: () => void;
  refreshing?: boolean;
  onPivot?: (ioc: string) => void;
  defaultTab?: TabId;
}) {
  const {
    selectedCategory,
    setSelectedCategory,
    selectedTool,
    setSelectedTool,
    setActiveTrail,
  } = useToolCategory();
  const [tab, setTab] = useState<TabId>(defaultTab);

  useEffect(() => {
    setTab(defaultTab);
  }, [defaultTab, report.ioc, report.timestamp]);
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);

  const copyText = async (label: string, text: string) => {
    await navigator.clipboard.writeText(text);
    setCopiedField(label);
    setTimeout(() => setCopiedField(null), 1500);
  };

  const handleExport = async (format: "json" | "csv" | "stix") => {
    setExporting(true);
    try {
      const res = await fetch("/api/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ format, reports: [report] }),
      });
      if (!res.ok) return;
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `eyesight-${report.type}-${format}.${format === "csv" ? "csv" : "json"}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } finally {
      setExporting(false);
    }
  };

  const filteredResults = selectedTool
    ? report.results.filter((r) => r.providerId === selectedTool)
    : selectedCategory === "all"
      ? report.results
      : report.results.filter(
          (r) => PROVIDER_MAP[r.providerId]?.category === selectedCategory,
        );

  const activeCategoryLabel = selectedTool
    ? PROVIDER_MAP[selectedTool]?.name || selectedTool
    : TOOL_CATEGORIES.find((c) => c.id === selectedCategory)?.label || "ALL TOOLS";

  const networkResult = report.results.find(
    (r) => r.providerId === "network_rdap",
  );
  const netDetails = (networkResult?.details || {}) as {
    geo?: Record<string, string | null> | null;
    rdap?: Record<string, unknown> | null;
    dns?: Record<string, string[]> | null;
  };

  const tabs: Array<{
    id: TabId;
    label: string;
    icon: React.ComponentType<{ className?: string }>;
  }> = [
    { id: "summary", label: "SUMMARY", icon: Shield },
    { id: "providers", label: `PROVIDERS (${filteredResults.length})`, icon: Activity },
    { id: "network", label: "NETWORK & DNS", icon: Globe },
    { id: "raw", label: "RAW JSON", icon: Code2 },
  ];

  return (
    <div className="rounded-2xl glass-panel overflow-hidden shadow-xl">
      {/* Header */}
      <div className="p-4 sm:p-6 border-b border-[var(--border-subtle)] flex flex-col xl:flex-row xl:items-center justify-between gap-5">
        <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4 sm:gap-5 min-w-0">
          <RiskGauge score={report.compositeScore} verdict={report.verdict} />
          <div className="min-w-0 space-y-2 w-full">
            <div className="flex flex-wrap items-center gap-2">
              <span
                className="text-[10px] font-bold tracking-wider px-2 py-0.5 rounded-md"
                style={{
                  backgroundColor: "var(--accent-soft)",
                  border: "1px solid var(--accent-border)",
                  color: "var(--accent)",
                }}
              >
                {report.type}
              </span>
              <VerdictBadge verdict={report.verdict} size="md" />
              <span className="text-[11px] px-2.5 py-0.5 rounded-full border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-[var(--text-secondary)]">
                COVERAGE:{" "}
                <strong className="text-[var(--text-primary)]">
                  {report.coverageCount}/{report.totalApplicable}
                </strong>{" "}
                SOURCES
              </span>
              {report.fromCacheCount > 0 && (
                <span className="inline-flex items-center gap-1 text-[10px] font-bold px-2 py-0.5 rounded-full bg-indigo-500/15 text-indigo-300 border border-indigo-500/30">
                  <Database className="w-3 h-3" />
                  {report.fromCacheCount} CACHED
                </span>
              )}
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <h2 className="font-mono-ioc preserve-case text-sm sm:text-lg font-bold break-all">
                {report.ioc}
              </h2>
              <button
                type="button"
                onClick={() => copyText("ioc", report.ioc)}
                title="COPY IOC"
                className="p-1.5 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-elevated)] hover:border-[var(--accent-border)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition cursor-pointer"
              >
                {copiedField === "ioc" ? (
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                ) : (
                  <Copy className="w-3.5 h-3.5" />
                )}
              </button>
              <button
                type="button"
                onClick={() => copyText("defang", report.defanged)}
                className="text-[10px] font-bold px-2.5 py-1 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-elevated)] hover:border-[var(--accent-border)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition cursor-pointer"
              >
                {copiedField === "defang" ? "COPIED DEFANGED!" : "COPY DEFANGED"}
              </button>
            </div>

            <p className="text-[11px] text-[var(--text-secondary)] flex flex-wrap items-center gap-1.5">
              <Clock className="w-3.5 h-3.5 shrink-0" />
              <span>ANALYZED {new Date(report.timestamp).toLocaleString()}</span>
              <span className="hidden sm:inline">•</span>
              <span>
                THRESHOLDS: SUSPICIOUS ≥ {report.thresholds.suspiciousThreshold},
                MALICIOUS ≥ {report.thresholds.maliciousThreshold}
              </span>
            </p>
          </div>
        </div>

        {/* Actions */}
        <div className="flex flex-wrap items-center gap-2 shrink-0">
          {onRefresh && (
            <button
              type="button"
              onClick={onRefresh}
              disabled={refreshing}
              className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] hover:border-[var(--accent-border)] text-[11px] font-bold transition cursor-pointer disabled:opacity-50"
            >
              <RefreshCw
                className={`w-3.5 h-3.5 ${refreshing ? "animate-spin" : ""}`}
              />
              FORCE REFRESH
            </button>
          )}
          <div className="inline-flex rounded-xl border border-[var(--border-subtle)] overflow-hidden">
            <button
              type="button"
              disabled={exporting}
              onClick={() => handleExport("json")}
              className="inline-flex items-center gap-1 px-3 py-2 bg-[var(--bg-elevated)] hover:bg-[var(--accent-soft)] text-[11px] font-bold border-r border-[var(--border-subtle)] transition cursor-pointer"
            >
              <Download className="w-3 h-3" /> JSON
            </button>
            <button
              type="button"
              disabled={exporting}
              onClick={() => handleExport("csv")}
              className="px-3 py-2 bg-[var(--bg-elevated)] hover:bg-[var(--accent-soft)] text-[11px] font-bold border-r border-[var(--border-subtle)] transition cursor-pointer"
            >
              CSV
            </button>
            <button
              type="button"
              disabled={exporting}
              onClick={() => handleExport("stix")}
              className="px-3 py-2 bg-[var(--bg-elevated)] hover:bg-[var(--accent-soft)] text-[11px] font-bold transition cursor-pointer"
            >
              STIX 2.1
            </button>
          </div>
        </div>
      </div>

      {/* Tabs + Active Classification Indicator */}
      <div className="px-3 sm:px-6 border-b border-[var(--border-subtle)] bg-[var(--bg-elevated)]/50 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-1 overflow-x-auto no-scrollbar">
          {tabs.map((t) => {
            const Icon = t.icon;
            const active = tab === t.id;
            return (
              <button
                key={t.id}
                type="button"
                onClick={() => setTab(t.id)}
                style={
                  active
                    ? {
                        borderColor: "var(--accent)",
                        color: "var(--accent)",
                      }
                    : undefined
                }
                className={`flex items-center gap-1.5 px-3 sm:px-4 py-3 text-[11px] font-bold border-b-2 transition whitespace-nowrap cursor-pointer ${
                  active
                    ? ""
                    : "border-transparent text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                {t.label}
              </button>
            );
          })}
        </div>

        {(selectedCategory !== "all" || selectedTool) && (
          <div className="flex items-center gap-2 py-1.5 text-[10px] font-bold">
            <span
              className="inline-flex items-center gap-1 px-2 py-1 rounded-full"
              style={{
                backgroundColor: "var(--accent-soft)",
                border: "1px solid var(--accent-border)",
                color: "var(--accent)",
              }}
            >
              <Filter className="w-3 h-3" />
              FILTER: {activeCategoryLabel}
            </span>
            <button
              type="button"
              onClick={() => {
                setSelectedCategory("all");
                setSelectedTool(null);
                setActiveTrail({
                  group: "IOC INVESTIGATION",
                  item: "IOC LOOKUP",
                });
              }}
              className="text-[var(--text-secondary)] hover:text-[var(--text-primary)] underline cursor-pointer"
            >
              SHOW ALL
            </button>
          </div>
        )}
      </div>

      {/* Tab Content */}
      <div className="p-4 sm:p-6">
        {tab === "summary" && (
          <div className="space-y-6">
            {report.isPrivateIp && (
              <div className="p-4 rounded-xl border border-amber-500/30 bg-amber-500/10 text-xs text-amber-300 font-semibold">
                PRIVATE OR RESERVED IP DETECTED. EXTERNAL PROVIDERS WERE SKIPPED TO PREVENT INTERNAL TOPOLOGY LEAKAGE.
              </div>
            )}

            <div>
              <h3 className="text-[11px] font-bold tracking-widest text-[var(--text-secondary)] mb-3">
                PROVIDER SIGNAL MATRIX ({filteredResults.length})
              </h3>
              {filteredResults.length === 0 ? (
                <div className="p-6 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/40 text-center text-xs text-[var(--text-secondary)]">
                  NO PROVIDERS IN {activeCategoryLabel} SUPPORT {report.type} INDICATORS.{" "}
                  <button
                    type="button"
                    onClick={() => {
                      setSelectedCategory("all");
                      setSelectedTool(null);
                      setActiveTrail({
                        group: "IOC INVESTIGATION",
                        item: "IOC LOOKUP",
                      });
                    }}
                    style={{ color: "var(--accent)" }}
                    className="underline font-bold ml-1 cursor-pointer"
                  >
                    RESET FILTER
                  </button>
                </div>
              ) : (
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 2xl:grid-cols-5 gap-3">
                  {filteredResults.map((r) => {
                    const statusCfg = STATUS_BADGE[r.status];
                    return (
                      <div
                        key={r.providerId}
                        className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/65 hover:border-[var(--accent-border)] transition flex flex-col justify-between gap-2.5"
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-xs font-bold truncate">
                            {r.providerName}
                          </span>
                          <span
                            className={`text-[9px] px-2 py-0.5 rounded-full border font-bold shrink-0 ${statusCfg.cls}`}
                          >
                            {statusCfg.label}
                          </span>
                        </div>
                        <p className="text-[11px] text-[var(--text-secondary)] line-clamp-2 leading-relaxed">
                          {r.summary}
                        </p>
                        <div className="flex items-center justify-between pt-2 border-t border-[var(--border-subtle)]/60 text-[10px] font-bold">
                          {r.riskScore !== null ? (
                            <div className="flex items-center gap-2">
                              <VerdictBadge verdict={r.verdict} />
                              <span className="font-mono-ioc text-[var(--text-secondary)]">
                                {r.riskScore}/100
                              </span>
                            </div>
                          ) : (
                            <span className="text-[var(--text-secondary)]">
                              {PROVIDER_MAP[r.providerId]?.isInformational
                                ? "CONTEXT ONLY"
                                : "NO SCORE"}
                            </span>
                          )}
                          <span className="text-[var(--text-secondary)] font-mono-ioc">
                            {r.cached ? "CACHED" : `${r.latencyMs}MS`}
                          </span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Relationship Pivots */}
            <div>
              <h3 className="text-[11px] font-bold tracking-widest text-[var(--text-secondary)] mb-3">
                RELATIONSHIP PIVOTS ({report.pivots.length})
              </h3>
              {report.pivots.length === 0 ? (
                <p className="text-xs text-[var(--text-secondary)]">
                  NO RELATED IPS, DOMAINS, URLS, HASHES, OR ASNS DISCOVERED.
                </p>
              ) : (
                <div className="flex flex-wrap gap-2">
                  {report.pivots.map((p, idx) => {
                    const pivotable = p.type !== "asn";
                    if (pivotable && onPivot) {
                      return (
                        <button
                          key={`${p.type}-${p.value}-${idx}`}
                          type="button"
                          onClick={() => onPivot(p.value)}
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] hover:border-[var(--accent-border)] text-xs transition cursor-pointer"
                        >
                          <span
                            className="text-[9px] font-extrabold"
                            style={{ color: "var(--accent)" }}
                          >
                            {p.type}
                          </span>
                          <span className="font-mono-ioc preserve-case">
                            {p.value}
                          </span>
                          {p.label && (
                            <span className="text-[10px] text-[var(--text-secondary)]">
                              ({p.label})
                            </span>
                          )}
                          <ArrowUpRight className="w-3 h-3" />
                        </button>
                      );
                    }
                    return (
                      <span
                        key={`${p.type}-${p.value}-${idx}`}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-xs"
                      >
                        <span className="text-[9px] font-extrabold text-[var(--text-secondary)]">
                          {p.type}
                        </span>
                        <span className="font-mono-ioc preserve-case">
                          {p.value}
                        </span>
                        {p.label && (
                          <span className="text-[10px] text-[var(--text-secondary)]">
                            ({p.label})
                          </span>
                        )}
                      </span>
                    );
                  })}
                </div>
              )}
            </div>
          </div>
        )}

        {tab === "providers" && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {filteredResults.map((r) => {
              const meta = PROVIDER_MAP[r.providerId];
              const statusCfg = STATUS_BADGE[r.status];
              const detailEntries = Object.entries(r.details || {}).filter(
                ([, val]) => val !== null && val !== undefined && val !== "",
              );

              return (
                <div
                  key={r.providerId}
                  className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/55 space-y-3"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-bold text-sm">{r.providerName}</span>
                      <span
                        className={`text-[9px] px-2 py-0.5 rounded-full border font-bold ${statusCfg.cls}`}
                      >
                        {statusCfg.label}
                      </span>
                      {r.riskScore !== null && <VerdictBadge verdict={r.verdict} />}
                      {r.status === "unconfigured" && (
                        <Link
                          href="/settings/byok"
                          style={{ color: "var(--accent)" }}
                          className="text-[10px] font-bold hover:underline"
                        >
                          CONFIGURE KEY →
                        </Link>
                      )}
                    </div>
                    <div className="flex items-center gap-3 text-[11px] font-semibold text-[var(--text-secondary)]">
                      {r.riskScore !== null && (
                        <span className="font-mono-ioc">
                          RISK: <strong>{r.riskScore}/100</strong>
                        </span>
                      )}
                      <span className="font-mono-ioc">
                        {r.cached ? "CACHED" : `${r.latencyMs}MS`}
                      </span>
                      {meta?.homepage && (
                        <a
                          href={meta.homepage}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center gap-0.5 hover:underline"
                          style={{ color: "var(--accent)" }}
                        >
                          DOCS <ExternalLink className="w-3 h-3" />
                        </a>
                      )}
                    </div>
                  </div>

                  <p className="text-xs text-[var(--text-primary)] leading-relaxed">
                    {r.summary}
                  </p>

                  {detailEntries.length > 0 && (
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 pt-2.5 border-t border-[var(--border-subtle)]/60">
                      {detailEntries.map(([k, v]) => (
                        <div key={k} className="text-[11px]">
                          <span className="text-[var(--text-secondary)] font-bold">
                            {k}:{" "}
                          </span>
                          <span className="font-mono-ioc preserve-case break-all">
                            {typeof v === "object" ? JSON.stringify(v) : String(v)}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}

        {tab === "network" && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
            <div className="p-4 sm:p-5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/55 space-y-4">
              <h3 className="text-[11px] font-bold tracking-widest text-[var(--text-secondary)]">
                GEOIP & ASN OWNERSHIP
              </h3>
              {netDetails.geo ? (
                <dl className="grid grid-cols-2 gap-3 text-xs">
                  {Object.entries(netDetails.geo).map(([k, v]) => (
                    <div key={k}>
                      <dt className="text-[10px] font-bold text-[var(--text-secondary)]">
                        {k}
                      </dt>
                      <dd className="font-mono-ioc preserve-case mt-0.5">
                        {v || "—"}
                      </dd>
                    </div>
                  ))}
                </dl>
              ) : (
                <p className="text-xs text-[var(--text-secondary)]">
                  NO GEOIP/ASN DATA AVAILABLE FOR THIS INDICATOR TYPE.
                </p>
              )}

              <h3 className="text-[11px] font-bold tracking-widest text-[var(--text-secondary)] pt-4 border-t border-[var(--border-subtle)]">
                RDAP / REGISTRATION
              </h3>
              {netDetails.rdap ? (
                <dl className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                  {Object.entries(netDetails.rdap).map(([k, v]) => (
                    <div key={k}>
                      <dt className="text-[10px] font-bold text-[var(--text-secondary)]">
                        {k}
                      </dt>
                      <dd className="font-mono-ioc preserve-case mt-0.5 break-all">
                        {Array.isArray(v) ? v.join(", ") || "—" : String(v ?? "—")}
                      </dd>
                    </div>
                  ))}
                </dl>
              ) : (
                <p className="text-xs text-[var(--text-secondary)]">
                  NO RDAP METADATA AVAILABLE.
                </p>
              )}
            </div>

            <div className="p-4 sm:p-5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/55 space-y-3">
              <h3 className="text-[11px] font-bold tracking-widest text-[var(--text-secondary)]">
                DNS RECORDS
              </h3>
              {netDetails.dns &&
              Object.values(netDetails.dns).some((arr) => arr?.length > 0) ? (
                <div className="space-y-3">
                  {Object.entries(netDetails.dns).map(([recordType, values]) => {
                    if (!values || values.length === 0) return null;
                    return (
                      <div key={recordType}>
                        <div
                          className="text-[11px] font-bold mb-1"
                          style={{ color: "var(--accent)" }}
                        >
                          {recordType}
                        </div>
                        <div className="space-y-1">
                          {values.map((val, i) => (
                            <div
                              key={i}
                              className="font-mono-ioc preserve-case text-xs px-3 py-1.5 rounded-lg bg-[var(--bg-surface)] border border-[var(--border-subtle)] break-all"
                            >
                              {val}
                            </div>
                          ))}
                        </div>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <p className="text-xs text-[var(--text-secondary)]">
                  NO DNS RECORDS RESOLVED FOR THIS INDICATOR.
                </p>
              )}
            </div>
          </div>
        )}

        {tab === "raw" && (
          <div className="space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="text-[11px] font-semibold text-[var(--text-secondary)]">
                NORMALIZED ENRICHMENT PAYLOAD + RAW PROVIDER RESPONSES
              </span>
              <button
                type="button"
                onClick={() => copyText("json", JSON.stringify(report, null, 2))}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-[11px] font-bold hover:border-[var(--accent-border)] cursor-pointer"
              >
                {copiedField === "json" ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-400" /> COPIED
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" /> COPY JSON
                  </>
                )}
              </button>
            </div>
            <pre className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[#04070e] text-slate-200 font-mono-ioc text-xs overflow-auto max-h-[540px]">
              {JSON.stringify(report, null, 2)}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}
