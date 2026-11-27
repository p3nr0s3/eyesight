"use client";

import React, { Suspense, useCallback, useEffect, useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import {
  Search,
  Sparkles,
  RefreshCw,
  AlertTriangle,
  Loader2,
  ArrowRight,
  Clock,
  ShieldCheck,
  Radar,
  Layers,
} from "lucide-react";
import { getByokHeaders } from "@/lib/client-byok";
import type { EnrichmentReport } from "@/lib/enrich";
import {
  PROVIDER_CATALOG,
  PROVIDER_MAP,
  TOOL_CATEGORIES,
  type IocType,
  type ProviderId,
  type ToolCategoryId,
} from "@/lib/providers/catalog";
import { resolveToolProfile } from "@/lib/providers/tool-profiles";
import type { ThreatVerdict } from "@/lib/providers/types";
import { useToolCategory } from "@/components/AppShell";
import { ReportView } from "@/components/ReportView";
import { VerdictBadge } from "@/components/VerdictBadge";

interface HistorySummaryItem {
  id: string;
  iocValue: string;
  iocType: string;
  compositeScore: number | null;
  verdict: ThreatVerdict;
  coverageCount: number;
  totalApplicable: number;
  createdAt: string;
}

function detectPreviewIocType(raw: string): {
  label: string;
  iocType: IocType;
} | null {
  const s = raw.trim();
  if (!s) return null;
  if (/^[a-fA-F0-9]{32}$/.test(s)) return { label: "MD5", iocType: "hash" };
  if (/^[a-fA-F0-9]{40}$/.test(s)) return { label: "SHA-1", iocType: "hash" };
  if (/^[a-fA-F0-9]{64}$/.test(s)) return { label: "SHA-256", iocType: "hash" };
  if (/^hxxps?:\/\//i.test(s) || /^https?:\/\//i.test(s)) {
    return { label: "URL", iocType: "url" };
  }
  if (/^\d{1,3}(\[\.\]|\.){3}\d{1,3}(:\d+)?$/.test(s) || s.includes(":")) {
    return { label: "IP", iocType: "ip" };
  }
  if (s.includes(".") || s.includes("[.]")) {
    return { label: "DOMAIN", iocType: "domain" };
  }
  return null;
}

function InvestigateContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const initialIoc = searchParams.get("ioc") || "";
  const urlCategory = searchParams.get("category") as ToolCategoryId | null;
  const urlTool = searchParams.get("tool") as ProviderId | null;
  const {
    selectedCategory,
    setSelectedCategory,
    selectedTool,
    setSelectedTool,
    activeTrail,
    setActiveTrail,
  } = useToolCategory();

  const [query, setQuery] = useState(initialIoc);
  const [forceRefresh, setForceRefresh] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<EnrichmentReport | null>(null);
  const [recent, setRecent] = useState<HistorySummaryItem[]>([]);

  const profile = useMemo(
    () => resolveToolProfile(selectedCategory, selectedTool),
    [selectedCategory, selectedTool],
  );

  const preview = useMemo(() => detectPreviewIocType(query), [query]);

  const incompatibleReason = useMemo(() => {
    if (!preview) return null;
    if (!profile.acceptedTypes.includes(preview.iocType)) {
      return `${activeTrail.item} ACCEPTS ${profile.acceptedTypes
        .join(", ")
        .toUpperCase()} ONLY — DETECTED ${preview.label}.`;
    }
    return null;
  }, [preview, profile.acceptedTypes, activeTrail.item]);

  const activeToolsCount = useMemo(
    () =>
      profile.providerIds
        ? profile.providerIds.length
        : PROVIDER_CATALOG.length,
    [profile.providerIds],
  );

  const loadRecent = useCallback(async () => {
    try {
      const res = await fetch("/api/history?limit=8", { cache: "no-store" });
      if (res.ok) {
        const data = await res.json();
        setRecent(data.items || []);
      }
    } catch {
      // ignore
    }
  }, []);

  const runLookup = useCallback(
    async (
      targetIoc: string,
      refresh = false,
      overrideProviders?: ProviderId[],
    ) => {
      const trimmed = targetIoc.trim();
      if (!trimmed) return;
      setLoading(true);
      setError(null);
      try {
        const providersToSend =
          overrideProviders !== undefined
            ? overrideProviders
            : profile.providerIds;

        const res = await fetch("/api/lookup", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            ...getByokHeaders(),
          },
          body: JSON.stringify({
            ioc: trimmed,
            forceRefresh: refresh,
            providers: providersToSend,
          }),
        });
        const data = await res.json();
        if (!res.ok) {
          setError(data.error || "LOOKUP FAILED");
        } else {
          setReport(data);
          setQuery(data.ioc);

          const nextParams = new URLSearchParams();
          nextParams.set("ioc", data.ioc);
          if (selectedCategory !== "all" && overrideProviders === undefined) {
            nextParams.set("category", selectedCategory);
          }
          if (selectedTool && overrideProviders === undefined) {
            nextParams.set("tool", selectedTool);
          }
          router.replace(`/?${nextParams.toString()}`, { scroll: false });
          loadRecent();
        }
      } catch {
        setError("NETWORK ERROR WHILE QUERYING EYESIGHT API.");
      } finally {
        setLoading(false);
      }
    },
    [loadRecent, profile.providerIds, router, selectedCategory, selectedTool],
  );

  useEffect(() => {
    setError(null);
    if (urlTool && PROVIDER_MAP[urlTool]) {
      const cat = PROVIDER_MAP[urlTool].category;
      setSelectedCategory(cat);
      setSelectedTool(urlTool);
      const catLabel =
        TOOL_CATEGORIES.find((c) => c.id === cat)?.label || "TOOLS";
      setActiveTrail({
        group: catLabel,
        item: PROVIDER_MAP[urlTool].name.toUpperCase(),
      });
    } else if (urlCategory && urlCategory !== "all" && TOOL_CATEGORIES.some((c) => c.id === urlCategory)) {
      setSelectedCategory(urlCategory);
      setSelectedTool(null);
      const catLabel =
        TOOL_CATEGORIES.find((c) => c.id === urlCategory)?.label || "TOOLS";
      setActiveTrail({
        group: catLabel,
        item: `ALL ${catLabel}`,
      });
    } else {
      setSelectedCategory("all");
      setSelectedTool(null);
      setActiveTrail({
        group: "IOC INVESTIGATION",
        item: "IOC LOOKUP",
      });
    }
    if (!initialIoc) {
      setReport(null);
    }
  }, [urlCategory, urlTool, initialIoc, setSelectedCategory, setSelectedTool, setActiveTrail]);

  useEffect(() => {
    loadRecent();
  }, [loadRecent]);

  useEffect(() => {
    if (initialIoc && (!report || report.ioc !== initialIoc)) {
      setQuery(initialIoc);
      runLookup(initialIoc, false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialIoc]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (incompatibleReason) {
      setError(incompatibleReason);
      return;
    }
    runLookup(query, forceRefresh);
  };

  const handleSwitchToAllEngines = () => {
    setSelectedCategory("all");
    setSelectedTool(null);
    setActiveTrail({ group: "IOC INVESTIGATION", item: "IOC LOOKUP" });
    if (report?.ioc) {
      runLookup(report.ioc, false, []);
    } else {
      router.replace("/", { scroll: false });
    }
  };

  return (
    <div className="space-y-6 w-full">
      {/* Tool-Tailored Hero Search Console */}
      <section className="rounded-2xl glass-panel p-5 sm:p-7 lg:p-8 shadow-xl relative overflow-hidden">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 mb-5">
          <div className="space-y-2 max-w-3xl">
            <div className="flex flex-wrap items-center gap-2">
              <div className="inline-flex items-center gap-2 text-[10px] font-bold tracking-widest px-2.5 py-1 rounded-full border border-[var(--border-subtle)] bg-[var(--bg-elevated)]">
                <Radar
                  className="w-3.5 h-3.5"
                  style={{ color: "var(--accent)" }}
                />
                <span>
                  {activeTrail.group} &gt; {activeTrail.item} (
                  {activeToolsCount}{" "}
                  {activeToolsCount === 1 ? "ENGINE" : "ENGINES"})
                </span>
              </div>
              <div className="inline-flex items-center gap-1">
                {profile.acceptedTypes.map((t) => (
                  <span
                    key={t}
                    className="text-[9px] font-extrabold px-2 py-0.5 rounded border"
                    style={{
                      backgroundColor: "var(--accent-soft)",
                      borderColor: "var(--accent-border)",
                      color: "var(--accent)",
                    }}
                  >
                    {t}
                  </span>
                ))}
              </div>
            </div>

            <h1 className="text-xl sm:text-2xl lg:text-3xl font-extrabold tracking-tight">
              {profile.title}
            </h1>
            <p className="text-xs sm:text-sm text-[var(--text-secondary)]">
              {profile.subtitle}
            </p>
          </div>

          <div className="grid grid-cols-2 gap-2.5 shrink-0">
            <div className="px-3.5 py-2.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/70">
              <div className="text-[10px] font-bold text-[var(--text-secondary)]">
                ACTIVE SCOPE
              </div>
              <div
                className="text-lg font-extrabold font-mono-ioc"
                style={{ color: "var(--accent)" }}
              >
                {activeToolsCount}/{PROVIDER_CATALOG.length}
              </div>
            </div>
            <div className="px-3.5 py-2.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/70">
              <div className="text-[10px] font-bold text-[var(--text-secondary)]">
                INPUT TYPES
              </div>
              <div className="text-sm font-extrabold font-mono-ioc text-emerald-400 flex items-center gap-1 mt-1">
                <ShieldCheck className="w-4 h-4 shrink-0" />
                {profile.acceptedTypes.join("/")}
              </div>
            </div>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="space-y-3">
          <div className="flex flex-col sm:flex-row gap-2.5">
            <div className="relative flex-1">
              <Search className="w-4 h-4 text-[var(--text-secondary)] absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
              <input
                type="text"
                value={query}
                onChange={(e) => {
                  setQuery(e.target.value);
                  setError(null);
                }}
                placeholder={profile.placeholder}
                className="w-full pl-10 pr-24 py-3.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] font-mono-ioc text-xs sm:text-sm focus:outline-none focus:border-[var(--accent)] transition"
              />
              {preview && (
                <span
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-[10px] font-extrabold tracking-wider px-2 py-0.5 rounded-md"
                  style={
                    incompatibleReason
                      ? {
                          backgroundColor: "rgba(244,63,94,0.16)",
                          border: "1px solid rgba(244,63,94,0.4)",
                          color: "#fb7185",
                        }
                      : {
                          backgroundColor: "var(--accent-soft)",
                          border: "1px solid var(--accent-border)",
                          color: "var(--accent)",
                        }
                  }
                >
                  {preview.label}
                </span>
              )}
            </div>
            <button
              type="submit"
              disabled={loading || !query.trim() || Boolean(incompatibleReason)}
              style={{ backgroundColor: "var(--accent)" }}
              className="w-full sm:w-auto px-6 py-3.5 rounded-xl hover:opacity-90 disabled:opacity-45 text-white text-xs font-extrabold tracking-wider inline-flex items-center justify-center gap-2 transition cursor-pointer shrink-0 shadow-md"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  ENRICHING...
                </>
              ) : (
                <>
                  {profile.submitLabel}
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </div>

          {incompatibleReason && (
            <div className="p-3 rounded-xl border border-amber-500/35 bg-amber-500/10 text-amber-300 text-xs font-bold flex flex-wrap items-center justify-between gap-2">
              <span className="flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                {incompatibleReason}
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
                style={{ color: "var(--accent)" }}
                className="underline font-extrabold cursor-pointer"
              >
                SWITCH TO UNIFIED IOC LOOKUP
              </button>
            </div>
          )}

          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-1">
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-[11px] font-bold text-[var(--text-secondary)] inline-flex items-center gap-1 mr-1">
                <Sparkles
                  className="w-3.5 h-3.5"
                  style={{ color: "var(--accent)" }}
                />
                SAMPLES:
              </span>
              {profile.samples.map((s) => (
                <button
                  key={s.label}
                  type="button"
                  onClick={() => {
                    setQuery(s.label);
                    runLookup(s.label, forceRefresh);
                  }}
                  title={s.desc}
                  className="text-[11px] font-mono-ioc preserve-case px-2.5 py-1 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-elevated)] hover:border-[var(--accent-border)] transition cursor-pointer"
                >
                  {s.label.length > 24 ? `${s.label.slice(0, 14)}…` : s.label}
                </button>
              ))}
            </div>

            <div className="flex flex-wrap items-center gap-4">
              {(selectedCategory !== "all" || selectedTool) && (
                <button
                  type="button"
                  onClick={handleSwitchToAllEngines}
                  style={{ color: "var(--accent)" }}
                  className="inline-flex items-center gap-1 text-[11px] font-bold hover:underline cursor-pointer"
                >
                  <Layers className="w-3.5 h-3.5" />
                  RUN ACROSS ALL 9 ENGINES
                </button>
              )}

              <label className="inline-flex items-center gap-2 text-[11px] font-semibold text-[var(--text-secondary)] cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={forceRefresh}
                  onChange={(e) => setForceRefresh(e.target.checked)}
                  className="rounded border-[var(--border-subtle)]"
                  style={{ accentColor: "var(--accent)" }}
                />
                <RefreshCw className="w-3 h-3" />
                BYPASS CACHE (FORCE REFRESH)
              </label>
            </div>
          </div>
        </form>

        {error && (
          <div className="mt-4 p-3.5 rounded-xl border border-rose-500/30 bg-rose-500/10 text-rose-400 text-xs font-semibold flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}
      </section>

      {/* Active Report */}
      {loading && !report && (
        <div className="rounded-2xl glass-panel p-12 text-center space-y-3">
          <Loader2
            className="w-8 h-8 animate-spin mx-auto"
            style={{ color: "var(--accent)" }}
          />
          <p className="text-sm font-bold">
            RUNNING {activeTrail.item}...
          </p>
          <p className="text-xs text-[var(--text-secondary)]">
            QUERYING {activeToolsCount} SELECTED THREAT INTEL SOURCE(S)
          </p>
        </div>
      )}

      {report && (
        <ReportView
          report={report}
          defaultTab={profile.defaultTab}
          refreshing={loading}
          onRefresh={() => runLookup(report.ioc, true)}
          onPivot={(nextIoc) => {
            setQuery(nextIoc);
            runLookup(nextIoc, false);
          }}
        />
      )}

      {/* Recent Lookups */}
      {recent.length > 0 && (
        <section className="rounded-2xl glass-panel p-5 space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-[11px] font-bold tracking-widest text-[var(--text-secondary)] flex items-center gap-1.5">
              <Clock className="w-3.5 h-3.5" />
              RECENT LOOKUPS
            </h2>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
            {recent.map((item) => (
              <button
                key={item.id}
                type="button"
                onClick={() => {
                  setQuery(item.iocValue);
                  runLookup(item.iocValue, false);
                }}
                className="text-left p-3.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/55 hover:border-[var(--accent-border)] transition flex items-center justify-between gap-2 cursor-pointer"
              >
                <div className="min-w-0">
                  <div className="font-mono-ioc preserve-case text-xs font-semibold truncate">
                    {item.iocValue}
                  </div>
                  <div className="text-[10px] font-semibold text-[var(--text-secondary)] mt-0.5">
                    {item.iocType} • {item.coverageCount}/{item.totalApplicable}{" "}
                    SOURCES
                  </div>
                </div>
                <div className="shrink-0">
                  <VerdictBadge verdict={item.verdict} />
                </div>
              </button>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}

export default function InvestigatePage() {
  return (
    <Suspense
      fallback={
        <div className="p-12 text-center text-xs font-bold text-[var(--text-secondary)]">
          LOADING EYESIGHT WORKSPACE...
        </div>
      }
    >
      <InvestigateContent />
    </Suspense>
  );
}
