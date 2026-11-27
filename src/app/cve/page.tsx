"use client";

import React, { Suspense, useCallback, useEffect, useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import {
  Search,
  ShieldAlert,
  Flame,
  Bug,
  Calendar,
  ExternalLink,
  Loader2,
  X,
  Copy,
  Check,
  Sparkles,
  RefreshCw,
  ArrowUpDown,
} from "lucide-react";
import type { CveDashboardData, CveRecord, CveSeverity, KevEntry } from "@/lib/cve";

type CveTab = "overview" | "latest" | "kev" | "search";

const SEVERITY_BADGE: Record<CveSeverity, string> = {
  CRITICAL: "bg-rose-500/20 text-rose-300 border-rose-500/40",
  HIGH: "bg-orange-500/20 text-orange-300 border-orange-500/40",
  MEDIUM: "bg-amber-500/20 text-amber-300 border-amber-500/40",
  LOW: "bg-emerald-500/15 text-emerald-300 border-emerald-500/35",
  NONE: "bg-slate-500/15 text-slate-300 border-slate-500/30",
  UNKNOWN: "bg-slate-500/15 text-slate-300 border-slate-500/30",
};

const CVE_SAMPLES = [
  "CVE-2024-3094",
  "CVE-2024-3400",
  "CVE-2021-44228",
  "fortinet",
  "openssl",
];

function formatShortDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso.slice(0, 10);
  return d.toISOString().slice(0, 10);
}

function CveDashboardContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const urlTab = (searchParams.get("tab") as CveTab | null) || "overview";

  const [tab, setTab] = useState<CveTab>(urlTab);
  const [dashboard, setDashboard] = useState<CveDashboardData | null>(null);
  const [loadingDash, setLoadingDash] = useState(true);
  const [dashError, setDashError] = useState<string | null>(null);

  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("ALL");
  const [kevOnly, setKevOnly] = useState(false);
  const [searching, setSearching] = useState(false);
  const [searchResults, setSearchResults] = useState<CveRecord[] | null>(null);
  const [searchError, setSearchError] = useState<string | null>(null);

  // KEV sub-filter
  const [kevFilter, setKevFilter] = useState("");
  const [ransomwareOnly, setRansomwareOnly] = useState(false);

  // Inspector modal
  const [selectedCve, setSelectedCve] = useState<CveRecord | null>(null);
  const [copiedId, setCopiedId] = useState(false);

  useEffect(() => {
    if (["overview", "latest", "kev", "search"].includes(urlTab)) {
      setTab(urlTab);
    }
  }, [urlTab]);

  const loadDashboard = useCallback(async () => {
    setLoadingDash(true);
    setDashError(null);
    try {
      const res = await fetch("/api/cve?mode=dashboard", { cache: "no-store" });
      const data = await res.json();
      if (!res.ok) {
        setDashError(data.error || "FAILED TO LOAD CVE DASHBOARD");
      } else {
        setDashboard(data);
      }
    } catch {
      setDashError("NETWORK ERROR WHILE FETCHING CVE FEEDS.");
    } finally {
      setLoadingDash(false);
    }
  }, []);

  useEffect(() => {
    loadDashboard();
  }, [loadDashboard]);

  const runSearch = async (targetQuery: string, sev = severity, onlyKev = kevOnly) => {
    setSearching(true);
    setSearchError(null);
    setTab("search");
    try {
      const params = new URLSearchParams({
        mode: "search",
        q: targetQuery.trim(),
        severity: sev,
        kevOnly: String(onlyKev),
      });
      const res = await fetch(`/api/cve?${params.toString()}`, {
        cache: "no-store",
      });
      const data = await res.json();
      if (!res.ok) {
        setSearchError(data.error || "CVE SEARCH FAILED");
      } else {
        setSearchResults(data.results || []);
      }
    } catch {
      setSearchError("NETWORK ERROR WHILE SEARCHING CVE DATABASE.");
    } finally {
      setSearching(false);
    }
  };

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    runSearch(query, severity, kevOnly);
  };

  const openKevInspector = async (kev: KevEntry) => {
    const synthesized: CveRecord = {
      id: kev.cveID,
      published: kev.dateAdded,
      lastModified: kev.dateAdded,
      description: kev.shortDescription,
      cvssScore: null,
      cvssVector: null,
      severity: "HIGH",
      cwes: [],
      references: [],
      affectedProducts: [`${kev.vendorProject} ${kev.product}`.trim()],
      activeExploit: kev,
      source: "kev",
    };
    setSelectedCve(synthesized);

    // Enrich with full NVD/CIRCL CVE details in background
    try {
      const res = await fetch(
        `/api/cve?mode=search&q=${encodeURIComponent(kev.cveID)}`,
        { cache: "no-store" },
      );
      if (res.ok) {
        const data = await res.json();
        const exact = (data.results || []).find(
          (r: CveRecord) => r.id.toUpperCase() === kev.cveID.toUpperCase(),
        );
        if (exact) {
          setSelectedCve(exact);
        }
      }
    } catch {
      // keep synthesized KEV card
    }
  };

  const filteredKevs = useMemo(() => {
    const list = dashboard?.activeExploits || [];
    return list.filter((k) => {
      if (
        ransomwareOnly &&
        k.knownRansomwareCampaignUse?.toLowerCase() !== "known"
      ) {
        return false;
      }
      if (!kevFilter.trim()) return true;
      const needle = kevFilter.toLowerCase();
      return (
        k.cveID.toLowerCase().includes(needle) ||
        k.vendorProject.toLowerCase().includes(needle) ||
        k.product.toLowerCase().includes(needle) ||
        k.vulnerabilityName.toLowerCase().includes(needle)
      );
    });
  }, [dashboard?.activeExploits, kevFilter, ransomwareOnly]);

  const severityBreakdown = useMemo(() => {
    const list = dashboard?.top10Latest || [];
    const counts: Record<string, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      UNKNOWN: 0,
    };
    for (const c of list) {
      counts[c.severity] = (counts[c.severity] || 0) + 1;
    }
    return counts;
  }, [dashboard?.top10Latest]);

  const switchTab = (next: CveTab) => {
    setTab(next);
    router.replace(next === "overview" ? "/cve" : `/cve?tab=${next}`, {
      scroll: false,
    });
  };

  const renderCveCard = (cve: CveRecord) => (
    <button
      key={cve.id}
      type="button"
      onClick={() => setSelectedCve(cve)}
      className="w-full text-left p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/60 hover:border-[var(--accent-border)] transition space-y-2.5 cursor-pointer"
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-mono-ioc preserve-case text-sm font-extrabold">
            {cve.id}
          </span>
          <span
            className={`text-[9px] font-extrabold px-2 py-0.5 rounded-full border ${
              SEVERITY_BADGE[cve.severity]
            }`}
          >
            {cve.severity}
            {cve.cvssScore !== null ? ` · ${cve.cvssScore.toFixed(1)}` : ""}
          </span>
          {cve.activeExploit && (
            <span className="inline-flex items-center gap-1 text-[9px] font-extrabold px-2 py-0.5 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/40">
              <Flame className="w-3 h-3" /> ACTIVE EXPLOIT (KEV)
            </span>
          )}
        </div>
        <span className="text-[10px] font-mono-ioc font-semibold text-[var(--text-secondary)] flex items-center gap-1">
          <Calendar className="w-3 h-3" />
          {formatShortDate(cve.published)}
        </span>
      </div>

      <p className="text-xs text-[var(--text-secondary)] preserve-case line-clamp-2 leading-relaxed">
        {cve.description}
      </p>

      {(cve.affectedProducts.length > 0 || cve.cwes.length > 0) && (
        <div className="flex flex-wrap items-center gap-1.5 pt-1">
          {cve.affectedProducts.slice(0, 3).map((prod) => (
            <span
              key={prod}
              className="text-[9px] font-bold px-2 py-0.5 rounded border border-[var(--border-subtle)] bg-[var(--bg-surface)] text-[var(--text-secondary)]"
            >
              {prod}
            </span>
          ))}
          {cve.cwes.slice(0, 2).map((cwe) => (
            <span
              key={cwe}
              className="text-[9px] font-mono-ioc font-bold px-2 py-0.5 rounded"
              style={{
                backgroundColor: "var(--accent-soft)",
                color: "var(--accent)",
              }}
            >
              {cwe}
            </span>
          ))}
        </div>
      )}
    </button>
  );

  return (
    <div className="space-y-6 w-full">
      {/* Header & KPI Telemetry Strip */}
      <section className="rounded-2xl glass-panel p-5 sm:p-7 space-y-5 shadow-xl">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="space-y-1.5">
            <div
              className="inline-flex items-center gap-2 text-[10px] font-bold tracking-widest px-2.5 py-1 rounded-full"
              style={{
                backgroundColor: "var(--accent-soft)",
                border: "1px solid var(--accent-border)",
                color: "var(--accent)",
              }}
            >
              <Bug className="w-3.5 h-3.5" />
              NVD + CISA KEV VULNERABILITY INTELLIGENCE
            </div>
            <h1 className="text-xl sm:text-2xl lg:text-3xl font-extrabold tracking-tight">
              CVE LOOKUP &amp; ACTIVE EXPLOIT DASHBOARD
            </h1>
            <p className="text-xs sm:text-sm text-[var(--text-secondary)]">
              MONITOR TOP 10 LATEST CVES, CISA KNOWN EXPLOITED VULNERABILITIES (KEV), AND SEARCH CVES SORTED LATEST FIRST.
            </p>
          </div>

          <button
            type="button"
            onClick={loadDashboard}
            disabled={loadingDash}
            className="self-start lg:self-auto inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] hover:border-[var(--accent-border)] text-xs font-bold cursor-pointer disabled:opacity-50"
          >
            <RefreshCw
              className={`w-3.5 h-3.5 ${loadingDash ? "animate-spin" : ""}`}
            />
            REFRESH FEEDS
          </button>
        </div>

        {/* 4 KPI Telemetry Cards */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          <div className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/65">
            <div className="text-[10px] font-bold text-[var(--text-secondary)]">
              TOP 10 LATEST FEED
            </div>
            <div
              className="text-xl sm:text-2xl font-extrabold font-mono-ioc mt-1"
              style={{ color: "var(--accent)" }}
            >
              {dashboard ? dashboard.top10Latest.length : "—"}
            </div>
            <div className="text-[10px] text-[var(--text-secondary)] mt-1">
              NEWEST: {formatShortDate(dashboard?.stats.latestPublishedAt)}
            </div>
          </div>

          <div className="p-4 rounded-xl border border-rose-500/25 bg-rose-500/10">
            <div className="text-[10px] font-bold text-rose-300 flex items-center gap-1">
              <Flame className="w-3.5 h-3.5" /> ACTIVE EXPLOITS (KEV)
            </div>
            <div className="text-xl sm:text-2xl font-extrabold font-mono-ioc text-rose-400 mt-1">
              {dashboard ? dashboard.stats.totalKevCount : "—"}
            </div>
            <div className="text-[10px] text-rose-300/80 mt-1">
              ADDED: {formatShortDate(dashboard?.stats.latestKevDateAdded)}
            </div>
          </div>

          <div className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/65">
            <div className="text-[10px] font-bold text-[var(--text-secondary)]">
              CRITICAL IN TOP 10
            </div>
            <div className="text-xl sm:text-2xl font-extrabold font-mono-ioc text-amber-400 mt-1">
              {dashboard ? dashboard.stats.criticalInLatestCount : "—"}
            </div>
            <div className="text-[10px] text-[var(--text-secondary)] mt-1">
              PEAK CVSS:{" "}
              {dashboard?.stats.highestCvssInLatest !== null &&
              dashboard?.stats.highestCvssInLatest !== undefined
                ? dashboard.stats.highestCvssInLatest.toFixed(1)
                : "—"}
            </div>
          </div>

          <div className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/65">
            <div className="text-[10px] font-bold text-[var(--text-secondary)]">
              RANSOMWARE LINKED (KEV)
            </div>
            <div className="text-xl sm:text-2xl font-extrabold font-mono-ioc text-orange-400 mt-1">
              {dashboard ? dashboard.stats.ransomwareKevCount : "—"}
            </div>
            <div className="text-[10px] text-[var(--text-secondary)] mt-1">
              KNOWN CAMPAIGN USE
            </div>
          </div>
        </div>

        {/* CVE Search Form (Sorted Latest First) */}
        <form onSubmit={handleSearchSubmit} className="space-y-3 pt-2 border-t border-[var(--border-subtle)]">
          <div className="flex flex-col lg:flex-row gap-2.5">
            <div className="relative flex-1">
              <Search className="w-4 h-4 text-[var(--text-secondary)] absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
              <input
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="SEARCH CVE ID (CVE-2024-3094) OR KEYWORD (FORTINET, OPENSSL, WINDOWS)..."
                className="w-full pl-10 pr-4 py-3 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] font-mono-ioc text-xs sm:text-sm focus:outline-none focus:border-[var(--accent)]"
              />
            </div>

            <div className="grid grid-cols-2 sm:flex gap-2">
              <select
                value={severity}
                onChange={(e) => setSeverity(e.target.value)}
                className="px-3 py-3 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-xs font-bold"
              >
                <option value="ALL">ALL SEVERITIES</option>
                <option value="CRITICAL">CRITICAL</option>
                <option value="HIGH">HIGH</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="LOW">LOW</option>
              </select>

              <button
                type="submit"
                disabled={searching}
                style={{ backgroundColor: "var(--accent)" }}
                className="px-5 py-3 rounded-xl hover:opacity-90 disabled:opacity-50 text-white text-xs font-extrabold inline-flex items-center justify-center gap-1.5 cursor-pointer"
              >
                {searching ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" /> SEARCHING
                  </>
                ) : (
                  <>
                    <ArrowUpDown className="w-3.5 h-3.5" /> SEARCH (LATEST)
                  </>
                )}
              </button>
            </div>
          </div>

          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-[11px] font-bold text-[var(--text-secondary)] inline-flex items-center gap-1 mr-1">
                <Sparkles
                  className="w-3.5 h-3.5"
                  style={{ color: "var(--accent)" }}
                />
                SAMPLES:
              </span>
              {CVE_SAMPLES.map((sample) => (
                <button
                  key={sample}
                  type="button"
                  onClick={() => {
                    setQuery(sample);
                    runSearch(sample, severity, kevOnly);
                  }}
                  className="text-[11px] font-mono-ioc preserve-case px-2.5 py-1 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-elevated)] hover:border-[var(--accent-border)] cursor-pointer"
                >
                  {sample}
                </button>
              ))}
            </div>

            <label className="inline-flex items-center gap-2 text-[11px] font-bold text-[var(--text-secondary)] cursor-pointer">
              <input
                type="checkbox"
                checked={kevOnly}
                onChange={(e) => setKevOnly(e.target.checked)}
                className="accent-rose-500"
              />
              <Flame className="w-3.5 h-3.5 text-rose-400" />
              ACTIVE EXPLOITS ONLY (CISA KEV)
            </label>
          </div>
        </form>
      </section>

      {/* Dashboard Navigation Tabs */}
      <div className="flex items-center gap-1.5 overflow-x-auto no-scrollbar border-b border-[var(--border-subtle)] pb-2">
        {(
          [
            { id: "overview", label: "DASHBOARD OVERVIEW" },
            { id: "latest", label: "TOP 10 LATEST CVES" },
            {
              id: "kev",
              label: `ACTIVE EXPLOITS (${dashboard?.activeExploits.length ?? 0})`,
            },
            {
              id: "search",
              label: `SEARCH RESULTS${searchResults ? ` (${searchResults.length})` : ""}`,
            },
          ] as Array<{ id: CveTab; label: string }>
        ).map((t) => {
          const active = tab === t.id;
          return (
            <button
              key={t.id}
              type="button"
              onClick={() => switchTab(t.id)}
              style={
                active
                  ? {
                      backgroundColor: "var(--accent-soft)",
                      borderColor: "var(--accent-border)",
                      color: "var(--accent)",
                    }
                  : undefined
              }
              className={`px-3.5 py-2 rounded-xl border text-xs font-bold whitespace-nowrap transition cursor-pointer ${
                active
                  ? ""
                  : "border-[var(--border-subtle)] bg-[var(--bg-surface)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
              }`}
            >
              {t.label}
            </button>
          );
        })}
      </div>

      {dashError && (
        <div className="p-4 rounded-xl border border-rose-500/30 bg-rose-500/10 text-rose-300 text-xs font-bold">
          {dashError}
        </div>
      )}

      {loadingDash && !dashboard ? (
        <div className="rounded-2xl glass-panel p-12 text-center space-y-3">
          <Loader2
            className="w-8 h-8 animate-spin mx-auto"
            style={{ color: "var(--accent)" }}
          />
          <p className="text-xs font-bold text-[var(--text-secondary)]">
            LOADING NVD LATEST CVES &amp; CISA KEV ACTIVE EXPLOITS...
          </p>
        </div>
      ) : (
        <>
          {/* OVERVIEW */}
          {tab === "overview" && dashboard && (
            <div className="grid grid-cols-1 xl:grid-cols-12 gap-6">
              {/* Top 10 Latest CVEs */}
              <div className="xl:col-span-7 rounded-2xl glass-panel p-5 space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <h2 className="text-sm font-extrabold">
                      TOP 10 LATEST CVES
                    </h2>
                    <p className="text-[11px] text-[var(--text-secondary)]">
                      SORTED NEWEST PUBLISHED FIRST • CLICK ANY CVE TO INSPECT
                    </p>
                  </div>
                  <div className="flex items-center gap-1.5 text-[10px] font-bold">
                    <span className="px-2 py-0.5 rounded bg-rose-500/15 text-rose-300">
                      CRIT: {severityBreakdown.CRITICAL}
                    </span>
                    <span className="px-2 py-0.5 rounded bg-orange-500/15 text-orange-300">
                      HIGH: {severityBreakdown.HIGH}
                    </span>
                    <span className="px-2 py-0.5 rounded bg-amber-500/15 text-amber-300">
                      MED: {severityBreakdown.MEDIUM}
                    </span>
                  </div>
                </div>

                <div className="space-y-3">
                  {dashboard.top10Latest.map((cve) => renderCveCard(cve))}
                </div>
              </div>

              {/* Latest Active Exploits (CISA KEV) */}
              <div className="xl:col-span-5 rounded-2xl glass-panel p-5 space-y-4">
                <div className="flex items-center justify-between gap-2">
                  <div>
                    <h2 className="text-sm font-extrabold flex items-center gap-1.5 text-rose-400">
                      <ShieldAlert className="w-4 h-4" />
                      LATEST ACTIVE EXPLOITS (CISA KEV)
                    </h2>
                    <p className="text-[11px] text-[var(--text-secondary)]">
                      CONFIRMED IN-THE-WILD EXPLOITATION • SORTED BY DATE ADDED
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => switchTab("kev")}
                    style={{ color: "var(--accent)" }}
                    className="text-[11px] font-bold hover:underline cursor-pointer shrink-0"
                  >
                    VIEW ALL →
                  </button>
                </div>

                <div className="space-y-2.5">
                  {dashboard.activeExploits.slice(0, 10).map((kev) => (
                    <button
                      key={kev.cveID}
                      type="button"
                      onClick={() => openKevInspector(kev)}
                      className="w-full text-left p-3.5 rounded-xl border border-rose-500/20 bg-rose-500/5 hover:border-rose-500/45 transition space-y-1.5 cursor-pointer"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-mono-ioc preserve-case text-xs font-extrabold text-rose-300">
                          {kev.cveID}
                        </span>
                        <span className="text-[10px] font-mono-ioc text-[var(--text-secondary)]">
                          ADDED: {kev.dateAdded}
                        </span>
                      </div>
                      <div className="text-xs font-bold">
                        {kev.vendorProject} — {kev.product}
                      </div>
                      <p className="text-[11px] text-[var(--text-secondary)] preserve-case line-clamp-2">
                        {kev.vulnerabilityName}
                      </p>
                      <div className="flex flex-wrap items-center gap-2 pt-1 text-[9px] font-bold">
                        {kev.knownRansomwareCampaignUse?.toLowerCase() ===
                          "known" && (
                          <span className="px-2 py-0.5 rounded bg-orange-500/20 text-orange-300 border border-orange-500/35">
                            RANSOMWARE CAMPAIGN
                          </span>
                        )}
                        <span className="text-[var(--text-secondary)]">
                          DUE: {kev.dueDate}
                        </span>
                      </div>
                    </button>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* TOP 10 LATEST FULL TAB */}
          {tab === "latest" && dashboard && (
            <div className="rounded-2xl glass-panel p-5 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <h2 className="text-sm font-extrabold">
                  TOP 10 LATEST PUBLISHED CVES (SORTED NEWEST FIRST)
                </h2>
                <span className="text-[11px] font-mono-ioc text-[var(--text-secondary)]">
                  UPDATED: {new Date(dashboard.fetchedAt).toLocaleString()}
                </span>
              </div>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
                {dashboard.top10Latest.map((cve) => renderCveCard(cve))}
              </div>
            </div>
          )}

          {/* ACTIVE EXPLOITS FULL TAB */}
          {tab === "kev" && dashboard && (
            <div className="rounded-2xl glass-panel p-5 space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div>
                  <h2 className="text-sm font-extrabold text-rose-400 flex items-center gap-1.5">
                    <Flame className="w-4 h-4" />
                    CISA KNOWN EXPLOITED VULNERABILITIES (LATEST 100)
                  </h2>
                  <p className="text-[11px] text-[var(--text-secondary)]">
                    ACTIVELY EXPLOITED VULNERABILITIES SORTED BY DATE ADDED
                  </p>
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  <input
                    type="text"
                    value={kevFilter}
                    onChange={(e) => setKevFilter(e.target.value)}
                    placeholder="FILTER VENDOR, PRODUCT, OR CVE..."
                    className="px-3 py-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] font-mono-ioc text-xs"
                  />
                  <label className="inline-flex items-center gap-1.5 text-[11px] font-bold cursor-pointer">
                    <input
                      type="checkbox"
                      checked={ransomwareOnly}
                      onChange={(e) => setRansomwareOnly(e.target.checked)}
                      className="accent-orange-500"
                    />
                    RANSOMWARE ONLY
                  </label>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
                {filteredKevs.map((kev) => (
                  <button
                    key={kev.cveID}
                    type="button"
                    onClick={() => openKevInspector(kev)}
                    className="text-left p-4 rounded-xl border border-rose-500/20 bg-rose-500/5 hover:border-rose-500/45 transition space-y-2 cursor-pointer"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono-ioc preserve-case text-xs font-extrabold text-rose-300">
                        {kev.cveID}
                      </span>
                      <span className="text-[10px] font-mono-ioc text-[var(--text-secondary)]">
                        {kev.dateAdded}
                      </span>
                    </div>
                    <div className="text-xs font-bold">
                      {kev.vendorProject} · {kev.product}
                    </div>
                    <p className="text-[11px] text-[var(--text-secondary)] preserve-case line-clamp-2">
                      {kev.shortDescription}
                    </p>
                    <div className="flex flex-wrap gap-1.5 pt-1 text-[9px] font-bold">
                      {kev.knownRansomwareCampaignUse?.toLowerCase() ===
                        "known" && (
                        <span className="px-2 py-0.5 rounded bg-orange-500/20 text-orange-300 border border-orange-500/35">
                          RANSOMWARE
                        </span>
                      )}
                      <span className="px-2 py-0.5 rounded border border-[var(--border-subtle)] text-[var(--text-secondary)]">
                        DUE {kev.dueDate}
                      </span>
                    </div>
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* SEARCH RESULTS TAB */}
          {tab === "search" && (
            <div className="rounded-2xl glass-panel p-5 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <h2 className="text-sm font-extrabold">
                  CVE SEARCH RESULTS (SORTED LATEST FIRST)
                </h2>
                {searchResults && (
                  <span className="text-xs font-mono-ioc text-[var(--text-secondary)]">
                    {searchResults.length} MATCHING CVE(S)
                  </span>
                )}
              </div>

              {searchError && (
                <div className="p-3.5 rounded-xl border border-rose-500/30 bg-rose-500/10 text-rose-300 text-xs font-bold">
                  {searchError}
                </div>
              )}

              {searching ? (
                <div className="p-10 text-center text-xs font-bold text-[var(--text-secondary)] flex items-center justify-center gap-2">
                  <Loader2 className="w-4 h-4 animate-spin" /> QUERYING NVD &amp; CISA KEV...
                </div>
              ) : searchResults === null ? (
                <div className="p-10 text-center text-xs font-bold text-[var(--text-secondary)]">
                  ENTER A CVE ID OR KEYWORD ABOVE TO SEARCH VULNERABILITIES SORTED FROM LATEST.
                </div>
              ) : searchResults.length === 0 ? (
                <div className="p-10 text-center text-xs font-bold text-[var(--text-secondary)]">
                  NO MATCHING CVES FOUND FOR THE CURRENT QUERY AND FILTERS.
                </div>
              ) : (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
                  {searchResults.map((cve) => renderCveCard(cve))}
                </div>
              )}
            </div>
          )}
        </>
      )}

      {/* CVE Detail Inspector Modal (Near-Fullscreen Workspace) */}
      {selectedCve && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-2 sm:p-4">
          <div className="w-[96vw] max-w-[1600px] h-[92vh] max-h-[92vh] flex flex-col rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-surface-solid)] shadow-2xl overflow-hidden">
            {/* Sticky Header */}
            <div className="shrink-0 flex items-start justify-between gap-4 border-b border-[var(--border-subtle)] bg-[var(--bg-surface)] px-5 sm:px-8 py-4">
              <div className="space-y-1.5 min-w-0">
                <div className="flex flex-wrap items-center gap-2.5">
                  <h2 className="font-mono-ioc preserve-case text-xl sm:text-2xl font-extrabold">
                    {selectedCve.id}
                  </h2>
                  <span
                    className={`text-[11px] font-extrabold px-3 py-0.5 rounded-full border ${
                      SEVERITY_BADGE[selectedCve.severity]
                    }`}
                  >
                    {selectedCve.severity}
                    {selectedCve.cvssScore !== null
                      ? ` · CVSS ${selectedCve.cvssScore.toFixed(1)}`
                      : ""}
                  </span>
                  <button
                    type="button"
                    onClick={async () => {
                      await navigator.clipboard.writeText(selectedCve.id);
                      setCopiedId(true);
                      setTimeout(() => setCopiedId(false), 1500);
                    }}
                    className="p-1.5 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-elevated)] cursor-pointer"
                    title="COPY CVE ID"
                  >
                    {copiedId ? (
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                    ) : (
                      <Copy className="w-3.5 h-3.5" />
                    )}
                  </button>
                </div>
                <div className="text-xs font-mono-ioc text-[var(--text-secondary)]">
                  PUBLISHED: {formatShortDate(selectedCve.published)} • MODIFIED:{" "}
                  {formatShortDate(selectedCve.lastModified)} • SOURCE:{" "}
                  {selectedCve.source}
                </div>
              </div>

              <button
                type="button"
                onClick={() => setSelectedCve(null)}
                className="p-2.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] hover:border-[var(--accent-border)] cursor-pointer shrink-0"
                aria-label="Close CVE details"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Scrollable 12-Col Body */}
            <div className="flex-1 overflow-y-auto px-5 sm:px-8 py-6">
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                <div className="lg:col-span-7 space-y-5">
                  {selectedCve.activeExploit && (
                    <div className="p-5 rounded-xl border border-rose-500/40 bg-rose-500/10 space-y-2.5">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="text-xs font-extrabold text-rose-300 flex items-center gap-1.5">
                          <Flame className="w-4 h-4" />
                          CISA KEV ACTIVE EXPLOIT ALERT
                        </span>
                        {selectedCve.activeExploit.knownRansomwareCampaignUse?.toLowerCase() ===
                          "known" && (
                          <span className="text-[10px] font-extrabold px-2.5 py-0.5 rounded bg-orange-500/20 text-orange-300 border border-orange-500/40">
                            KNOWN RANSOMWARE USE
                          </span>
                        )}
                      </div>
                      <div className="text-sm font-bold">
                        {selectedCve.activeExploit.vendorProject} —{" "}
                        {selectedCve.activeExploit.product} (
                        {selectedCve.activeExploit.vulnerabilityName})
                      </div>
                      <div className="text-xs sm:text-sm preserve-case leading-relaxed text-rose-100/90">
                        <strong>REQUIRED ACTION:</strong>{" "}
                        {selectedCve.activeExploit.requiredAction}
                      </div>
                      <div className="text-[11px] font-mono-ioc text-rose-200/80">
                        ADDED TO KEV: {selectedCve.activeExploit.dateAdded} • DUE DATE:{" "}
                        {selectedCve.activeExploit.dueDate}
                      </div>
                    </div>
                  )}

                  <div className="p-5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/40 space-y-2">
                    <div className="text-[11px] font-bold tracking-widest text-[var(--text-secondary)]">
                      VULNERABILITY DESCRIPTION
                    </div>
                    <p className="text-xs sm:text-sm preserve-case leading-relaxed text-[var(--text-primary)]">
                      {selectedCve.description}
                    </p>
                  </div>

                  {selectedCve.cvssVector && (
                    <div className="p-5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/40 space-y-2">
                      <div className="text-[11px] font-bold tracking-widest text-[var(--text-secondary)]">
                        CVSS VECTOR STRING
                      </div>
                      <code className="block p-3 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-surface)] font-mono-ioc preserve-case text-xs sm:text-sm break-all">
                        {selectedCve.cvssVector}
                      </code>
                    </div>
                  )}
                </div>

                <div className="lg:col-span-5 space-y-5">
                  {selectedCve.cwes && selectedCve.cwes.length > 0 && (
                    <div className="p-5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/40 space-y-2.5">
                      <div className="text-[11px] font-bold tracking-widest text-[var(--text-secondary)]">
                        WEAKNESS CLASSIFICATION (CWE)
                      </div>
                      <div className="flex flex-wrap gap-1.5">
                        {selectedCve.cwes.map((cwe) => (
                          <span
                            key={cwe}
                            className="text-xs font-mono-ioc px-2.5 py-1 rounded-lg border border-amber-500/35 bg-amber-500/10 text-amber-300"
                          >
                            {cwe}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {selectedCve.affectedProducts.length > 0 && (
                    <div className="p-5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/40 space-y-2.5">
                      <div className="text-[11px] font-bold tracking-widest text-[var(--text-secondary)]">
                        AFFECTED PRODUCTS / VENDORS ({selectedCve.affectedProducts.length})
                      </div>
                      <div className="flex flex-wrap gap-1.5 max-h-60 overflow-y-auto">
                        {selectedCve.affectedProducts.map((p) => (
                          <span
                            key={p}
                            className="text-xs font-mono-ioc preserve-case px-2.5 py-1 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-surface)]"
                          >
                            {p}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  <div className="p-5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/40 space-y-2.5">
                    <div className="text-[11px] font-bold tracking-widest text-[var(--text-secondary)]">
                      REFERENCES &amp; ADVISORIES
                    </div>
                    <div className="flex flex-wrap gap-2">
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(selectedCve.id)}`}
                        target="_blank"
                        rel="noreferrer"
                        style={{
                          backgroundColor: "var(--accent-soft)",
                          borderColor: "var(--accent-border)",
                          color: "var(--accent)",
                        }}
                        className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg border text-xs font-bold"
                      >
                        NVD RECORD <ExternalLink className="w-3.5 h-3.5" />
                      </a>
                      {selectedCve.references.map((ref) => (
                        <a
                          key={ref}
                          href={ref}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-surface)] text-[11px] font-mono-ioc preserve-case max-w-full truncate hover:border-[var(--accent-border)]"
                        >
                          <span className="truncate max-w-[320px]">{ref}</span>
                          <ExternalLink className="w-3 h-3 shrink-0" />
                        </a>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Sticky Footer */}
            <div className="shrink-0 flex flex-wrap items-center justify-between gap-3 border-t border-[var(--border-subtle)] bg-[var(--bg-surface)] px-5 sm:px-8 py-3.5">
              <span className="text-[11px] font-mono-ioc text-[var(--text-secondary)]">
                CVE DOSSIER WORKSPACE · {selectedCve.id}
              </span>
              <button
                type="button"
                onClick={() => setSelectedCve(null)}
                className="px-4 py-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-xs font-bold cursor-pointer"
              >
                CLOSE INSPECTOR
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default function CvePage() {
  return (
    <Suspense
      fallback={
        <div className="p-12 text-center text-xs font-bold text-[var(--text-secondary)]">
          LOADING CVE INTELLIGENCE DASHBOARD...
        </div>
      }
    >
      <CveDashboardContent />
    </Suspense>
  );
}
