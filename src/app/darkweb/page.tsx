"use client";

import React, { Suspense, useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import {
  Skull,
  Search,
  RefreshCw,
  ShieldAlert,
  Database,
  Globe,
  Eye,
  Plus,
  Trash2,
  ExternalLink,
  Loader2,
  Sparkles,
  CheckCircle2,
  AlertTriangle,
  KeyRound,
  MapPin,
  Download,
  Copy,
  Check,
  X,
  ArrowUpRight,
  Server,
  BarChart3,
  LockOpen,
  UserCheck,
  ShieldOff,
  Radio,
  Activity,
} from "lucide-react";
import {
  COUNTRY_CATALOG,
  type BreachRecord,
  type DarkwebInfraStats,
  type DarkwebSearchResult,
  type LeakedDomainEntry,
  type MonitorEvaluation,
  type RansomwareVictim,
} from "@/lib/darkweb";
import type {
  CredentialLeakReport,
  LiveGlobalBreachItem,
} from "@/lib/credentials";
import { PaginationControls } from "@/components/PaginationControls";

type DarkwebTab =
  | "ransomware"
  | "credentials"
  | "breaches"
  | "actors"
  | "monitors"
  | "search";

function safeGetStorage(key: string): string | null {
  try {
    return typeof window !== "undefined" ? window.localStorage.getItem(key) : null;
  } catch {
    return null;
  }
}

function safeSetStorage(key: string, value: string): void {
  try {
    if (typeof window !== "undefined") {
      window.localStorage.setItem(key, value);
    }
  } catch {
    // Ignore storage restriction errors in private/sandboxed browsers
  }
}

interface DashboardResponse {
  victims: RansomwareVictim[];
  groups: string[];
  markets: string[];
  breaches: BreachRecord[];
  leakedDomains: LeakedDomainEntry[];
  infraStats: DarkwebInfraStats | null;
  topGroups: Array<{ name: string; count: number }>;
  topSectors: Array<{ name: string; count: number }>;
  topCountries: Array<{ code: string; name: string; count: number }>;
  stats: {
    recentVictimsCount: number;
    groupsCount: number;
    marketsCount: number;
    breachesCount: number;
    stealerBreachesCount: number;
    leakedDomainsCount: number;
    latestVictimDate: string | null;
    latestBreachDate: string | null;
  };
  fetchedAt: string;
}

interface MonitorItem {
  id: string;
  target: string;
  targetType: "DOMAIN" | "BRAND" | "EMAIL" | "KEYWORD";
  notes: string | null;
  evaluation: MonitorEvaluation;
}

const DARKWEB_SAMPLES = ["dropbox.com", "university", "lockbit", "adobe.com"];
const COUNTRY_STORAGE_KEY = "eyesight_darkweb_country";

function DarkwebDashboardContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const urlTab = (searchParams.get("tab") as DarkwebTab | null) || "ransomware";

  const [tab, setTab] = useState<DarkwebTab>(urlTab);
  const [dash, setDash] = useState<DashboardResponse | null>(null);
  const [monitors, setMonitors] = useState<MonitorItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Target Country Focus (persisted)
  const [targetCountry, setTargetCountry] = useState<string>("ALL");

  // Search state
  const [query, setQuery] = useState("");
  const [hibpKey, setHibpKey] = useState("");
  const [showHibpInput, setShowHibpInput] = useState(false);
  const [searching, setSearching] = useState(false);
  const [searchResult, setSearchResult] = useState<DarkwebSearchResult | null>(
    null,
  );

  // Sub-filters & Pagination
  const [victimFilter, setVictimFilter] = useState("");
  const [groupFilter, setGroupFilter] = useState("ALL");
  const [sectorFilter, setSectorFilter] = useState("ALL");
  const [victimPage, setVictimPage] = useState(1);
  const [victimPageSize, setVictimPageSize] = useState(12);

  const [stealerOnly, setStealerOnly] = useState(false);
  const [breachFilter, setBreachFilter] = useState("");
  const [breachPage, setBreachPage] = useState(1);
  const [breachPageSize, setBreachPageSize] = useState(12);

  const [leakDomainFilter, setLeakDomainFilter] = useState("");
  const [leakPage, setLeakPage] = useState(1);

  const [actorFilter, setActorFilter] = useState("");
  const [groupPage, setGroupPage] = useState(1);

  // Incident Dossier Modal
  const [selectedVictim, setSelectedVictim] = useState<RansomwareVictim | null>(
    null,
  );
  const [copiedToken, setCopiedToken] = useState<string | null>(null);

  // Credential Leak Monitoring state (Uncensored default ON)
  const [credQuery, setCredQuery] = useState("");
  const [credLoading, setCredLoading] = useState(false);
  const [credError, setCredError] = useState<string | null>(null);
  const [credReport, setCredReport] = useState<CredentialLeakReport | null>(
    null,
  );
  const [credPage, setCredPage] = useState(1);
  const [credPageSize, setCredPageSize] = useState(50);
  const [uncensoredMode, setUncensoredMode] = useState(true);
  const [xonBreachPage, setXonBreachPage] = useState(1);
  const [leakCheckPage, setLeakCheckPage] = useState(1);
  const [recentGlobalBreaches, setRecentGlobalBreaches] = useState<
    LiveGlobalBreachItem[]
  >([]);
  const [globalBreachPage, setGlobalBreachPage] = useState(1);

  // Real-time auto-sync controls
  const [liveStream, setLiveStream] = useState(true);
  const [liveIntervalSec, setLiveIntervalSec] = useState(45);
  const [liveCountdown, setLiveCountdown] = useState(45);

  // Add Monitor Form
  const [monTarget, setMonTarget] = useState("");
  const [monType, setMonType] = useState<"DOMAIN" | "BRAND" | "EMAIL" | "KEYWORD">(
    "DOMAIN",
  );
  const [monNotes, setMonNotes] = useState("");
  const [expandedMonitorId, setExpandedMonitorId] = useState<string | null>(null);

  useEffect(() => {
    if (
      [
        "ransomware",
        "credentials",
        "breaches",
        "actors",
        "monitors",
        "search",
      ].includes(urlTab)
    ) {
      setTab(urlTab);
    }
  }, [urlTab]);

  useEffect(() => {
    setHibpKey(safeGetStorage("eyesight_hibp_key") || "");
    const savedCountry = safeGetStorage(COUNTRY_STORAGE_KEY);
    if (savedCountry) setTargetCountry(savedCountry);
  }, []);

  const handleCountryChange = (code: string) => {
    setTargetCountry(code);
    setVictimPage(1);
    safeSetStorage(COUNTRY_STORAGE_KEY, code);
  };

  const loadAll = useCallback(async (refresh = false) => {
    setLoading(true);
    setError(null);
    try {
      const [dwRes, monRes, feedRes] = await Promise.all([
        fetch(`/api/darkweb?mode=dashboard${refresh ? "&refresh=true" : ""}`, {
          cache: "no-store",
        }),
        fetch("/api/darkweb/monitors", { cache: "no-store" }),
        fetch(
          `/api/darkweb/credentials?mode=feed${refresh ? "&refresh=true" : ""}`,
          { cache: "no-store" },
        ),
      ]);
      const dwData = await dwRes.json();
      if (!dwRes.ok) {
        setError(dwData.error || "FAILED TO LOAD DARKWEB FEEDS");
      } else {
        setDash(dwData);
      }
      if (monRes.ok) {
        const monData = await monRes.json();
        setMonitors(monData.items || []);
      }
      if (feedRes.ok) {
        const feedData = await feedRes.json();
        setRecentGlobalBreaches(feedData.recentBreaches || []);
      }
    } catch {
      setError("NETWORK ERROR WHILE FETCHING DARKWEB INTELLIGENCE.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadAll(false);
  }, [loadAll]);

  useEffect(() => {
    setLiveCountdown(liveIntervalSec);
    if (!liveStream) return;

    const timer = setInterval(() => {
      setLiveCountdown((prev) => {
        if (prev <= 1) {
          loadAll(true);
          return liveIntervalSec;
        }
        return prev - 1;
      });
    }, 1000);

    return () => clearInterval(timer);
  }, [liveStream, liveIntervalSec, loadAll]);

  const runSearch = async (targetQuery: string) => {
    if (!targetQuery.trim()) return;
    setSearching(true);
    setTab("search");
    try {
      const headers: Record<string, string> = {};
      if (hibpKey.trim()) {
        headers["X-HIBP-Key"] = hibpKey.trim();
        safeSetStorage("eyesight_hibp_key", hibpKey.trim());
      }
      const res = await fetch(
        `/api/darkweb?mode=search&q=${encodeURIComponent(targetQuery.trim())}`,
        { cache: "no-store", headers },
      );
      const data = await res.json();
      if (res.ok) {
        setSearchResult(data);
      }
    } finally {
      setSearching(false);
    }
  };

  const runCredentialScan = async (
    targetQuery: string,
    page = 1,
    pageSize = credPageSize,
    forceRefresh = false,
  ) => {
    const clean = targetQuery.trim();
    if (!clean) return;
    setCredQuery(clean);
    setCredLoading(true);
    setCredError(null);
    setTab("credentials");
    if (page === 1) {
      setXonBreachPage(1);
      setLeakCheckPage(1);
    }
    setCredPage(page);
    setCredPageSize(pageSize);

    try {
      const start = Math.max(0, (page - 1) * pageSize);
      const res = await fetch(
        `/api/darkweb/credentials?q=${encodeURIComponent(clean)}&start=${start}&limit=${pageSize}${forceRefresh ? "&refresh=true" : ""}`,
        { cache: "no-store" },
      );
      const data = await res.json();
      if (!res.ok) {
        setCredError(data.error || "FAILED TO SCAN CREDENTIAL LEAK SOURCES.");
      } else {
        setCredReport(data);
      }
    } catch {
      setCredError("NETWORK ERROR WHILE SCANNING CREDENTIAL LEAK SOURCES.");
    } finally {
      setCredLoading(false);
    }
  };

  const exportCredentials = (format: "csv" | "json") => {
    if (!credReport || credReport.comb.records.length === 0) return;
    const rows = credReport.comb.records;
    let content = "";
    let mime = "application/json";
    if (format === "json") {
      content = JSON.stringify(credReport, null, 2);
    } else {
      mime = "text/csv";
      const header = [
        "index",
        "identifier",
        "domain",
        "secret",
        "leak_date",
        "source_corpus",
        "evidence_source",
        "evidence_url",
        "raw_line",
      ];
      const body = rows.map((r) =>
        [
          r.index,
          r.identifier,
          r.domain || "",
          r.secret,
          r.leakDate || "",
          r.sourceCorpus,
          r.evidenceSource || "",
          r.evidenceUrl || "",
          r.rawLine,
        ]
          .map((c) => `"${String(c).replace(/"/g, '""')}"`)
          .join(","),
      );
      content = [header.join(","), ...body].join("\n");
    }
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `eyesight-credential-leaks-${credReport.query.replace(/[^a-z0-9._-]/gi, "_")}.${format}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    runSearch(query);
  };

  const handleAddMonitor = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!monTarget.trim()) return;
    const res = await fetch("/api/darkweb/monitors", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target: monTarget.trim(),
        targetType: monType,
        notes: monNotes.trim() || null,
      }),
    });
    if (res.ok) {
      setMonTarget("");
      setMonNotes("");
      loadAll(false);
    }
  };

  const handleDeleteMonitor = async (id: string) => {
    const res = await fetch(`/api/darkweb/monitors?id=${encodeURIComponent(id)}`, {
      method: "DELETE",
    });
    if (res.ok) loadAll(false);
  };

  const switchTab = (next: DarkwebTab) => {
    setTab(next);
    router.replace(next === "ransomware" ? "/darkweb" : `/darkweb?tab=${next}`, {
      scroll: false,
    });
  };

  const copyValue = async (key: string, val: string) => {
    await navigator.clipboard.writeText(val);
    setCopiedToken(key);
    setTimeout(() => setCopiedToken(null), 1500);
  };

  // Victims filters & pagination
  const victimGroups = useMemo(() => {
    return Array.from(new Set((dash?.victims || []).map((v) => v.group))).sort();
  }, [dash?.victims]);

  const victimSectors = useMemo(() => {
    return Array.from(new Set((dash?.victims || []).map((v) => v.sector))).sort();
  }, [dash?.victims]);

  const filteredVictims = useMemo(() => {
    return (dash?.victims || []).filter((v) => {
      if (targetCountry !== "ALL" && v.countryCode !== targetCountry) {
        return false;
      }
      if (groupFilter !== "ALL" && v.group !== groupFilter) return false;
      if (sectorFilter !== "ALL" && v.sector !== sectorFilter) return false;
      if (!victimFilter.trim()) return true;
      const needle = victimFilter.toLowerCase();
      return (
        v.victim.toLowerCase().includes(needle) ||
        v.group.toLowerCase().includes(needle) ||
        v.description.toLowerCase().includes(needle) ||
        v.countryName.toLowerCase().includes(needle) ||
        (v.extractedDomain && v.extractedDomain.toLowerCase().includes(needle))
      );
    });
  }, [dash?.victims, targetCountry, groupFilter, sectorFilter, victimFilter]);

  useEffect(() => {
    setVictimPage(1);
  }, [targetCountry, groupFilter, sectorFilter, victimFilter, victimPageSize]);

  const pagedVictims = useMemo(() => {
    const start = (victimPage - 1) * victimPageSize;
    return filteredVictims.slice(start, start + victimPageSize);
  }, [filteredVictims, victimPage, victimPageSize]);

  // Breaches filters & pagination
  const filteredBreaches = useMemo(() => {
    const needle = breachFilter.trim().toLowerCase();
    return (dash?.breaches || []).filter((b) => {
      if (stealerOnly && !b.isStealerLog) return false;
      if (!needle) return true;
      return (
        b.title.toLowerCase().includes(needle) ||
        b.domain.toLowerCase().includes(needle) ||
        b.dataClasses.some((d) => d.toLowerCase().includes(needle))
      );
    });
  }, [dash?.breaches, stealerOnly, breachFilter]);

  useEffect(() => {
    setBreachPage(1);
  }, [stealerOnly, breachFilter, breachPageSize]);

  const pagedBreaches = useMemo(() => {
    const start = (breachPage - 1) * breachPageSize;
    return filteredBreaches.slice(start, start + breachPageSize);
  }, [filteredBreaches, breachPage, breachPageSize]);

  // Leaked domains pagination
  const filteredLeakDomains = useMemo(() => {
    const needle = leakDomainFilter.trim().toLowerCase();
    return (dash?.leakedDomains || []).filter((d) =>
      needle ? d.domain.toLowerCase().includes(needle) : true,
    );
  }, [dash?.leakedDomains, leakDomainFilter]);

  useEffect(() => {
    setLeakPage(1);
  }, [leakDomainFilter]);

  const pagedLeakDomains = useMemo(() => {
    const start = (leakPage - 1) * 20;
    return filteredLeakDomains.slice(start, start + 20);
  }, [filteredLeakDomains, leakPage]);

  // Actors & Markets pagination
  const filteredGroups = useMemo(() => {
    const needle = actorFilter.trim().toLowerCase();
    return (dash?.groups || []).filter((g) =>
      needle ? g.toLowerCase().includes(needle) : true,
    );
  }, [dash?.groups, actorFilter]);

  useEffect(() => {
    setGroupPage(1);
  }, [actorFilter]);

  const pagedGroups = useMemo(() => {
    const start = (groupPage - 1) * 60;
    return filteredGroups.slice(start, start + 60);
  }, [filteredGroups, groupPage]);

  const filteredMarkets = useMemo(() => {
    const needle = actorFilter.trim().toLowerCase();
    return (dash?.markets || []).filter((m) =>
      needle ? m.toLowerCase().includes(needle) : true,
    );
  }, [dash?.markets, actorFilter]);

  const alertMonitorsCount = useMemo(
    () => monitors.filter((m) => m.evaluation.matchCount > 0).length,
    [monitors],
  );

  const exportVictims = (format: "json" | "csv") => {
    if (filteredVictims.length === 0) return;
    let content = "";
    let mime = "application/json";
    if (format === "json") {
      content = JSON.stringify(filteredVictims, null, 2);
    } else {
      mime = "text/csv";
      const headers = [
        "victim",
        "group",
        "country",
        "sector",
        "domain",
        "discovered",
        "misp_uuid",
      ];
      const rows = filteredVictims.map((v) =>
        [
          v.victim,
          v.group,
          v.countryCode,
          v.sector,
          v.extractedDomain || "",
          v.discovered,
          v.mispUuid || "",
        ]
          .map((c) => `"${String(c).replace(/"/g, '""')}"`)
          .join(","),
      );
      content = [headers.join(","), ...rows].join("\n");
    }
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `eyesight-darkweb-victims-${targetCountry.toLowerCase()}.${format}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const selectedCountryName =
    COUNTRY_CATALOG.find((c) => c.code === targetCountry)?.name || targetCountry;

  return (
    <div className="space-y-6 w-full">
      {/* Header, Country Focus & KPI Telemetry */}
      <section className="rounded-2xl glass-panel p-5 sm:p-7 space-y-5 shadow-xl">
        <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-4">
          <div className="space-y-1.5">
            <div
              className="inline-flex items-center gap-2 text-[10px] font-bold tracking-widest px-2.5 py-1 rounded-full"
              style={{
                backgroundColor: "var(--accent-soft)",
                border: "1px solid var(--accent-border)",
                color: "var(--accent)",
              }}
            >
              <Skull className="w-3.5 h-3.5" />
              RANSOMLOOK + HIBP BREACHES + MISP CORRELATION
            </div>
            <h1 className="text-xl sm:text-2xl lg:text-3xl font-extrabold tracking-tight">
              DARKWEB MONITORING &amp; LEAK INTELLIGENCE
            </h1>
            <p className="text-xs sm:text-sm text-[var(--text-secondary)]">
              TRACK RANSOMWARE EXTORTION VICTIMS BY COUNTRY &amp; SECTOR, CREDENTIAL STEALER LOGS, TOR LEAK INFRASTRUCTURE, AND WATCHLIST ALERTS.
            </p>
          </div>

          {/* Country Target Setting + Controls */}
          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <div className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]">
              <MapPin
                className="w-3.5 h-3.5 shrink-0"
                style={{ color: "var(--accent)" }}
              />
              <span className="text-[10px] font-bold text-[var(--text-secondary)]">
                COUNTRY:
              </span>
              <select
                value={targetCountry}
                onChange={(e) => handleCountryChange(e.target.value)}
                className="bg-transparent text-xs font-extrabold focus:outline-none cursor-pointer"
                aria-label="Target country filter"
              >
                {COUNTRY_CATALOG.map((c) => (
                  <option
                    key={c.code}
                    value={c.code}
                    className="bg-[var(--bg-surface-solid)] text-[var(--text-primary)]"
                  >
                    {c.code === "ALL" ? c.name : `${c.code} — ${c.name}`}
                  </option>
                ))}
              </select>
            </div>

            <button
              type="button"
              onClick={() => setLiveStream((v) => !v)}
              className={`inline-flex items-center gap-1.5 px-3 py-2 rounded-xl border text-xs font-extrabold cursor-pointer ${
                liveStream
                  ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-300"
                  : "border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-[var(--text-secondary)]"
              }`}
              title="Real-time auto-sync darkweb feeds"
            >
              <Radio
                className={`w-3.5 h-3.5 ${liveStream ? "animate-pulse text-emerald-400" : ""}`}
              />
              {liveStream ? `LIVE (${liveCountdown}s)` : "LIVE: PAUSED"}
            </button>

            <select
              value={liveIntervalSec}
              onChange={(e) => setLiveIntervalSec(Number(e.target.value))}
              aria-label="Darkweb auto-sync interval"
              className="px-2.5 py-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-xs font-bold cursor-pointer"
            >
              <option value={15}>15s</option>
              <option value={30}>30s</option>
              <option value={45}>45s</option>
              <option value={60}>60s</option>
            </select>

            <Link
              href="/attacks"
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl border border-rose-500/35 bg-rose-500/15 text-rose-300 hover:bg-rose-500/25 text-xs font-bold"
            >
              <Activity className="w-3.5 h-3.5" />
              LIVE ATTACK IOCS
            </Link>

            <button
              type="button"
              onClick={() => setShowHibpInput((v) => !v)}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-xs font-bold cursor-pointer"
            >
              <KeyRound className="w-3.5 h-3.5" />
              HIBP KEY
            </button>

            <button
              type="button"
              onClick={() => {
                setLiveCountdown(liveIntervalSec);
                loadAll(true);
              }}
              disabled={loading}
              style={{ backgroundColor: "var(--accent)" }}
              className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl text-white text-xs font-bold hover:opacity-90 disabled:opacity-50 cursor-pointer"
            >
              <RefreshCw
                className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`}
              />
              SYNC FEEDS
            </button>
          </div>
        </div>

        {/* Country Active Banner */}
        {targetCountry !== "ALL" && dash && (
          <div
            className="p-3.5 rounded-xl flex flex-wrap items-center justify-between gap-2 text-xs font-bold"
            style={{
              backgroundColor: "var(--accent-soft)",
              border: "1px solid var(--accent-border)",
              color: "var(--accent)",
            }}
          >
            <span className="flex items-center gap-2">
              <MapPin className="w-4 h-4 shrink-0" />
              COUNTRY FOCUS ACTIVE: {selectedCountryName} —{" "}
              {filteredVictims.length} MATCHING VICTIM(S) IN LATEST{" "}
              {dash.victims.length} LEAK POSTS
            </span>
            <button
              type="button"
              onClick={() => handleCountryChange("ALL")}
              className="underline cursor-pointer"
            >
              RESET TO ALL COUNTRIES
            </button>
          </div>
        )}

        {/* 4 Telemetry KPI Cards */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          <div className="p-4 rounded-xl border border-rose-500/25 bg-rose-500/10">
            <div className="text-[10px] font-bold text-rose-300 flex items-center gap-1">
              <ShieldAlert className="w-3.5 h-3.5" /> RANSOMWARE VICTIMS
            </div>
            <div className="text-xl sm:text-2xl font-extrabold font-mono-ioc text-rose-400 mt-1">
              {dash ? filteredVictims.length : "—"}
              {targetCountry !== "ALL" && dash && (
                <span className="text-xs font-normal text-rose-300/75 ml-1">
                  / {dash.stats.recentVictimsCount}
                </span>
              )}
            </div>
            <div className="text-[10px] text-rose-300/80 mt-1">
              LATEST: {dash?.stats.latestVictimDate?.slice(0, 10) || "—"}
            </div>
          </div>

          <div className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/65">
            <div className="text-[10px] font-bold text-[var(--text-secondary)] flex items-center gap-1">
              <Server className="w-3.5 h-3.5" /> TOR DARKWEB INFRA
            </div>
            <div
              className="text-xl sm:text-2xl font-extrabold font-mono-ioc mt-1"
              style={{ color: "var(--accent)" }}
            >
              {dash?.infraStats
                ? `${dash.infraStats.dlsSites} DLS`
                : dash
                  ? `${dash.stats.groupsCount} GANGS`
                  : "—"}
            </div>
            <div className="text-[10px] text-[var(--text-secondary)] mt-1">
              {dash?.infraStats
                ? `${dash.infraStats.locations.toLocaleString()} MIRRORS · ${dash.infraStats.negotiationChats} CHATS`
                : `${dash?.stats.marketsCount ?? "—"} MARKETS`}
            </div>
          </div>

          <div className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/65">
            <div className="text-[10px] font-bold text-[var(--text-secondary)]">
              BREACHES &amp; LEAKED DBS
            </div>
            <div className="text-xl sm:text-2xl font-extrabold font-mono-ioc text-amber-400 mt-1">
              {dash
                ? `${dash.stats.breachesCount} · ${dash.stats.leakedDomainsCount}`
                : "—"}
            </div>
            <div className="text-[10px] text-[var(--text-secondary)] mt-1">
              STEALER LOG BREACHES: {dash?.stats.stealerBreachesCount ?? "—"}
            </div>
          </div>

          <div className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/65">
            <div className="text-[10px] font-bold text-[var(--text-secondary)]">
              WATCHLIST ALERTS
            </div>
            <div
              className={`text-xl sm:text-2xl font-extrabold font-mono-ioc mt-1 ${
                alertMonitorsCount > 0 ? "text-rose-400" : "text-emerald-400"
              }`}
            >
              {alertMonitorsCount}/{monitors.length}
            </div>
            <div className="text-[10px] text-[var(--text-secondary)] mt-1">
              MONITORED TARGETS WITH HITS
            </div>
          </div>
        </div>

        {showHibpInput && (
          <div className="p-3.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/60 flex flex-col sm:flex-row sm:items-center gap-3">
            <span className="text-[11px] font-bold text-[var(--text-secondary)] shrink-0">
              OPTIONAL HIBP API KEY (FOR EMAIL SEARCH):
            </span>
            <input
              type="password"
              value={hibpKey}
              onChange={(e) => {
                setHibpKey(e.target.value);
                safeSetStorage("eyesight_hibp_key", e.target.value);
              }}
              placeholder="Paste Have I Been Pwned API key..."
              className="flex-1 px-3 py-2 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-surface)] font-mono-ioc text-xs"
            />
          </div>
        )}

        {/* Unified Darkweb Search Bar */}
        <form
          onSubmit={handleSearchSubmit}
          className="space-y-3 pt-2 border-t border-[var(--border-subtle)]"
        >
          <div className="flex flex-col sm:flex-row gap-2.5">
            <div className="relative flex-1">
              <Search className="w-4 h-4 text-[var(--text-secondary)] absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
              <input
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="SEARCH DOMAIN, BRAND, EMAIL, OR RANSOMWARE GROUP ACROSS DARKWEB FEEDS..."
                className="w-full pl-10 pr-4 py-3 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] font-mono-ioc text-xs sm:text-sm focus:outline-none focus:border-[var(--accent)]"
              />
            </div>
            <button
              type="submit"
              disabled={searching || !query.trim()}
              style={{ backgroundColor: "var(--accent)" }}
              className="px-6 py-3 rounded-xl hover:opacity-90 disabled:opacity-50 text-white text-xs font-extrabold inline-flex items-center justify-center gap-1.5 cursor-pointer"
            >
              {searching ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" /> SCANNING...
                </>
              ) : (
                "SCAN DARKWEB"
              )}
            </button>
          </div>

          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-[11px] font-bold text-[var(--text-secondary)] inline-flex items-center gap-1 mr-1">
              <Sparkles
                className="w-3.5 h-3.5"
                style={{ color: "var(--accent)" }}
              />
              SAMPLES:
            </span>
            {DARKWEB_SAMPLES.map((s) => (
              <button
                key={s}
                type="button"
                onClick={() => {
                  setQuery(s);
                  runSearch(s);
                }}
                className="text-[11px] font-mono-ioc preserve-case px-2.5 py-1 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-elevated)] hover:border-[var(--accent-border)] cursor-pointer"
              >
                {s}
              </button>
            ))}
          </div>
        </form>
      </section>

      {/* Expert Threat Analytics Strip */}
      {dash && tab === "ransomware" && (
        <section className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* Top Active Gangs */}
          <div className="rounded-2xl glass-panel p-4 space-y-2.5">
            <div className="text-[10px] font-bold tracking-widest text-[var(--text-secondary)] flex items-center gap-1.5">
              <BarChart3 className="w-3.5 h-3.5 text-rose-400" />
              TOP ACTIVE RANSOMWARE GANGS
            </div>
            <div className="space-y-1.5">
              {dash.topGroups.slice(0, 5).map((g) => {
                const max = dash.topGroups[0]?.count || 1;
                const pct = Math.round((g.count / max) * 100);
                return (
                  <button
                    key={g.name}
                    type="button"
                    onClick={() =>
                      setGroupFilter(groupFilter === g.name ? "ALL" : g.name)
                    }
                    className="w-full text-left space-y-1 cursor-pointer group"
                  >
                    <div className="flex items-center justify-between text-[11px] font-bold">
                      <span className="group-hover:underline">{g.name}</span>
                      <span className="font-mono-ioc text-rose-400">{g.count}</span>
                    </div>
                    <div className="h-1.5 rounded-full bg-[var(--bg-elevated)] overflow-hidden">
                      <div
                        className="h-full bg-rose-500/80 rounded-full"
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Top Targeted Sectors */}
          <div className="rounded-2xl glass-panel p-4 space-y-2.5">
            <div className="text-[10px] font-bold tracking-widest text-[var(--text-secondary)] flex items-center gap-1.5">
              <BarChart3 className="w-3.5 h-3.5 text-amber-400" />
              TOP TARGETED SECTORS
            </div>
            <div className="space-y-1.5">
              {dash.topSectors.slice(0, 5).map((s) => {
                const max = dash.topSectors[0]?.count || 1;
                const pct = Math.round((s.count / max) * 100);
                return (
                  <button
                    key={s.name}
                    type="button"
                    onClick={() =>
                      setSectorFilter(sectorFilter === s.name ? "ALL" : s.name)
                    }
                    className="w-full text-left space-y-1 cursor-pointer group"
                  >
                    <div className="flex items-center justify-between text-[11px] font-bold">
                      <span className="group-hover:underline">{s.name}</span>
                      <span className="font-mono-ioc text-amber-400">{s.count}</span>
                    </div>
                    <div className="h-1.5 rounded-full bg-[var(--bg-elevated)] overflow-hidden">
                      <div
                        className="h-full bg-amber-500/80 rounded-full"
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Top Targeted Countries */}
          <div className="rounded-2xl glass-panel p-4 space-y-2.5">
            <div className="text-[10px] font-bold tracking-widest text-[var(--text-secondary)] flex items-center gap-1.5">
              <MapPin className="w-3.5 h-3.5" style={{ color: "var(--accent)" }} />
              TOP DETECTED COUNTRIES (INFERRED)
            </div>
            <div className="space-y-1.5">
              {dash.topCountries.slice(0, 5).map((c) => {
                const max = dash.topCountries[0]?.count || 1;
                const pct = Math.round((c.count / max) * 100);
                return (
                  <button
                    key={c.code}
                    type="button"
                    onClick={() =>
                      handleCountryChange(
                        targetCountry === c.code ? "ALL" : c.code,
                      )
                    }
                    className="w-full text-left space-y-1 cursor-pointer group"
                  >
                    <div className="flex items-center justify-between text-[11px] font-bold">
                      <span className="group-hover:underline">
                        {c.code} · {c.name}
                      </span>
                      <span
                        className="font-mono-ioc"
                        style={{ color: "var(--accent)" }}
                      >
                        {c.count}
                      </span>
                    </div>
                    <div className="h-1.5 rounded-full bg-[var(--bg-elevated)] overflow-hidden">
                      <div
                        className="h-full rounded-full"
                        style={{
                          width: `${pct}%`,
                          backgroundColor: "var(--accent)",
                        }}
                      />
                    </div>
                  </button>
                );
              })}
            </div>
          </div>
        </section>
      )}

      {/* Tabs */}
      <div className="flex items-center gap-1.5 overflow-x-auto no-scrollbar border-b border-[var(--border-subtle)] pb-2">
        {(
          [
            { id: "ransomware", label: "RANSOMWARE LEAKS", icon: Skull },
            { id: "credentials", label: "CREDENTIAL LEAKS", icon: LockOpen },
            { id: "breaches", label: "BREACHES & STEALER LOGS", icon: Database },
            { id: "actors", label: "GANGS & MARKETS", icon: Globe },
            {
              id: "monitors",
              label: `WATCHLIST MONITORS (${monitors.length})`,
              icon: Eye,
            },
            { id: "search", label: "SEARCH RESULTS", icon: Search },
          ] as Array<{
            id: DarkwebTab;
            label: string;
            icon: React.ComponentType<{ className?: string }>;
          }>
        ).map((t) => {
          const Icon = t.icon;
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
              className={`inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl border text-xs font-bold whitespace-nowrap transition cursor-pointer ${
                active
                  ? ""
                  : "border-[var(--border-subtle)] bg-[var(--bg-surface)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              {t.label}
            </button>
          );
        })}
      </div>

      {error && (
        <div className="p-4 rounded-xl border border-rose-500/30 bg-rose-500/10 text-rose-300 text-xs font-bold">
          {error}
        </div>
      )}

      {loading && !dash ? (
        <div className="rounded-2xl glass-panel p-12 text-center space-y-3">
          <Loader2
            className="w-8 h-8 animate-spin mx-auto"
            style={{ color: "var(--accent)" }}
          />
          <p className="text-xs font-bold text-[var(--text-secondary)]">
            SYNCING RANSOMWARE LEAK SITES, BREACH CATALOGS &amp; DARKWEB MONITORS...
          </p>
        </div>
      ) : (
        <>
          {/* RANSOMWARE LEAKS TAB WITH PAGINATION & FILTERS */}
          {tab === "ransomware" && dash && (
            <div className="space-y-4">
              <div className="rounded-2xl glass-panel p-4 sm:p-5 space-y-4">
                <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-3">
                  <div>
                    <h2 className="text-sm font-extrabold text-rose-400">
                      RANSOMWARE LEAK SITE VICTIMS ({filteredVictims.length})
                    </h2>
                    <p className="text-[11px] text-[var(--text-secondary)]">
                      CLICK ANY VICTIM FOR FULL DOSSIER (MISP UUID, TOR ONION LINK, PROOF SCREENSHOT &amp; IOC PIVOT)
                    </p>
                  </div>

                  <div className="flex flex-wrap items-center gap-2">
                    <input
                      type="text"
                      value={victimFilter}
                      onChange={(e) => setVictimFilter(e.target.value)}
                      placeholder="FILTER VICTIM OR DOMAIN..."
                      className="px-3 py-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] font-mono-ioc text-xs"
                    />
                    <select
                      value={groupFilter}
                      onChange={(e) => setGroupFilter(e.target.value)}
                      className="px-3 py-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-xs font-bold"
                    >
                      <option value="ALL">ALL GROUPS</option>
                      {victimGroups.map((g) => (
                        <option key={g} value={g}>
                          {g.toUpperCase()}
                        </option>
                      ))}
                    </select>
                    <select
                      value={sectorFilter}
                      onChange={(e) => setSectorFilter(e.target.value)}
                      className="px-3 py-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-xs font-bold"
                    >
                      <option value="ALL">ALL SECTORS</option>
                      {victimSectors.map((s) => (
                        <option key={s} value={s}>
                          {s}
                        </option>
                      ))}
                    </select>
                    <div className="inline-flex rounded-xl border border-[var(--border-subtle)] overflow-hidden">
                      <button
                        type="button"
                        onClick={() => exportVictims("csv")}
                        className="inline-flex items-center gap-1 px-2.5 py-2 bg-[var(--bg-elevated)] hover:bg-[var(--accent-soft)] text-[10px] font-bold border-r border-[var(--border-subtle)] cursor-pointer"
                      >
                        <Download className="w-3 h-3" /> CSV
                      </button>
                      <button
                        type="button"
                        onClick={() => exportVictims("json")}
                        className="px-2.5 py-2 bg-[var(--bg-elevated)] hover:bg-[var(--accent-soft)] text-[10px] font-bold cursor-pointer"
                      >
                        JSON
                      </button>
                    </div>
                  </div>
                </div>

                {pagedVictims.length === 0 ? (
                  <div className="p-8 text-center text-xs font-bold text-[var(--text-secondary)]">
                    NO RANSOMWARE VICTIMS MATCH YOUR COUNTRY / SECTOR / GROUP FILTERS.
                  </div>
                ) : (
                  <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
                    {pagedVictims.map((v, idx) => (
                      <button
                        key={`${v.group}-${v.victim}-${idx}`}
                        type="button"
                        onClick={() => setSelectedVictim(v)}
                        className="text-left p-4 rounded-xl border border-rose-500/20 bg-rose-500/5 hover:border-rose-500/50 transition space-y-2.5 flex flex-col justify-between cursor-pointer"
                      >
                        <div className="space-y-2 w-full">
                          <div className="flex flex-wrap items-center justify-between gap-1.5">
                            <div className="flex flex-wrap items-center gap-1.5">
                              <span className="text-[10px] font-extrabold px-2 py-0.5 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/35">
                                {v.group}
                              </span>
                              {v.countryCode !== "UNSPECIFIED" && (
                                <span
                                  className="text-[9px] font-extrabold px-2 py-0.5 rounded-full"
                                  style={{
                                    backgroundColor: "var(--accent-soft)",
                                    color: "var(--accent)",
                                  }}
                                >
                                  {v.countryCode}
                                </span>
                              )}
                              {v.sector !== "OTHER" && (
                                <span className="text-[9px] font-bold px-2 py-0.5 rounded-full border border-[var(--border-subtle)] bg-[var(--bg-surface)] text-[var(--text-secondary)]">
                                  {v.sector}
                                </span>
                              )}
                            </div>
                            <span className="text-[10px] font-mono-ioc text-[var(--text-secondary)]">
                              {v.discovered.slice(0, 10)}
                            </span>
                          </div>

                          <div className="text-sm font-extrabold preserve-case">
                            {v.victim}
                          </div>

                          {v.description && (
                            <p className="text-[11px] text-[var(--text-secondary)] preserve-case line-clamp-2">
                              {v.description}
                            </p>
                          )}
                        </div>

                        <div className="pt-2 border-t border-rose-500/15 flex items-center justify-between gap-2 text-[10px] font-bold w-full">
                          <span className="font-mono-ioc preserve-case truncate text-[var(--text-secondary)]">
                            {v.extractedDomain || (v.onionLink ? ".ONION LEAK" : "DOSSIER")}
                          </span>
                          <span style={{ color: "var(--accent)" }}>
                            INSPECT →
                          </span>
                        </div>
                      </button>
                    ))}
                  </div>
                )}
              </div>

              <PaginationControls
                totalItems={filteredVictims.length}
                page={victimPage}
                pageSize={victimPageSize}
                onPageChange={(p) => {
                  setVictimPage(p);
                  window.scrollTo({ top: 0, behavior: "smooth" });
                }}
                onPageSizeChange={(s) => setVictimPageSize(s)}
                label="VICTIMS"
              />
            </div>
          )}

          {/* CREDENTIAL LEAK MONITORING TAB (UNCENSORED DEFAULT + PAGINATION) */}
          {tab === "credentials" && (
            <div className="space-y-5">
              <div className="rounded-2xl glass-panel p-5 space-y-4">
                <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <h2 className="text-sm font-extrabold text-rose-400 flex items-center gap-1.5">
                        <LockOpen className="w-4 h-4" />
                        CREDENTIAL LEAK &amp; INFOSTEALER MONITORING
                      </h2>
                      <span
                        className={`text-[9px] font-extrabold px-2 py-0.5 rounded-full border ${
                          uncensoredMode
                            ? "bg-rose-500/20 text-rose-300 border-rose-500/40"
                            : "bg-emerald-500/15 text-emerald-300 border-emerald-500/35"
                        }`}
                      >
                        {uncensoredMode ? "UNCENSORED FULL OUTPUT" : "MASKED PREVIEW"}
                      </span>
                    </div>
                    <p className="text-[11px] text-[var(--text-secondary)] mt-0.5">
                      LIVE LOOKUP ACROSS PROXYNOVA COMB LEAK PAIRS, HUDSON ROCK INFOSTEALER LOGS, AND XPOSEDORNOT BREACH ANALYTICS (NO CENSORSHIP ON EXPOSED RECORDS).
                    </p>
                  </div>

                  <div className="flex flex-wrap items-center gap-2">
                    <button
                      type="button"
                      onClick={() => setUncensoredMode((v) => !v)}
                      className={`inline-flex items-center gap-1.5 px-3 py-2 rounded-xl border text-xs font-bold cursor-pointer ${
                        uncensoredMode
                          ? "border-rose-500/40 bg-rose-500/15 text-rose-300"
                          : "border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-[var(--text-secondary)]"
                      }`}
                    >
                      <ShieldOff className="w-3.5 h-3.5" />
                      {uncensoredMode ? "UNCENSORED: ON" : "UNCENSORED: OFF"}
                    </button>

                    {credReport && credReport.comb.records.length > 0 && (
                      <div className="inline-flex rounded-xl border border-[var(--border-subtle)] overflow-hidden">
                        <button
                          type="button"
                          onClick={() => exportCredentials("csv")}
                          className="inline-flex items-center gap-1 px-2.5 py-2 bg-[var(--bg-elevated)] hover:bg-[var(--accent-soft)] text-[10px] font-bold border-r border-[var(--border-subtle)] cursor-pointer"
                        >
                          <Download className="w-3 h-3" /> CSV
                        </button>
                        <button
                          type="button"
                          onClick={() => exportCredentials("json")}
                          className="px-2.5 py-2 bg-[var(--bg-elevated)] hover:bg-[var(--accent-soft)] text-[10px] font-bold cursor-pointer"
                        >
                          JSON
                        </button>
                      </div>
                    )}
                  </div>
                </div>

                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    runCredentialScan(credQuery, 1, credPageSize);
                  }}
                  className="flex flex-col sm:flex-row gap-2.5"
                >
                  <input
                    type="text"
                    value={credQuery}
                    onChange={(e) => setCredQuery(e.target.value)}
                    placeholder="ENTER DOMAIN, EMAIL, OR USERNAME (E.G. DROPBOX.COM, USER@DOMAIN.COM)..."
                    className="flex-1 px-4 py-3 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] font-mono-ioc text-xs sm:text-sm focus:outline-none focus:border-[var(--accent)]"
                  />
                  <button
                    type="submit"
                    disabled={credLoading || credQuery.trim().length < 2}
                    style={{ backgroundColor: "var(--accent)" }}
                    className="px-6 py-3 rounded-xl text-white text-xs font-extrabold inline-flex items-center justify-center gap-1.5 hover:opacity-90 disabled:opacity-50 cursor-pointer"
                  >
                    {credLoading ? (
                      <>
                        <Loader2 className="w-4 h-4 animate-spin" /> SCANNING LEAKS...
                      </>
                    ) : (
                      <>
                        <LockOpen className="w-4 h-4" /> SCAN CREDENTIAL LEAKS
                      </>
                    )}
                  </button>
                </form>

                <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
                  <span className="font-bold text-[var(--text-secondary)]">
                    QUICK TARGETS:
                  </span>
                  {["dropbox.com", "test@example.com", "example.com", "adobe.com"].map(
                    (sample) => (
                      <button
                        key={sample}
                        type="button"
                        onClick={() => runCredentialScan(sample, 1, credPageSize)}
                        className="font-mono-ioc preserve-case px-2.5 py-1 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-elevated)] hover:border-[var(--accent-border)] cursor-pointer"
                      >
                        {sample}
                      </button>
                    ),
                  )}
                </div>

                {credError && (
                  <div className="p-3.5 rounded-xl border border-rose-500/35 bg-rose-500/10 text-rose-300 text-xs font-bold">
                    {credError}
                  </div>
                )}
              </div>

              {!credReport && !credLoading && recentGlobalBreaches.length > 0 && (
                <div className="space-y-4">
                  <div className="rounded-2xl glass-panel p-5 space-y-4">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div>
                        <h3 className="text-sm font-extrabold text-rose-400 flex items-center gap-1.5">
                          <Radio className="w-4 h-4 animate-pulse text-emerald-400" />
                          LATEST REAL-TIME GLOBAL CREDENTIAL BREACHES (
                          {recentGlobalBreaches.length})
                        </h3>
                        <p className="text-[11px] text-[var(--text-secondary)]">
                          NEWEST REPORTED DATA BREACHES &amp; CREDENTIAL EXPOSURES (2026 LIVE INDEX) — CLICK ANY ENTRY TO SCAN DOMAIN OR CREDENTIALS
                        </p>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      {recentGlobalBreaches
                        .slice((globalBreachPage - 1) * 10, globalBreachPage * 10)
                        .map((b) => (
                          <div
                            key={b.breachId}
                            className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/55 space-y-2"
                          >
                            <div className="flex items-center justify-between gap-2">
                              <span className="text-sm font-extrabold">
                                {b.breachId}
                              </span>
                              <span className="text-[10px] font-mono-ioc text-amber-300">
                                {b.addedDate.slice(0, 10) || b.breachedDate.slice(0, 10)}
                              </span>
                            </div>
                            <div className="flex flex-wrap items-center gap-1.5 text-[10px] font-bold">
                              {b.domain && (
                                <button
                                  type="button"
                                  onClick={() =>
                                    runCredentialScan(b.domain, 1, credPageSize, true)
                                  }
                                  className="font-mono-ioc preserve-case px-2 py-0.5 rounded bg-[var(--accent-soft)] text-[var(--accent)] hover:underline cursor-pointer"
                                >
                                  SCAN {b.domain} →
                                </button>
                              )}
                              <span className="px-2 py-0.5 rounded border border-[var(--border-subtle)]">
                                {b.exposedRecords.toLocaleString()} RECORDS
                              </span>
                              {b.industry && (
                                <span className="px-2 py-0.5 rounded bg-rose-500/15 text-rose-300">
                                  {b.industry}
                                </span>
                              )}
                            </div>
                            {b.description && (
                              <p className="text-[11px] text-[var(--text-secondary)] preserve-case line-clamp-2">
                                {b.description}
                              </p>
                            )}
                            {b.exposedData.length > 0 && (
                              <div className="flex flex-wrap gap-1">
                                {b.exposedData.slice(0, 5).map((attr) => (
                                  <span
                                    key={attr}
                                    className="text-[9px] px-1.5 py-0.5 rounded bg-[var(--bg-surface)] border border-[var(--border-subtle)] text-[var(--text-secondary)]"
                                  >
                                    {attr}
                                  </span>
                                ))}
                              </div>
                            )}
                          </div>
                        ))}
                    </div>
                  </div>

                  <PaginationControls
                    totalItems={recentGlobalBreaches.length}
                    page={globalBreachPage}
                    pageSize={10}
                    onPageChange={(p) => setGlobalBreachPage(p)}
                    label="RECENT BREACHES"
                  />
                </div>
              )}

              {credReport && (
                <div className="space-y-5">
                  {/* Real-Time Credential Intelligence KPI Summary */}
                  <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
                    <div className="p-4 rounded-xl border border-rose-500/25 bg-rose-500/10">
                      <div className="text-[10px] font-bold text-rose-300">
                        LATEST COMPROMISE DATE
                      </div>
                      <div className="text-xl font-extrabold font-mono-ioc text-rose-400 mt-1">
                        {credReport.evidence.timelineSummary.latestDate || "HISTORICAL"}
                      </div>
                      <div className="text-[10px] text-rose-300/80 mt-0.5">
                        EARLIEST:{" "}
                        {credReport.evidence.timelineSummary.earliestDate || "2021"} ·{" "}
                        {credReport.evidence.timelineSummary.totalEvidenceSources} SOURCE(S)
                      </div>
                    </div>

                    <div className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/65">
                      <div className="text-[10px] font-bold text-[var(--text-secondary)]">
                        LIVE STEALERS (HUDSON ROCK)
                      </div>
                      <div className="text-xl font-extrabold font-mono-ioc text-amber-400 mt-1">
                        {credReport.hudsonRockDomain
                          ? credReport.hudsonRockDomain.total.toLocaleString()
                          : credReport.hudsonRockEmail
                            ? credReport.hudsonRockEmail.hosts.length
                            : "0"}
                      </div>
                      <div className="text-[10px] text-[var(--text-secondary)] mt-0.5">
                        {credReport.hudsonRockDomain
                          ? `${credReport.hudsonRockDomain.employees.toLocaleString()} EMP · ${credReport.hudsonRockDomain.users.toLocaleString()} USERS`
                          : credReport.hudsonRockEmail
                            ? `${credReport.hudsonRockEmail.totalCorporateServices} CORP · ${credReport.hudsonRockEmail.totalUserServices} USER`
                            : "DAILY INFOSTEALER LOGS"}
                      </div>
                    </div>

                    <div className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/65">
                      <div className="text-[10px] font-bold text-[var(--text-secondary)]">
                        LEAKCHECK LIVE SOURCES
                      </div>
                      <div
                        className="text-xl font-extrabold font-mono-ioc mt-1"
                        style={{ color: "var(--accent)" }}
                      >
                        {credReport.leakCheck
                          ? credReport.leakCheck.found.toLocaleString()
                          : "0"}
                      </div>
                      <div className="text-[10px] text-[var(--text-secondary)] mt-0.5">
                        {credReport.leakCheck
                          ? `${credReport.leakCheck.sources.length} DATED BREACH/STEALER SOURCES`
                          : "NO LEAKCHECK HITS"}
                      </div>
                    </div>

                    <div className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/65">
                      <div className="text-[10px] font-bold text-[var(--text-secondary)]">
                        HISTORICAL COMB CORPUS
                      </div>
                      <div className="text-xl font-extrabold font-mono-ioc text-[var(--text-primary)] mt-1">
                        {credReport.comb.totalCount.toLocaleString()}
                      </div>
                      <div className="text-[10px] text-[var(--text-secondary)] mt-0.5">
                        LEGACY ARCHIVE PAIRS ({credReport.queryKind.toUpperCase()})
                      </div>
                    </div>
                  </div>

                  {/* REAL-TIME SOURCE 1: LeakCheck Live Dated Sources & Stealer Logs */}
                  {credReport.leakCheck && credReport.leakCheck.found > 0 && (
                    <div className="space-y-4">
                      <div className="rounded-2xl glass-panel p-5 space-y-4">
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div>
                            <h3 className="text-sm font-extrabold text-emerald-400 flex items-center gap-1.5">
                              <Radio className="w-4 h-4 animate-pulse" />
                              LEAKCHECK REAL-TIME BREACH &amp; STEALER INDEX (
                              {credReport.leakCheck.sources.length} SOURCES ·{" "}
                              {credReport.leakCheck.found.toLocaleString()} HITS)
                            </h3>
                            <p className="text-[11px] text-[var(--text-secondary)]">
                              LATEST DATED CREDENTIAL BREACHES &amp; STEALER LOGS SORTED NEWEST FIRST (2026 LIVE TELEMETRY)
                            </p>
                          </div>
                        </div>

                        {credReport.leakCheck.fields.length > 0 && (
                          <div className="flex flex-wrap items-center gap-1.5 text-[10px]">
                            <span className="font-bold text-[var(--text-secondary)]">
                              EXPOSED FIELDS DETECTED:
                            </span>
                            {credReport.leakCheck.fields.map((field) => (
                              <span
                                key={field}
                                className="px-2 py-0.5 rounded bg-rose-500/15 text-rose-300 border border-rose-500/30 font-mono-ioc preserve-case"
                              >
                                {field}
                              </span>
                            ))}
                          </div>
                        )}

                        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5">
                          {credReport.leakCheck.sources
                            .slice((leakCheckPage - 1) * 12, leakCheckPage * 12)
                            .map((src, idx) => (
                              <div
                                key={`${src.name}-${src.date}-${idx}`}
                                className="p-3 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/55 flex items-center justify-between gap-2 text-xs"
                              >
                                <span className="font-mono-ioc preserve-case font-bold truncate">
                                  {src.name}
                                </span>
                                <span
                                  className={`text-[10px] font-mono-ioc px-2 py-0.5 rounded shrink-0 ${
                                    src.name.toLowerCase().includes("stealer")
                                      ? "bg-rose-500/20 text-rose-300 border border-rose-500/35"
                                      : "bg-amber-500/15 text-amber-300"
                                  }`}
                                >
                                  {src.date || "ACTIVE LOG"}
                                </span>
                              </div>
                            ))}
                        </div>
                      </div>

                      <PaginationControls
                        totalItems={credReport.leakCheck.sources.length}
                        page={leakCheckPage}
                        pageSize={12}
                        onPageChange={(p) => setLeakCheckPage(p)}
                        label="LEAKCHECK SOURCES"
                      />
                    </div>
                  )}

                  {/* REAL-TIME SOURCE 2: Cross-Source Forensic Leak Evidence & Dates */}
                  {(credReport.evidence.xonCatalogMatches.length > 0 ||
                    credReport.evidence.ransomLookDumps.length > 0 ||
                    credReport.evidence.hibpMatches.length > 0 ||
                    credReport.evidence.ransomwareHits.length > 0) && (
                    <div className="rounded-2xl glass-panel p-5 space-y-4">
                      <div>
                        <h3
                          className="text-sm font-extrabold flex items-center gap-1.5"
                          style={{ color: "var(--accent)" }}
                        >
                          <ShieldAlert className="w-4 h-4 text-rose-400" />
                          LEAK DATE &amp; FORENSIC EVIDENCE PROVENANCE
                        </h3>
                        <p className="text-[11px] text-[var(--text-secondary)]">
                          CORRELATED XPOSEDORNOT 2026 BREACHES, RANSOMLOOK DUMP METADATA, HIBP RECORDS &amp; RANSOMWARE CLAIMS
                        </p>
                      </div>

                      <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-4 gap-4 text-xs">
                        {credReport.evidence.xonCatalogMatches.length > 0 && (
                          <div className="p-4 rounded-xl border border-emerald-500/25 bg-emerald-500/5 space-y-2.5">
                            <div className="text-[10px] font-bold text-emerald-300">
                              XPOSEDORNOT 2026 CATALOG ({credReport.evidence.xonCatalogMatches.length})
                            </div>
                            {credReport.evidence.xonCatalogMatches.slice(0, 6).map((b) => (
                              <div
                                key={b.breachId}
                                className="p-2.5 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-surface)] space-y-1"
                              >
                                <div className="flex items-center justify-between gap-2">
                                  <span className="font-extrabold">{b.breachId}</span>
                                  <span className="text-[10px] font-mono-ioc text-emerald-300">
                                    {b.addedDate.slice(0, 10) || b.breachedDate.slice(0, 10)}
                                  </span>
                                </div>
                                <div className="text-[10px] text-[var(--text-secondary)]">
                                  {b.exposedRecords.toLocaleString()} RECORDS · {b.passwordRisk.toUpperCase()}
                                </div>
                                <div className="text-[10px] text-rose-300 preserve-case">
                                  {b.exposedData.slice(0, 4).join(", ")}
                                </div>
                              </div>
                            ))}
                          </div>
                        )}
                        {credReport.evidence.ransomLookDumps.length > 0 && (
                          <div className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/55 space-y-2.5">
                            <div className="text-[10px] font-bold text-cyan-300">
                              RANSOMLOOK INDEXED DUMPS ({credReport.evidence.ransomLookDumps.length})
                            </div>
                            {credReport.evidence.ransomLookDumps.map((d) => (
                              <div
                                key={`${d.id}-${d.domain}`}
                                className="p-2.5 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-surface)] space-y-1"
                              >
                                <div className="flex items-center justify-between gap-2">
                                  <span className="font-mono-ioc preserve-case font-extrabold">
                                    {d.domain}
                                  </span>
                                  <span className="text-[10px] font-mono-ioc text-amber-300">
                                    DATE: {d.indexedDate || "UNKNOWN"}
                                  </span>
                                </div>
                                <div className="text-[10px] text-[var(--text-secondary)]">
                                  RECORDS: {d.records || "—"} · SIZE: {d.size || "—"}
                                </div>
                                {d.columns.length > 0 && (
                                  <div className="font-mono-ioc preserve-case text-[10px] text-rose-300">
                                    COLUMNS: {d.columns.join(", ")}
                                  </div>
                                )}
                                <a
                                  href={d.sourceUrl}
                                  target="_blank"
                                  rel="noreferrer"
                                  style={{ color: "var(--accent)" }}
                                  className="inline-flex items-center gap-1 text-[10px] font-bold hover:underline"
                                >
                                  RANSOMLOOK LEAK #{d.id} <ExternalLink className="w-3 h-3" />
                                </a>
                              </div>
                            ))}
                          </div>
                        )}

                        {credReport.evidence.hibpMatches.length > 0 && (
                          <div className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/55 space-y-2.5">
                            <div className="text-[10px] font-bold text-amber-300">
                              HIBP BREACH EVIDENCE ({credReport.evidence.hibpMatches.length})
                            </div>
                            {credReport.evidence.hibpMatches.slice(0, 6).map((b) => (
                              <div
                                key={b.name}
                                className="p-2.5 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-surface)] space-y-1"
                              >
                                <div className="flex items-center justify-between gap-2">
                                  <span className="font-extrabold">{b.title}</span>
                                  <span className="text-[10px] font-mono-ioc text-amber-300">
                                    {b.breachDate}
                                  </span>
                                </div>
                                <div className="text-[10px] text-[var(--text-secondary)]">
                                  {b.pwnCount.toLocaleString()} RECORDS · ADDED{" "}
                                  {b.addedDate.slice(0, 10)} ·{" "}
                                  {b.isVerified ? "VERIFIED" : "UNVERIFIED"}
                                </div>
                                <div className="text-[10px] text-rose-300 preserve-case">
                                  {b.dataClasses.slice(0, 5).join(", ")}
                                </div>
                              </div>
                            ))}
                          </div>
                        )}

                        {credReport.evidence.ransomwareHits.length > 0 && (
                          <div className="p-4 rounded-xl border border-rose-500/25 bg-rose-500/5 space-y-2.5">
                            <div className="text-[10px] font-bold text-rose-300">
                              RANSOMWARE EXTORTION CLAIMS ({credReport.evidence.ransomwareHits.length})
                            </div>
                            {credReport.evidence.ransomwareHits.slice(0, 6).map((v, i) => (
                              <button
                                key={`${v.group}-${v.victim}-${i}`}
                                type="button"
                                onClick={() => setSelectedVictim(v)}
                                className="w-full text-left p-2.5 rounded-lg border border-rose-500/20 bg-[var(--bg-surface)] hover:border-rose-400 space-y-1 cursor-pointer"
                              >
                                <div className="flex items-center justify-between gap-2">
                                  <span className="font-extrabold preserve-case">
                                    {v.victim}
                                  </span>
                                  <span className="text-[10px] font-mono-ioc text-rose-300">
                                    {v.discovered.slice(0, 10)}
                                  </span>
                                </div>
                                <div className="text-[10px] text-[var(--text-secondary)]">
                                  GROUP: {v.group.toUpperCase()} · {v.sector}
                                </div>
                              </button>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {/* Hudson Rock Domain Infostealer Telemetry */}
                  {credReport.hudsonRockDomain && (
                    <div className="rounded-2xl glass-panel p-5 space-y-4">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div>
                          <h3 className="text-sm font-extrabold text-amber-400 flex items-center gap-1.5">
                            <UserCheck className="w-4 h-4" />
                            HUDSON ROCK INFOSTEALER DOMAIN EXPOSURE (
                            {credReport.hudsonRockDomain.domain})
                          </h3>
                          <p className="text-[11px] text-[var(--text-secondary)]">
                            COMPROMISED EMPLOYEES, END-USERS, THIRD PARTIES, STEALER FAMILIES &amp; TOP LOGIN ENDPOINTS
                          </p>
                        </div>
                        <div className="flex flex-wrap gap-1.5">
                          {credReport.hudsonRockDomain.lastEmployeeCompromised && (
                            <span className="text-[10px] font-mono-ioc px-2.5 py-1 rounded-full bg-rose-500/15 text-rose-300 border border-rose-500/35">
                              LAST EMP HIT:{" "}
                              {credReport.hudsonRockDomain.lastEmployeeCompromised.slice(
                                0,
                                10,
                              )}
                            </span>
                          )}
                          {credReport.hudsonRockDomain.lastUserCompromised && (
                            <span className="text-[10px] font-mono-ioc px-2.5 py-1 rounded-full bg-amber-500/15 text-amber-300 border border-amber-500/35">
                              LAST USER HIT:{" "}
                              {credReport.hudsonRockDomain.lastUserCompromised.slice(
                                0,
                                10,
                              )}
                            </span>
                          )}
                        </div>
                      </div>

                      {(credReport.hudsonRockDomain.antivirusStats ||
                        credReport.hudsonRockDomain.exposedApplications.length > 0) && (
                        <div className="flex flex-wrap items-center gap-2 text-[10px] font-bold">
                          {credReport.hudsonRockDomain.antivirusStats && (
                            <span className="px-2.5 py-1 rounded-lg border border-rose-500/30 bg-rose-500/10 text-rose-300">
                              HOST WITHOUT AV:{" "}
                              {credReport.hudsonRockDomain.antivirusStats.notFoundPct}% (
                              {credReport.hudsonRockDomain.antivirusStats.total} SAMPLED)
                            </span>
                          )}
                          {credReport.hudsonRockDomain.exposedApplications.map((app) => (
                            <span
                              key={app.keyword}
                              className="px-2.5 py-1 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-elevated)] font-mono-ioc"
                            >
                              {app.keyword.toUpperCase()}: {app.count}
                            </span>
                          ))}
                        </div>
                      )}

                      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 text-xs">
                        <div className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/50 space-y-2">
                          <div className="text-[10px] font-bold text-[var(--text-secondary)]">
                            TOP INFOSTEALER MALWARE FAMILIES
                          </div>
                          {credReport.hudsonRockDomain.stealerFamilies.length === 0 ? (
                            <p className="text-[var(--text-secondary)]">NO DATA</p>
                          ) : (
                            credReport.hudsonRockDomain.stealerFamilies.map((f) => (
                              <div
                                key={f.family}
                                className="flex items-center justify-between py-1 border-b border-[var(--border-subtle)]/40"
                              >
                                <span className="font-mono-ioc preserve-case font-bold">
                                  {f.family}
                                </span>
                                <span className="font-mono-ioc text-amber-400">
                                  {f.count.toLocaleString()}
                                </span>
                              </div>
                            ))
                          )}
                        </div>

                        <div className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/50 space-y-2">
                          <div className="text-[10px] font-bold text-[var(--text-secondary)]">
                            COMPROMISED EMPLOYEE LOGIN URLS
                          </div>
                          {credReport.hudsonRockDomain.employeeUrls.length === 0 ? (
                            <p className="text-[var(--text-secondary)]">NO EMPLOYEE URLS</p>
                          ) : (
                            credReport.hudsonRockDomain.employeeUrls.map((u) => (
                              <div
                                key={u.url}
                                className="flex items-center justify-between gap-2 py-1 border-b border-[var(--border-subtle)]/40"
                              >
                                <span className="font-mono-ioc preserve-case truncate">
                                  {u.url}
                                </span>
                                <span className="font-mono-ioc text-rose-300 shrink-0">
                                  {u.occurrence}x
                                </span>
                              </div>
                            ))
                          )}
                        </div>

                        <div className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/50 space-y-2">
                          <div className="text-[10px] font-bold text-[var(--text-secondary)]">
                            EMPLOYEE PASSWORD HYGIENE &amp; CLIENT URLS
                          </div>
                          {credReport.hudsonRockDomain.employeePasswords && (
                            <div className="grid grid-cols-2 gap-1.5 text-[10px] pb-2 border-b border-[var(--border-subtle)]/50">
                              <div className="p-2 rounded bg-rose-500/10 text-rose-300">
                                TOO WEAK:{" "}
                                {credReport.hudsonRockDomain.employeePasswords.tooWeakPct}%
                              </div>
                              <div className="p-2 rounded bg-amber-500/10 text-amber-300">
                                WEAK: {credReport.hudsonRockDomain.employeePasswords.weakPct}%
                              </div>
                              <div className="p-2 rounded bg-cyan-500/10 text-cyan-300">
                                MEDIUM:{" "}
                                {credReport.hudsonRockDomain.employeePasswords.mediumPct}%
                              </div>
                              <div className="p-2 rounded bg-emerald-500/10 text-emerald-300">
                                STRONG:{" "}
                                {credReport.hudsonRockDomain.employeePasswords.strongPct}%
                              </div>
                            </div>
                          )}
                          {credReport.hudsonRockDomain.clientUrls.slice(0, 6).map((u) => (
                            <div
                              key={u.url}
                              className="flex items-center justify-between gap-2 py-1 text-[11px]"
                            >
                              <span className="font-mono-ioc preserve-case truncate">
                                {u.url}
                              </span>
                              <span className="font-mono-ioc text-[var(--text-secondary)] shrink-0">
                                {u.occurrence}x
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Hudson Rock Infected Email Hosts */}
                  {credReport.hudsonRockEmail &&
                    credReport.hudsonRockEmail.hosts.length > 0 && (
                      <div className="rounded-2xl glass-panel p-5 space-y-4">
                        <h3 className="text-sm font-extrabold text-rose-400">
                          INFECTED INFOSTEALER HOSTS FOR {credReport.query} (
                          {credReport.hudsonRockEmail.hosts.length})
                        </h3>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                          {credReport.hudsonRockEmail.hosts.map((h, idx) => (
                            <div
                              key={`${h.dateCompromised}-${idx}`}
                              className="p-4 rounded-xl border border-rose-500/25 bg-rose-500/5 space-y-2"
                            >
                              <div className="flex items-center justify-between gap-2">
                                <div className="flex flex-wrap items-center gap-1.5">
                                  <span className="font-mono-ioc preserve-case font-extrabold text-rose-300">
                                    {h.computerName}
                                  </span>
                                  {h.stealerFamily && (
                                    <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/35">
                                      {h.stealerFamily}
                                    </span>
                                  )}
                                </div>
                                <span className="font-mono-ioc text-[10px] text-emerald-300">
                                  {h.dateCompromised.slice(0, 10)}
                                </span>
                              </div>
                              <div className="text-[11px] preserve-case space-y-1">
                                <div>
                                  <strong>OS:</strong> {h.operatingSystem}
                                </div>
                                <div className="font-mono-ioc break-all">
                                  <strong>MALWARE PATH:</strong> {h.malwarePath}
                                </div>
                                <div>
                                  <strong>IP:</strong>{" "}
                                  <span className="font-mono-ioc">{h.ip}</span> ·{" "}
                                  <strong>CORP SERVICES:</strong>{" "}
                                  {h.totalCorporateServices} ·{" "}
                                  <strong>USER SERVICES:</strong>{" "}
                                  {h.totalUserServices}
                                </div>
                                {h.topLogins.length > 0 && (
                                  <div className="font-mono-ioc text-[10px] text-[var(--text-secondary)]">
                                    SOURCE LOGINS: {h.topLogins.join(" · ")}
                                  </div>
                                )}
                                {h.topPasswords.length > 0 && (
                                  <div className="font-mono-ioc text-[10px] text-rose-300/90">
                                    SOURCE PASSWORDS: {h.topPasswords.join(" · ")}
                                  </div>
                                )}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                  {/* XposedOrNot Free Email Breach Analytics */}
                  {credReport.xposedOrNot &&
                    credReport.xposedOrNot.breaches.length > 0 && (
                      <div className="space-y-4">
                        <div className="rounded-2xl glass-panel p-5 space-y-4">
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <div>
                              <h3
                                className="text-sm font-extrabold"
                                style={{ color: "var(--accent)" }}
                              >
                                XPOSEDORNOT EMAIL BREACH TIMELINE (
                                {credReport.xposedOrNot.breaches.length})
                              </h3>
                              <p className="text-[11px] text-[var(--text-secondary)]">
                                FULL BREACH HISTORY, PASSWORD RISK &amp; EXPOSED ATTRIBUTES
                              </p>
                            </div>
                            {credReport.xposedOrNot.passwordStrength && (
                              <div className="flex flex-wrap gap-1.5 text-[10px] font-bold">
                                <span className="px-2 py-1 rounded bg-rose-500/15 text-rose-300">
                                  PLAINTEXT:{" "}
                                  {credReport.xposedOrNot.passwordStrength.plainText}
                                </span>
                                <span className="px-2 py-1 rounded bg-amber-500/15 text-amber-300">
                                  EASY CRACK:{" "}
                                  {credReport.xposedOrNot.passwordStrength.easyToCrack}
                                </span>
                                <span className="px-2 py-1 rounded bg-emerald-500/15 text-emerald-300">
                                  STRONG HASH:{" "}
                                  {credReport.xposedOrNot.passwordStrength.strongHash}
                                </span>
                              </div>
                            )}
                          </div>

                          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                            {credReport.xposedOrNot.breaches
                              .slice((xonBreachPage - 1) * 10, xonBreachPage * 10)
                              .map((b) => (
                                <div
                                  key={`${b.breach}-${b.xposedDate}`}
                                  className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/55 space-y-2"
                                >
                                  <div className="flex items-center justify-between gap-2">
                                    <span className="text-sm font-extrabold">
                                      {b.breach}
                                    </span>
                                    <span className="text-[10px] font-mono-ioc text-[var(--text-secondary)]">
                                      {b.xposedDate}
                                    </span>
                                  </div>
                                  <div className="flex flex-wrap gap-1.5 text-[10px] font-bold">
                                    {b.added && (
                                      <span className="font-mono-ioc px-2 py-0.5 rounded bg-amber-500/15 text-amber-300">
                                        INDEXED: {b.added.slice(0, 10)}
                                      </span>
                                    )}
                                    {b.domain && (
                                      <span className="font-mono-ioc preserve-case px-2 py-0.5 rounded bg-[var(--accent-soft)] text-[var(--accent)]">
                                        {b.domain}
                                      </span>
                                    )}
                                    <span className="px-2 py-0.5 rounded border border-[var(--border-subtle)]">
                                      {b.xposedRecords.toLocaleString()} RECORDS
                                    </span>
                                    <span className="px-2 py-0.5 rounded bg-rose-500/15 text-rose-300">
                                      PW RISK: {b.passwordRisk.toUpperCase()}
                                    </span>
                                    {b.reference && (
                                      <a
                                        href={b.reference}
                                        target="_blank"
                                        rel="noreferrer"
                                        style={{ color: "var(--accent)" }}
                                        className="inline-flex items-center gap-1 px-2 py-0.5 rounded border border-[var(--accent-border)] hover:underline"
                                      >
                                        EVIDENCE <ExternalLink className="w-2.5 h-2.5" />
                                      </a>
                                    )}
                                  </div>
                                  {b.details && (
                                    <p className="text-[11px] text-[var(--text-secondary)] preserve-case line-clamp-2">
                                      {b.details}
                                    </p>
                                  )}
                                  {b.xposedData.length > 0 && (
                                    <div className="flex flex-wrap gap-1">
                                      {b.xposedData.slice(0, 5).map((attr) => (
                                        <span
                                          key={attr}
                                          className="text-[9px] px-1.5 py-0.5 rounded bg-[var(--bg-surface)] border border-[var(--border-subtle)] text-[var(--text-secondary)]"
                                        >
                                          {attr}
                                        </span>
                                      ))}
                                    </div>
                                  )}
                                </div>
                              ))}
                          </div>
                        </div>

                        <PaginationControls
                          totalItems={credReport.xposedOrNot.breaches.length}
                          page={xonBreachPage}
                          pageSize={10}
                          onPageChange={(p) => setXonBreachPage(p)}
                          label="EMAIL BREACHES"
                        />
                      </div>
                    )}

                  {/* ProxyNova COMB Historical Archive (Uncensored Legacy Corpus) */}
                  <div className="rounded-2xl glass-panel p-5 space-y-4">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div>
                        <h3 className="text-sm font-extrabold text-rose-400">
                          HISTORICAL CREDENTIAL ARCHIVE (PROXYNOVA COMB) —{" "}
                          {credReport.comb.totalCount.toLocaleString()} MATCH(ES)
                        </h3>
                        <p className="text-[11px] text-[var(--text-secondary)]">
                          UNCENSORED LEGACY PLAINTEXT PAIRS (2021 ARCHIVE) ENRICHED WITH CORRELATED DOMAIN BREACH DATES
                        </p>
                      </div>
                      {credReport.comb.note && (
                        <span className="text-[10px] font-bold text-amber-300">
                          {credReport.comb.note}
                        </span>
                      )}
                    </div>

                    {credReport.comb.records.length === 0 ? (
                      <div className="p-6 text-center text-xs font-bold text-[var(--text-secondary)]">
                        NO COMB CREDENTIAL PAIRS FOUND FOR &quot;{credReport.query}&quot;.
                      </div>
                    ) : (
                      <div className="overflow-x-auto rounded-xl border border-[var(--border-subtle)]">
                        <table className="w-full text-left text-xs">
                          <thead className="bg-[var(--bg-elevated)] text-[10px] font-bold text-[var(--text-secondary)]">
                            <tr>
                              <th className="px-3 py-2.5">#</th>
                              <th className="px-3 py-2.5">IDENTIFIER / EMAIL</th>
                              <th className="px-3 py-2.5">LEAKED CREDENTIAL / SECRET</th>
                              <th className="px-3 py-2.5">LEAK DATE</th>
                              <th className="px-3 py-2.5">LEAK EVIDENCE / SOURCE</th>
                              <th className="px-3 py-2.5 text-right">COPY</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-[var(--border-subtle)]/50">
                            {credReport.comb.records.map((rec) => {
                              const displaySecret = uncensoredMode
                                ? rec.secret || "(empty)"
                                : rec.secret
                                  ? `${rec.secret.slice(0, 2)}${"*".repeat(Math.max(4, rec.secret.length - 2))}`
                                  : "(empty)";
                              const displayId = uncensoredMode
                                ? rec.identifier
                                : rec.identifier.replace(/(^.).*(@|$)/, "$1***$2");
                              return (
                                <tr
                                  key={`${rec.index}-${rec.rawLine}`}
                                  className="hover:bg-[var(--bg-elevated)]/40"
                                >
                                  <td className="px-3 py-2 font-mono-ioc text-[var(--text-secondary)]">
                                    {rec.index}
                                  </td>
                                  <td className="px-3 py-2 font-mono-ioc preserve-case font-semibold">
                                    <div>{displayId}</div>
                                    {rec.domain && (
                                      <div className="text-[10px] text-[var(--text-secondary)] font-normal">
                                        {rec.domain}
                                      </div>
                                    )}
                                  </td>
                                  <td className="px-3 py-2 font-mono-ioc preserve-case text-rose-300 font-bold break-all">
                                    {displaySecret}
                                  </td>
                                  <td className="px-3 py-2 font-mono-ioc whitespace-nowrap">
                                    {rec.leakDate ? (
                                      <span className="px-2 py-0.5 rounded bg-amber-500/15 text-amber-300 border border-amber-500/35 text-[10px] font-bold">
                                        {rec.leakDate}
                                      </span>
                                    ) : (
                                      <span className="text-[10px] text-[var(--text-secondary)]">
                                        COMB 2021
                                      </span>
                                    )}
                                  </td>
                                  <td className="px-3 py-2 text-[11px] preserve-case">
                                    <div className="text-[var(--text-secondary)] max-w-xs">
                                      {rec.evidenceSource || rec.sourceCorpus}
                                    </div>
                                    {rec.evidenceUrl && (
                                      <a
                                        href={rec.evidenceUrl}
                                        target="_blank"
                                        rel="noreferrer"
                                        style={{ color: "var(--accent)" }}
                                        className="inline-flex items-center gap-1 text-[10px] font-bold hover:underline"
                                      >
                                        VERIFY SOURCE <ExternalLink className="w-2.5 h-2.5" />
                                      </a>
                                    )}
                                  </td>
                                  <td className="px-3 py-2 text-right">
                                    <button
                                      type="button"
                                      onClick={() =>
                                        copyValue(`comb-${rec.index}`, rec.rawLine)
                                      }
                                      className="inline-flex items-center gap-1 px-2 py-1 rounded border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-[10px] font-bold cursor-pointer"
                                    >
                                      {copiedToken === `comb-${rec.index}` ? (
                                        <Check className="w-3 h-3 text-emerald-400" />
                                      ) : (
                                        <Copy className="w-3 h-3" />
                                      )}
                                      PAIR
                                    </button>
                                  </td>
                                </tr>
                              );
                            })}
                          </tbody>
                        </table>
                      </div>
                    )}

                    <PaginationControls
                      totalItems={credReport.comb.totalCount}
                      page={credPage}
                      pageSize={credPageSize}
                      pageSizeOptions={[20, 50, 100]}
                      onPageChange={(p) =>
                        runCredentialScan(credReport.query, p, credPageSize)
                      }
                      onPageSizeChange={(s) =>
                        runCredentialScan(credReport.query, 1, s)
                      }
                      label="CREDENTIAL PAIRS"
                    />
                  </div>
                </div>
              )}
            </div>
          )}

          {/* BREACHES & STEALER LOGS TAB WITH PAGINATION */}
          {tab === "breaches" && dash && (
            <div className="grid grid-cols-1 xl:grid-cols-12 gap-6">
              <div className="xl:col-span-8 space-y-4">
                <div className="rounded-2xl glass-panel p-5 space-y-4">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div>
                      <h2 className="text-sm font-extrabold">
                        DATA BREACHES &amp; STEALER LOGS ({filteredBreaches.length})
                      </h2>
                      <p className="text-[11px] text-[var(--text-secondary)]">
                        HAVE I BEEN PWNED CATALOG SORTED BY LATEST DISCOVERY
                      </p>
                    </div>
                    <div className="flex flex-wrap items-center gap-2">
                      <input
                        type="text"
                        value={breachFilter}
                        onChange={(e) => setBreachFilter(e.target.value)}
                        placeholder="FILTER BREACH OR DOMAIN..."
                        className="px-3 py-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] font-mono-ioc text-xs"
                      />
                      <label className="inline-flex items-center gap-2 text-xs font-bold cursor-pointer">
                        <input
                          type="checkbox"
                          checked={stealerOnly}
                          onChange={(e) => setStealerOnly(e.target.checked)}
                          className="accent-rose-500"
                        />
                        STEALER LOGS ONLY
                      </label>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {pagedBreaches.map((b) => (
                      <div
                        key={b.name}
                        className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/55 space-y-2"
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-sm font-extrabold">{b.title}</span>
                          <span className="text-[10px] font-mono-ioc text-[var(--text-secondary)]">
                            {b.breachDate}
                          </span>
                        </div>
                        <div className="flex flex-wrap items-center gap-1.5 text-[10px] font-bold">
                          {b.domain && (
                            <Link
                              href={`/?ioc=${encodeURIComponent(b.domain)}`}
                              className="font-mono-ioc preserve-case px-2 py-0.5 rounded hover:underline"
                              style={{
                                backgroundColor: "var(--accent-soft)",
                                color: "var(--accent)",
                              }}
                            >
                              {b.domain} ↗
                            </Link>
                          )}
                          <span className="px-2 py-0.5 rounded border border-[var(--border-subtle)]">
                            {b.pwnCount.toLocaleString()} RECORDS
                          </span>
                          {b.isStealerLog && (
                            <span className="px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/35">
                              STEALER LOG
                            </span>
                          )}
                        </div>
                        <p className="text-[11px] text-[var(--text-secondary)] preserve-case line-clamp-2">
                          {b.description}
                        </p>
                        <div className="flex flex-wrap gap-1 pt-1">
                          {b.dataClasses.slice(0, 4).map((dc) => (
                            <span
                              key={dc}
                              className="text-[9px] px-1.5 py-0.5 rounded bg-[var(--bg-surface)] border border-[var(--border-subtle)] text-[var(--text-secondary)]"
                            >
                              {dc}
                            </span>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                <PaginationControls
                  totalItems={filteredBreaches.length}
                  page={breachPage}
                  pageSize={breachPageSize}
                  onPageChange={(p) => setBreachPage(p)}
                  onPageSizeChange={(s) => setBreachPageSize(s)}
                  label="BREACHES"
                />
              </div>

              <div className="xl:col-span-4 space-y-4">
                <div className="rounded-2xl glass-panel p-5 space-y-4">
                  <div>
                    <h2 className="text-sm font-extrabold">
                      LEAKED DATABASE DOMAINS ({filteredLeakDomains.length})
                    </h2>
                    <p className="text-[11px] text-[var(--text-secondary)]">
                      INDEXED BREACH DUMPS FROM RANSOMLOOK
                    </p>
                  </div>

                  <input
                    type="text"
                    value={leakDomainFilter}
                    onChange={(e) => setLeakDomainFilter(e.target.value)}
                    placeholder="FILTER LEAKED DOMAIN..."
                    className="w-full px-3 py-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] font-mono-ioc text-xs"
                  />

                  <div className="space-y-1.5">
                    {pagedLeakDomains.map((d) => (
                      <div
                        key={`${d.id}-${d.domain}`}
                        className="w-full px-3 py-2 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/45 hover:border-[var(--accent-border)] font-mono-ioc preserve-case text-xs flex items-center justify-between gap-2"
                      >
                        <button
                          type="button"
                          onClick={() => {
                            setQuery(d.domain);
                            runSearch(d.domain);
                          }}
                          className="truncate text-left flex-1 cursor-pointer hover:underline"
                        >
                          {d.domain}
                        </button>
                        <div className="flex items-center gap-2 shrink-0">
                          <button
                            type="button"
                            onClick={() => runCredentialScan(d.domain, 1, credPageSize)}
                            className="text-[9px] font-bold text-rose-300 hover:underline cursor-pointer"
                          >
                            CREDS →
                          </button>
                          {d.sourceUrl && (
                            <a
                              href={d.sourceUrl}
                              target="_blank"
                              rel="noreferrer"
                              title="Open RansomLook Leak Record"
                              style={{ color: "var(--accent)" }}
                              className="inline-flex items-center hover:opacity-80"
                            >
                              <ExternalLink className="w-3 h-3" />
                            </a>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                <PaginationControls
                  totalItems={filteredLeakDomains.length}
                  page={leakPage}
                  pageSize={20}
                  onPageChange={(p) => setLeakPage(p)}
                  label="DOMAINS"
                />
              </div>
            </div>
          )}

          {/* ACTORS & MARKETS TAB WITH PAGINATION */}
          {tab === "actors" && dash && (
            <div className="space-y-4">
              <div className="rounded-2xl glass-panel p-5 space-y-5">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div>
                    <h2 className="text-sm font-extrabold">
                      TRACKED RANSOMWARE GROUPS &amp; UNDERGROUND MARKETS
                    </h2>
                    <p className="text-[11px] text-[var(--text-secondary)]">
                      ACTIVE THREAT ACTOR EXTORTION SITES AND DARKWEB MARKETPLACES
                    </p>
                  </div>
                  <input
                    type="text"
                    value={actorFilter}
                    onChange={(e) => setActorFilter(e.target.value)}
                    placeholder="FILTER GROUP OR MARKET NAME..."
                    className="px-3 py-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] font-mono-ioc text-xs"
                  />
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
                  <div className="space-y-3">
                    <h3 className="text-xs font-bold text-rose-400">
                      RANSOMWARE GROUPS ({filteredGroups.length})
                    </h3>
                    <div className="flex flex-wrap gap-1.5">
                      {pagedGroups.map((g) => (
                        <button
                          key={g}
                          type="button"
                          onClick={() => {
                            setQuery(g);
                            runSearch(g);
                          }}
                          className="px-2.5 py-1.5 rounded-lg border border-rose-500/25 bg-rose-500/10 text-rose-300 text-[11px] font-mono-ioc hover:border-rose-400 cursor-pointer"
                        >
                          {g}
                        </button>
                      ))}
                    </div>
                  </div>

                  <div className="space-y-3">
                    <h3
                      className="text-xs font-bold"
                      style={{ color: "var(--accent)" }}
                    >
                      UNDERGROUND MARKETS &amp; FORUMS ({filteredMarkets.length})
                    </h3>
                    <div className="flex flex-wrap gap-1.5 max-h-[460px] overflow-y-auto">
                      {filteredMarkets.map((m) => (
                        <span
                          key={m}
                          className="px-2.5 py-1.5 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-[11px] font-mono-ioc"
                        >
                          {m}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              </div>

              <PaginationControls
                totalItems={filteredGroups.length}
                page={groupPage}
                pageSize={60}
                onPageChange={(p) => setGroupPage(p)}
                label="RANSOMWARE GROUPS"
              />
            </div>
          )}

          {/* WATCHLIST MONITORS TAB */}
          {tab === "monitors" && (
            <div className="rounded-2xl glass-panel p-5 space-y-5">
              <div>
                <h2 className="text-sm font-extrabold">
                  DARKWEB WATCHLIST MONITORS ({monitors.length})
                </h2>
                <p className="text-[11px] text-[var(--text-secondary)]">
                  ADD ORGANIZATION DOMAINS, BRANDS, VIP EMAILS, OR KEYWORDS TO CONTINUOUSLY MATCH AGAINST LEAK FEEDS.
                </p>
              </div>

              <form
                onSubmit={handleAddMonitor}
                className="grid grid-cols-1 sm:grid-cols-12 gap-2.5 p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/50"
              >
                <input
                  type="text"
                  required
                  value={monTarget}
                  onChange={(e) => setMonTarget(e.target.value)}
                  placeholder="TARGET (E.G. ACME.COM, CEO@ACME.COM, BRAND)"
                  className="sm:col-span-4 px-3 py-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-surface)] font-mono-ioc text-xs"
                />
                <select
                  value={monType}
                  onChange={(e) =>
                    setMonType(
                      e.target.value as "DOMAIN" | "BRAND" | "EMAIL" | "KEYWORD",
                    )
                  }
                  className="sm:col-span-2 px-3 py-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-surface)] text-xs font-bold"
                >
                  <option value="DOMAIN">DOMAIN</option>
                  <option value="BRAND">BRAND</option>
                  <option value="EMAIL">EMAIL</option>
                  <option value="KEYWORD">KEYWORD</option>
                </select>
                <input
                  type="text"
                  value={monNotes}
                  onChange={(e) => setMonNotes(e.target.value)}
                  placeholder="NOTES (E.G. PRIMARY CORPORATE DOMAIN)"
                  className="sm:col-span-4 px-3 py-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-surface)] text-xs"
                />
                <button
                  type="submit"
                  style={{ backgroundColor: "var(--accent)" }}
                  className="sm:col-span-2 inline-flex items-center justify-center gap-1 px-3 py-2 rounded-xl text-white text-xs font-bold cursor-pointer"
                >
                  <Plus className="w-3.5 h-3.5" /> MONITOR
                </button>
              </form>

              <div className="space-y-3">
                {monitors.map((m) => {
                  const hasHits = m.evaluation.matchCount > 0;
                  const expanded = expandedMonitorId === m.id;
                  return (
                    <div
                      key={m.id}
                      className={`p-4 rounded-xl border space-y-3 ${
                        hasHits
                          ? "border-rose-500/35 bg-rose-500/5"
                          : "border-[var(--border-subtle)] bg-[var(--bg-elevated)]/45"
                      }`}
                    >
                      <div className="flex flex-wrap items-center justify-between gap-3">
                        <div className="flex flex-wrap items-center gap-2.5">
                          <span
                            className="text-[9px] font-bold px-2 py-0.5 rounded"
                            style={{
                              backgroundColor: "var(--accent-soft)",
                              color: "var(--accent)",
                            }}
                          >
                            {m.targetType}
                          </span>
                          <span className="font-mono-ioc preserve-case text-sm font-extrabold">
                            {m.target}
                          </span>
                          {hasHits ? (
                            <span className="inline-flex items-center gap-1 text-[10px] font-extrabold px-2.5 py-0.5 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/40">
                              <AlertTriangle className="w-3 h-3" />
                              {m.evaluation.matchCount} EXPOSURE MATCH(ES)
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 text-[10px] font-extrabold px-2.5 py-0.5 rounded-full bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                              <CheckCircle2 className="w-3 h-3" /> CLEAR
                            </span>
                          )}
                        </div>

                        <div className="flex items-center gap-2">
                          <button
                            type="button"
                            onClick={() =>
                              runCredentialScan(m.target, 1, credPageSize)
                            }
                            className="text-xs font-bold text-rose-300 hover:underline cursor-pointer"
                          >
                            CREDENTIAL SCAN →
                          </button>
                          {hasHits && (
                            <button
                              type="button"
                              onClick={() =>
                                setExpandedMonitorId(expanded ? null : m.id)
                              }
                              style={{ color: "var(--accent)" }}
                              className="text-xs font-bold hover:underline cursor-pointer"
                            >
                              {expanded ? "HIDE MATCHES" : "VIEW MATCHES"}
                            </button>
                          )}
                          <button
                            type="button"
                            onClick={() => handleDeleteMonitor(m.id)}
                            className="p-1.5 rounded-lg text-rose-400 hover:bg-rose-500/15 cursor-pointer"
                            title="REMOVE MONITOR"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </div>

                      {m.notes && (
                        <p className="text-xs text-[var(--text-secondary)] preserve-case">
                          {m.notes}
                        </p>
                      )}

                      {expanded && hasHits && (
                        <div className="pt-3 border-t border-rose-500/20 grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
                          <div>
                            <div className="text-[10px] font-bold text-rose-300 mb-1">
                              RANSOMWARE VICTIMS ({m.evaluation.victimHits.length})
                            </div>
                            {m.evaluation.victimHits.map((vh, i) => (
                              <div key={i} className="preserve-case text-[11px] py-1">
                                <strong>{vh.victim}</strong> ({vh.group})
                              </div>
                            ))}
                          </div>
                          <div>
                            <div className="text-[10px] font-bold text-amber-300 mb-1">
                              HIBP BREACHES ({m.evaluation.breachHits.length})
                            </div>
                            {m.evaluation.breachHits.map((bh) => (
                              <div key={bh.name} className="preserve-case text-[11px] py-1">
                                <strong>{bh.title}</strong> ({bh.breachDate})
                              </div>
                            ))}
                          </div>
                          <div>
                            <div className="text-[10px] font-bold text-cyan-300 mb-1">
                              LEAKED DB DOMAINS ({m.evaluation.leakedDomainHits.length})
                            </div>
                            {m.evaluation.leakedDomainHits.map((lh) => (
                              <div key={lh.domain} className="font-mono-ioc preserve-case text-[11px] py-1">
                                {lh.domain}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* SEARCH RESULTS TAB */}
          {tab === "search" && (
            <div className="rounded-2xl glass-panel p-5 space-y-5">
              <h2 className="text-sm font-extrabold">
                CROSS-SOURCE DARKWEB SEARCH RESULTS
                {searchResult ? ` — "${searchResult.query.toUpperCase()}"` : ""}
              </h2>

              {searching ? (
                <div className="p-10 text-center text-xs font-bold text-[var(--text-secondary)] flex items-center justify-center gap-2">
                  <Loader2 className="w-4 h-4 animate-spin" /> SCANNING DARKWEB DATASETS...
                </div>
              ) : !searchResult ? (
                <div className="p-10 text-center text-xs font-bold text-[var(--text-secondary)]">
                  ENTER A DOMAIN, BRAND, EMAIL, OR RANSOMWARE GANG ABOVE TO SCAN ALL DARKWEB SOURCES.
                </div>
              ) : (
                <div className="space-y-5">
                  {searchResult.emailLookupNote && (
                    <div className="p-3.5 rounded-xl border border-amber-500/30 bg-amber-500/10 text-amber-300 text-xs font-bold">
                      {searchResult.emailLookupNote}
                    </div>
                  )}

                  {searchResult.emailBreaches &&
                    searchResult.emailBreaches.length > 0 && (
                      <div className="space-y-2">
                        <h3 className="text-xs font-bold text-rose-400">
                          EMAIL ACCOUNT BREACHES ({searchResult.emailBreaches.length})
                        </h3>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                          {searchResult.emailBreaches.map((b) => (
                            <div
                              key={b.name}
                              className="p-3.5 rounded-xl border border-rose-500/30 bg-rose-500/10 text-xs space-y-1"
                            >
                              <div className="font-extrabold">
                                {b.title} ({b.breachDate})
                              </div>
                              <div className="text-[11px] preserve-case">
                                {b.dataClasses.join(", ")}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                  <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                    <div className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/45 space-y-2">
                      <h3 className="text-xs font-bold text-rose-400">
                        RANSOMWARE VICTIMS ({searchResult.victims.length})
                      </h3>
                      {searchResult.victims.length === 0 ? (
                        <p className="text-xs text-[var(--text-secondary)]">NO MATCHES</p>
                      ) : (
                        searchResult.victims.map((v, i) => (
                          <button
                            key={i}
                            type="button"
                            onClick={() => setSelectedVictim(v)}
                            className="w-full text-left text-xs py-1.5 border-b border-[var(--border-subtle)]/50 preserve-case hover:underline cursor-pointer"
                          >
                            <strong>{v.victim}</strong> • {v.group} ({v.discovered.slice(0, 10)})
                          </button>
                        ))
                      )}
                    </div>

                    <div className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/45 space-y-2">
                      <h3 className="text-xs font-bold text-amber-400">
                        HIBP BREACHES ({searchResult.breaches.length})
                      </h3>
                      {searchResult.breaches.length === 0 ? (
                        <p className="text-xs text-[var(--text-secondary)]">NO MATCHES</p>
                      ) : (
                        searchResult.breaches.map((b) => (
                          <div key={b.name} className="text-xs py-1.5 border-b border-[var(--border-subtle)]/50 preserve-case">
                            <strong>{b.title}</strong> ({b.domain || "—"}) • {b.pwnCount.toLocaleString()}
                          </div>
                        ))
                      )}
                    </div>

                    <div className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/45 space-y-2">
                      <h3
                        className="text-xs font-bold"
                        style={{ color: "var(--accent)" }}
                      >
                        LEAKED DOMAINS &amp; ACTORS (
                        {searchResult.leakedDomains.length +
                          searchResult.groups.length +
                          searchResult.markets.length}
                        )
                      </h3>
                      {searchResult.leakedDomains.map((d) => (
                        <div key={d.domain} className="font-mono-ioc preserve-case text-xs py-1">
                          DB LEAK: {d.domain}
                        </div>
                      ))}
                      {searchResult.groups.map((g) => (
                        <div key={g} className="font-mono-ioc preserve-case text-xs py-1 text-rose-300">
                          GROUP: {g}
                        </div>
                      ))}
                      {searchResult.markets.map((m) => (
                        <div key={m} className="font-mono-ioc preserve-case text-xs py-1 text-amber-300">
                          MARKET: {m}
                        </div>
                      ))}
                      {searchResult.leakedDomains.length === 0 &&
                        searchResult.groups.length === 0 &&
                        searchResult.markets.length === 0 && (
                          <p className="text-xs text-[var(--text-secondary)]">NO MATCHES</p>
                        )}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </>
      )}

      {/* Expert Darkweb Victim Dossier Modal (Near-Fullscreen Workspace) */}
      {selectedVictim && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-2 sm:p-4">
          <div className="w-[96vw] max-w-[1600px] h-[92vh] max-h-[92vh] flex flex-col rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-surface-solid)] shadow-2xl overflow-hidden">
            {/* Sticky Header */}
            <div className="shrink-0 flex items-start justify-between gap-4 border-b border-[var(--border-subtle)] bg-[var(--bg-surface)] px-5 sm:px-8 py-4">
              <div className="space-y-2 min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-[10px] font-extrabold px-2.5 py-0.5 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/35">
                    {selectedVictim.group}
                  </span>
                  {selectedVictim.countryCode !== "UNSPECIFIED" && (
                    <span
                      className="text-[10px] font-extrabold px-2.5 py-0.5 rounded-full"
                      style={{
                        backgroundColor: "var(--accent-soft)",
                        color: "var(--accent)",
                      }}
                    >
                      {selectedVictim.countryCode} · {selectedVictim.countryName}
                    </span>
                  )}
                  <span className="text-[10px] font-bold px-2.5 py-0.5 rounded-full border border-[var(--border-subtle)]">
                    {selectedVictim.sector}
                  </span>
                  {selectedVictim.hasMagnet && (
                    <span className="text-[10px] font-extrabold px-2.5 py-0.5 rounded-full bg-orange-500/20 text-orange-300 border border-orange-500/35">
                      TORRENT LEAK PUBLISHED
                    </span>
                  )}
                </div>
                <h2 className="text-xl sm:text-2xl font-extrabold preserve-case">
                  {selectedVictim.victim}
                </h2>
                <div className="text-xs font-mono-ioc text-[var(--text-secondary)]">
                  DISCOVERED: {selectedVictim.discovered}
                </div>
              </div>

              <button
                type="button"
                onClick={() => setSelectedVictim(null)}
                className="p-2.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] hover:border-[var(--accent-border)] cursor-pointer shrink-0"
                aria-label="Close victim dossier"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Scrollable 12-Col Body */}
            <div className="flex-1 overflow-y-auto px-5 sm:px-8 py-6">
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                <div className="lg:col-span-7 space-y-5">
                  {selectedVictim.description && (
                    <div className="p-5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/40 space-y-2">
                      <div className="text-[11px] font-bold tracking-widest text-[var(--text-secondary)]">
                        EXTORTION POST DETAILS
                      </div>
                      <p className="text-xs sm:text-sm preserve-case leading-relaxed">
                        {selectedVictim.description}
                      </p>
                    </div>
                  )}

                  {selectedVictim.screenshotUrl && (
                    <div className="p-5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/40 space-y-2.5">
                      <div className="text-[11px] font-bold tracking-widest text-[var(--text-secondary)]">
                        LEAK SITE CAPTURE PREVIEW
                      </div>
                      <div className="rounded-xl border border-[var(--border-subtle)] overflow-hidden bg-black/40">
                        {/* eslint-disable-next-line @next/next/no-img-element */}
                        <img
                          src={selectedVictim.screenshotUrl}
                          alt={selectedVictim.victim}
                          onError={(e) => {
                            e.currentTarget.style.display = "none";
                          }}
                          className="w-full max-h-[480px] object-contain"
                        />
                      </div>
                    </div>
                  )}
                </div>

                <div className="lg:col-span-5 space-y-4">
                  <div className="p-5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/40 space-y-3 text-xs">
                    <div className="text-[11px] font-bold tracking-widest text-[var(--text-secondary)]">
                      VICTIM ATTRIBUTION &amp; INFRASTRUCTURE
                    </div>
                    <div>
                      <strong>THREAT ACTOR GROUP:</strong>{" "}
                      <span className="font-mono-ioc text-rose-300">
                        {selectedVictim.group}
                      </span>
                    </div>
                    <div>
                      <strong>DETECTED COUNTRY:</strong>{" "}
                      {selectedVictim.countryCode} · {selectedVictim.countryName}
                    </div>
                    <div>
                      <strong>INDUSTRY SECTOR:</strong> {selectedVictim.sector}
                    </div>
                    <div>
                      <strong>EXTRACTED DOMAIN:</strong>{" "}
                      <span className="font-mono-ioc preserve-case">
                        {selectedVictim.extractedDomain || "NOT EXTRACTED"}
                      </span>
                    </div>
                  </div>

                  {selectedVictim.mispUuid && (
                    <div className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/60 space-y-1.5 text-xs">
                      <div className="text-[10px] font-bold text-[var(--text-secondary)]">
                        MISP EVENT UUID
                      </div>
                      <div className="flex items-center justify-between gap-2">
                        <code className="font-mono-ioc preserve-case text-xs break-all">
                          {selectedVictim.mispUuid}
                        </code>
                        <button
                          type="button"
                          onClick={() => copyValue("misp", selectedVictim.mispUuid!)}
                          className="p-1.5 rounded border border-[var(--border-subtle)] cursor-pointer shrink-0"
                        >
                          {copiedToken === "misp" ? (
                            <Check className="w-3.5 h-3.5 text-emerald-400" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                        </button>
                      </div>
                    </div>
                  )}

                  {selectedVictim.onionLink && (
                    <div className="p-4 rounded-xl border border-rose-500/25 bg-rose-500/5 space-y-1.5 text-xs">
                      <div className="text-[10px] font-bold text-rose-300">
                        {selectedVictim.onionLink.startsWith("/")
                          ? "EXTORTION BLOG .ONION PATH (APPEND TO GANG MIRROR)"
                          : "TOR .ONION LEAK PORTAL (COPY FOR TOR BROWSER)"}
                      </div>
                      <div className="flex items-center justify-between gap-2">
                        <code className="font-mono-ioc preserve-case text-xs break-all text-rose-200">
                          {selectedVictim.onionLink}
                        </code>
                        <button
                          type="button"
                          onClick={() =>
                            copyValue("onion", selectedVictim.onionLink!)
                          }
                          className="p-1.5 rounded border border-rose-500/30 cursor-pointer shrink-0"
                        >
                          {copiedToken === "onion" ? (
                            <Check className="w-3.5 h-3.5 text-emerald-400" />
                          ) : (
                            <Copy className="w-3.5 h-3.5 text-rose-300" />
                          )}
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Sticky Footer */}
            <div className="shrink-0 flex flex-wrap items-center justify-between gap-3 border-t border-[var(--border-subtle)] bg-[var(--bg-surface)] px-5 sm:px-8 py-3.5">
              {selectedVictim.extractedDomain ? (
                <Link
                  href={`/?ioc=${encodeURIComponent(selectedVictim.extractedDomain)}`}
                  style={{ backgroundColor: "var(--accent)" }}
                  className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl text-white text-xs font-bold"
                >
                  INVESTIGATE {selectedVictim.extractedDomain} IN IOC LOOKUP
                  <ArrowUpRight className="w-3.5 h-3.5" />
                </Link>
              ) : (
                <span className="text-xs text-[var(--text-secondary)]">
                  NO CLEARNET DOMAIN EXTRACTED FROM POST
                </span>
              )}

              <div className="flex items-center gap-2">
                {selectedVictim.sourceUrl && (
                  <a
                    href={selectedVictim.sourceUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1 px-3.5 py-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-xs font-bold"
                  >
                    OPEN RANSOMLOOK RECORD <ExternalLink className="w-3.5 h-3.5" />
                  </a>
                )}
                <button
                  type="button"
                  onClick={() => setSelectedVictim(null)}
                  className="px-4 py-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-xs font-bold cursor-pointer"
                >
                  CLOSE DOSSIER
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default function DarkwebPage() {
  return (
    <Suspense
      fallback={
        <div className="p-12 text-center text-xs font-bold text-[var(--text-secondary)]">
          LOADING DARKWEB MONITORING CONSOLE...
        </div>
      }
    >
      <DarkwebDashboardContent />
    </Suspense>
  );
}
