"use client";

import React, { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  Activity,
  ArrowUpRight,
  Bug,
  Check,
  Copy,
  Download,
  ExternalLink,
  Globe,
  Loader2,
  Radio,
  RefreshCw,
  Server,
  ShieldAlert,
  X,
} from "lucide-react";
import type {
  AttackCategory,
  AttackIocType,
  LiveAttackFeedSnapshot,
  LiveAttackIoc,
} from "@/lib/attack-iocs";
import { PaginationControls } from "@/components/PaginationControls";

export default function LiveAttackIocsPage() {
  const [snap, setSnap] = useState<LiveAttackFeedSnapshot | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Real-time auto-sync controls
  const [liveStream, setLiveStream] = useState(true);
  const [intervalSec, setIntervalSec] = useState(30);
  const [countdown, setCountdown] = useState(30);

  // Filters & pagination
  const [typeFilter, setTypeFilter] = useState<"ALL" | AttackIocType>("ALL");
  const [catFilter, setCatFilter] = useState<"ALL" | AttackCategory>("ALL");
  const [countryFilter, setCountryFilter] = useState("ALL");
  const [sourceFilter, setSourceFilter] = useState("ALL");
  const [searchText, setSearchText] = useState("");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);

  // Dossier modal
  const [selected, setSelected] = useState<LiveAttackIoc | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const fetchAttacks = useCallback(async (force = false) => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(
        `/api/attacks${force ? "?refresh=true" : ""}`,
        { cache: "no-store" },
      );
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || "FAILED TO SYNC LIVE ATTACK IOC FEEDS");
      } else {
        setSnap(data);
      }
    } catch {
      setError("NETWORK ERROR FETCHING LIVE ATTACK TELEMETRY.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAttacks(false);
  }, [fetchAttacks]);

  useEffect(() => {
    setCountdown(intervalSec);
    if (!liveStream) return;

    const timer = setInterval(() => {
      setCountdown((prev) => {
        if (prev <= 1) {
          fetchAttacks(true);
          return intervalSec;
        }
        return prev - 1;
      });
    }, 1000);

    return () => clearInterval(timer);
  }, [liveStream, intervalSec, fetchAttacks]);

  const countries = useMemo(() => {
    return Array.from(
      new Set((snap?.items || []).map((i) => i.country).filter(Boolean)),
    ).sort() as string[];
  }, [snap?.items]);

  const sources = useMemo(() => {
    return Array.from(new Set((snap?.items || []).map((i) => i.sourceFeed))).sort();
  }, [snap?.items]);

  const filtered = useMemo(() => {
    const q = searchText.trim().toLowerCase();
    return (snap?.items || []).filter((item) => {
      if (typeFilter !== "ALL" && item.iocType !== typeFilter) return false;
      if (catFilter !== "ALL" && item.attackType !== catFilter) return false;
      if (countryFilter !== "ALL" && item.country !== countryFilter) return false;
      if (sourceFilter !== "ALL" && item.sourceFeed !== sourceFilter) return false;
      if (!q) return true;
      return (
        item.ioc.toLowerCase().includes(q) ||
        item.malwareFamily.toLowerCase().includes(q) ||
        item.summary.toLowerCase().includes(q) ||
        (item.asName && item.asName.toLowerCase().includes(q)) ||
        (item.hostname && item.hostname.toLowerCase().includes(q)) ||
        item.cves.some((c) => c.toLowerCase().includes(q)) ||
        item.tags.some((t) => t.toLowerCase().includes(q))
      );
    });
  }, [snap?.items, typeFilter, catFilter, countryFilter, sourceFilter, searchText]);

  useEffect(() => {
    setPage(1);
  }, [typeFilter, catFilter, countryFilter, sourceFilter, searchText, pageSize]);

  const pagedItems = useMemo(() => {
    const start = (page - 1) * pageSize;
    return filtered.slice(start, start + pageSize);
  }, [filtered, page, pageSize]);

  const copyValue = async (key: string, val: string) => {
    try {
      await navigator.clipboard.writeText(val);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 1400);
    } catch {
      // Ignore clipboard failures in restricted environments
    }
  };

  const exportIocs = (format: "csv" | "json") => {
    if (filtered.length === 0) return;
    let content = "";
    let mime = "application/json";
    if (format === "json") {
      content = JSON.stringify(filtered, null, 2);
    } else {
      mime = "text/csv";
      const header = [
        "ioc",
        "type",
        "attack_type",
        "malware_family",
        "severity",
        "confidence",
        "status",
        "source_feed",
        "country",
        "asn",
        "as_name",
        "ports",
        "cves",
        "first_seen",
        "last_seen",
        "summary",
      ];
      const rows = filtered.map((r) =>
        [
          r.ioc,
          r.iocType,
          r.attackType,
          r.malwareFamily,
          r.severity,
          r.confidence,
          r.status,
          r.sourceFeed,
          r.country || "",
          r.asn || "",
          r.asName || "",
          r.ports.join(";"),
          r.cves.join(";"),
          r.firstSeen || "",
          r.lastSeen || "",
          r.summary,
        ]
          .map((c) => `"${String(c).replace(/"/g, '""')}"`)
          .join(","),
      );
      content = [header.join(","), ...rows].join("\n");
    }
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `eyesight-live-attack-iocs.${format}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6 w-full">
      {/* Header + Real-Time Live Stream Controls */}
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
              <Activity className="w-3.5 h-3.5" />
              SANS DSHIELD · FEODO TRACKER · C2INTEL · OPENPHISH · SHODAN INTERNETDB
            </div>
            <h1 className="text-xl sm:text-2xl lg:text-3xl font-extrabold tracking-tight">
              LIVE ATTACK IOC STREAM &amp; THREAT CAMPAIGNS
            </h1>
            <p className="text-xs sm:text-sm text-[var(--text-secondary)]">
              REAL-TIME STREAM OF ACTIVE BOTNET C2S, BRUTE-FORCE SCANNERS, PHISHING LURES &amp; MALWARE PAYLOADS ENRICHED WITH OPEN PORTS, CVES &amp; ASN TELEMETRY.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={() => setLiveStream((v) => !v)}
              className={`inline-flex items-center gap-2 px-3.5 py-2 rounded-xl border text-xs font-extrabold cursor-pointer ${
                liveStream
                  ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-300"
                  : "border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-[var(--text-secondary)]"
              }`}
            >
              <Radio
                className={`w-3.5 h-3.5 ${liveStream ? "animate-pulse text-emerald-400" : ""}`}
              />
              {liveStream ? `LIVE AUTO-SYNC (${countdown}s)` : "LIVE SYNC PAUSED"}
            </button>

            <select
              value={intervalSec}
              onChange={(e) => setIntervalSec(Number(e.target.value))}
              aria-label="Live refresh interval"
              className="px-3 py-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-xs font-bold cursor-pointer"
            >
              <option value={15}>EVERY 15s</option>
              <option value={30}>EVERY 30s</option>
              <option value={60}>EVERY 60s</option>
            </select>

            <button
              type="button"
              onClick={() => {
                setCountdown(intervalSec);
                fetchAttacks(true);
              }}
              disabled={loading}
              style={{ backgroundColor: "var(--accent)" }}
              className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl text-white text-xs font-bold hover:opacity-90 disabled:opacity-50 cursor-pointer"
            >
              <RefreshCw
                className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`}
              />
              SYNC NOW
            </button>
          </div>
        </div>

        {/* KPI Cards */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          <div className="p-4 rounded-xl border border-rose-500/25 bg-rose-500/10">
            <div className="text-[10px] font-bold text-rose-300 flex items-center gap-1">
              <ShieldAlert className="w-3.5 h-3.5" /> LIVE ATTACK IOCS
            </div>
            <div className="text-xl sm:text-2xl font-extrabold font-mono-ioc text-rose-400 mt-1">
              {snap ? snap.stats.totalIocs : "—"}
            </div>
            <div className="text-[10px] text-rose-300/80 mt-1">
              {snap ? `${snap.stats.sourcesOnline.length} LIVE FEEDS ONLINE` : "SYNCING..."}
            </div>
          </div>

          <div className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/65">
            <div className="text-[10px] font-bold text-[var(--text-secondary)] flex items-center gap-1">
              <Server className="w-3.5 h-3.5" /> BOTNET &amp; C2 SERVERS
            </div>
            <div className="text-xl sm:text-2xl font-extrabold font-mono-ioc text-amber-400 mt-1">
              {snap ? snap.stats.c2Count : "—"}
            </div>
            <div className="text-[10px] text-[var(--text-secondary)] mt-1">
              ACTIVE SCANNERS: {snap?.stats.scannerCount ?? "—"}
            </div>
          </div>

          <div className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/65">
            <div className="text-[10px] font-bold text-[var(--text-secondary)] flex items-center gap-1">
              <Bug className="w-3.5 h-3.5" /> PHISHING &amp; PAYLOADS
            </div>
            <div
              className="text-xl sm:text-2xl font-extrabold font-mono-ioc mt-1"
              style={{ color: "var(--accent)" }}
            >
              {snap
                ? `${snap.stats.phishingCount} · ${snap.stats.malwareHashCount}`
                : "—"}
            </div>
            <div className="text-[10px] text-[var(--text-secondary)] mt-1">
              HOSTS WITH EXPOSED CVES: {snap?.stats.enrichedWithCveCount ?? "—"}
            </div>
          </div>

          <div className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/65">
            <div className="text-[10px] font-bold text-[var(--text-secondary)] flex items-center gap-1">
              <Globe className="w-3.5 h-3.5" /> LAST TELEMETRY SYNC
            </div>
            <div className="text-lg sm:text-xl font-extrabold font-mono-ioc text-emerald-400 mt-1">
              {snap ? new Date(snap.fetchedAt).toLocaleTimeString() : "—"}
            </div>
            <div className="text-[10px] text-[var(--text-secondary)] mt-1 truncate">
              {snap?.stats.topCountries
                .slice(0, 3)
                .map((c) => `${c.country}(${c.count})`)
                .join(" · ") || "MULTI-REGION"}
            </div>
          </div>
        </div>
      </section>

      {error && (
        <div className="p-4 rounded-xl border border-rose-500/30 bg-rose-500/10 text-rose-300 text-xs font-bold">
          {error}
        </div>
      )}

      {/* Filter Bar + Attack IOC Stream Table */}
      <section className="space-y-4">
        <div className="rounded-2xl glass-panel p-5 space-y-4">
          <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-3">
            <div>
              <h2 className="text-sm font-extrabold">
                EXTRACTED ATTACK INDICATORS ({filtered.length})
              </h2>
              <p className="text-[11px] text-[var(--text-secondary)]">
                CLICK ANY ROW TO INSPECT FULL FORENSIC DOSSIER (PORTS, CVES, ASN, ABUSE CONTACT, MALWARE FAMILY &amp; PIVOT)
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <input
                type="text"
                value={searchText}
                onChange={(e) => setSearchText(e.target.value)}
                placeholder="FILTER IP, DOMAIN, CVE, MALWARE, ASN..."
                className="px-3 py-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] font-mono-ioc text-xs"
              />
              <select
                value={typeFilter}
                onChange={(e) =>
                  setTypeFilter(e.target.value as "ALL" | AttackIocType)
                }
                className="px-3 py-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-xs font-bold"
              >
                <option value="ALL">ALL IOC TYPES</option>
                <option value="ip">IP ADDRESS</option>
                <option value="domain">DOMAIN</option>
                <option value="url">URL</option>
                <option value="hash">FILE HASH</option>
              </select>
              <select
                value={catFilter}
                onChange={(e) =>
                  setCatFilter(e.target.value as "ALL" | AttackCategory)
                }
                className="px-3 py-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-xs font-bold"
              >
                <option value="ALL">ALL ATTACK TYPES</option>
                <option value="BOTNET C2">BOTNET C2</option>
                <option value="C2 INFRASTRUCTURE">C2 INFRASTRUCTURE</option>
                <option value="BRUTE FORCE / SCANNER">BRUTE FORCE / SCANNER</option>
                <option value="PHISHING">PHISHING</option>
                <option value="MALWARE PAYLOAD">MALWARE PAYLOAD</option>
              </select>
              <select
                value={countryFilter}
                onChange={(e) => setCountryFilter(e.target.value)}
                className="px-3 py-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-xs font-bold"
              >
                <option value="ALL">ALL COUNTRIES</option>
                {countries.map((c) => (
                  <option key={c} value={c}>
                    {c}
                  </option>
                ))}
              </select>
              <select
                value={sourceFilter}
                onChange={(e) => setSourceFilter(e.target.value)}
                className="px-3 py-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-xs font-bold"
              >
                <option value="ALL">ALL SOURCES</option>
                {sources.map((s) => (
                  <option key={s} value={s}>
                    {s.toUpperCase()}
                  </option>
                ))}
              </select>
              <div className="inline-flex rounded-xl border border-[var(--border-subtle)] overflow-hidden">
                <button
                  type="button"
                  onClick={() => exportIocs("csv")}
                  className="inline-flex items-center gap-1 px-2.5 py-2 bg-[var(--bg-elevated)] hover:bg-[var(--accent-soft)] text-[10px] font-bold border-r border-[var(--border-subtle)] cursor-pointer"
                >
                  <Download className="w-3 h-3" /> CSV
                </button>
                <button
                  type="button"
                  onClick={() => exportIocs("json")}
                  className="px-2.5 py-2 bg-[var(--bg-elevated)] hover:bg-[var(--accent-soft)] text-[10px] font-bold cursor-pointer"
                >
                  JSON
                </button>
              </div>
            </div>
          </div>

          {loading && !snap ? (
            <div className="p-10 text-center space-y-2">
              <Loader2
                className="w-7 h-7 animate-spin mx-auto"
                style={{ color: "var(--accent)" }}
              />
              <p className="text-xs font-bold text-[var(--text-secondary)]">
                COLLECTING &amp; ENRICHING REAL-TIME ATTACK INDICATORS...
              </p>
            </div>
          ) : pagedItems.length === 0 ? (
            <div className="p-8 text-center text-xs font-bold text-[var(--text-secondary)]">
              NO LIVE ATTACK IOCS MATCH YOUR FILTERS.
            </div>
          ) : (
            <div className="overflow-x-auto rounded-xl border border-[var(--border-subtle)]">
              <table className="w-full text-left text-xs">
                <thead className="bg-[var(--bg-elevated)] text-[10px] font-bold text-[var(--text-secondary)]">
                  <tr>
                    <th className="px-3 py-2.5">IOC INDICATOR</th>
                    <th className="px-3 py-2.5">ATTACK &amp; MALWARE</th>
                    <th className="px-3 py-2.5">PORTS / CVES / ASN</th>
                    <th className="px-3 py-2.5">SOURCE &amp; LAST SEEN</th>
                    <th className="px-3 py-2.5 text-right">ACTION</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--border-subtle)]/50">
                  {pagedItems.map((item) => (
                    <tr
                      key={item.id}
                      className="hover:bg-[var(--bg-elevated)]/45 cursor-pointer"
                      onClick={() => setSelected(item)}
                    >
                      <td className="px-3 py-2.5 max-w-xs">
                        <div className="flex items-center gap-1.5">
                          <span
                            className={`text-[9px] font-extrabold px-1.5 py-0.5 rounded uppercase ${
                              item.severity === "CRITICAL"
                                ? "bg-rose-500/20 text-rose-300 border border-rose-500/35"
                                : item.severity === "HIGH"
                                  ? "bg-amber-500/20 text-amber-300 border border-amber-500/35"
                                  : "bg-cyan-500/15 text-cyan-300 border border-cyan-500/35"
                            }`}
                          >
                            {item.iocType}
                          </span>
                          <span className="font-mono-ioc preserve-case font-bold truncate">
                            {item.ioc}
                          </span>
                        </div>
                        {item.hostname && item.hostname !== item.ioc && (
                          <div className="font-mono-ioc preserve-case text-[10px] text-[var(--text-secondary)] truncate mt-0.5">
                            HOST: {item.hostname}
                          </div>
                        )}
                      </td>

                      <td className="px-3 py-2.5">
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span className="text-[10px] font-extrabold text-rose-300">
                            {item.attackType}
                          </span>
                          <span
                            className={`text-[9px] font-bold px-1.5 py-0.5 rounded ${
                              item.status === "ONLINE" || item.status === "ACTIVE"
                                ? "bg-emerald-500/15 text-emerald-300"
                                : "bg-[var(--bg-elevated)] text-[var(--text-secondary)]"
                            }`}
                          >
                            {item.status}
                          </span>
                        </div>
                        <div className="text-[11px] preserve-case text-[var(--text-secondary)] truncate max-w-xs">
                          {item.malwareFamily}
                        </div>
                      </td>

                      <td className="px-3 py-2.5 text-[10px]">
                        <div className="font-mono-ioc preserve-case">
                          {item.country && (
                            <span className="font-bold text-amber-300 mr-1.5">
                              {item.country}
                            </span>
                          )}
                          {item.asn && (
                            <span className="text-[var(--text-secondary)]">
                              {item.asn} {item.asName ? `· ${item.asName}` : ""}
                            </span>
                          )}
                          {!item.country && !item.asn && "—"}
                        </div>
                        <div className="flex flex-wrap gap-1 mt-0.5">
                          {item.ports.slice(0, 4).map((p) => (
                            <span
                              key={p}
                              className="px-1.5 py-0.5 rounded bg-[var(--bg-surface)] border border-[var(--border-subtle)] font-mono-ioc"
                            >
                              :{p}
                            </span>
                          ))}
                          {item.cves.length > 0 && (
                            <span className="px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300 font-bold">
                              {item.cves.length} CVE(S)
                            </span>
                          )}
                        </div>
                      </td>

                      <td className="px-3 py-2.5 whitespace-nowrap">
                        <div className="text-[11px] font-bold">
                          {item.sourceFeed}
                        </div>
                        <div className="text-[10px] font-mono-ioc text-[var(--text-secondary)]">
                          {item.lastSeen || item.firstSeen || "LIVE"}
                        </div>
                      </td>

                      <td
                        className="px-3 py-2.5 text-right whitespace-nowrap"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <Link
                          href={`/?ioc=${encodeURIComponent(item.ioc)}`}
                          style={{ color: "var(--accent)" }}
                          className="inline-flex items-center gap-1 text-[10px] font-extrabold hover:underline"
                        >
                          ENRICH <ArrowUpRight className="w-3 h-3" />
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <PaginationControls
          totalItems={filtered.length}
          page={page}
          pageSize={pageSize}
          pageSizeOptions={[20, 40, 80]}
          onPageChange={(p) => {
            setPage(p);
            window.scrollTo({ top: 0, behavior: "smooth" });
          }}
          onPageSizeChange={(s) => setPageSize(s)}
          label="ATTACK IOCS"
        />
      </section>

      {/* Full Forensic Attack IOC Dossier Modal (Near-Fullscreen Workspace) */}
      {selected && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-2 sm:p-4">
          <div className="w-[96vw] max-w-[1600px] h-[92vh] max-h-[92vh] flex flex-col rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-surface-solid)] shadow-2xl overflow-hidden">
            {/* Sticky Header */}
            <div className="shrink-0 flex items-start justify-between gap-4 border-b border-[var(--border-subtle)] bg-[var(--bg-surface)] px-5 sm:px-8 py-4">
              <div className="space-y-2 min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-[10px] font-extrabold px-2.5 py-0.5 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/35">
                    {selected.attackType} · {selected.severity}
                  </span>
                  <span className="text-[10px] font-bold px-2.5 py-0.5 rounded-full border border-[var(--border-subtle)]">
                    {selected.sourceFeed} · {selected.confidence}% CONFIDENCE
                  </span>
                  <span className="text-[10px] font-bold px-2.5 py-0.5 rounded-full bg-emerald-500/15 text-emerald-300">
                    STATUS: {selected.status}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <h2 className="text-lg sm:text-2xl font-extrabold font-mono-ioc preserve-case break-all">
                    {selected.ioc}
                  </h2>
                  <button
                    type="button"
                    onClick={() => copyValue("ioc", selected.ioc)}
                    className="p-1.5 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-elevated)] shrink-0 cursor-pointer"
                  >
                    {copiedKey === "ioc" ? (
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                    ) : (
                      <Copy className="w-3.5 h-3.5" />
                    )}
                  </button>
                </div>
                <div className="text-xs font-bold text-amber-300">
                  ATTRIBUTION / MALWARE: {selected.malwareFamily}
                </div>
              </div>

              <button
                type="button"
                onClick={() => setSelected(null)}
                className="p-2.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] hover:border-[var(--accent-border)] cursor-pointer shrink-0"
                aria-label="Close IOC dossier"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Scrollable 12-Col Body */}
            <div className="flex-1 overflow-y-auto px-5 sm:px-8 py-6">
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                <div className="lg:col-span-7 space-y-5">
                  <div className="p-5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/55 space-y-2">
                    <div className="text-[11px] font-bold tracking-widest text-[var(--text-secondary)]">
                      FORENSIC ATTACK SUMMARY
                    </div>
                    <p className="text-xs sm:text-sm preserve-case leading-relaxed">
                      {selected.summary}
                    </p>
                  </div>

                  {(selected.ports.length > 0 ||
                    selected.cves.length > 0 ||
                    selected.cpes.length > 0) && (
                    <div className="p-5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/45 space-y-4 text-xs">
                      {selected.ports.length > 0 && (
                        <div>
                          <div className="text-[11px] font-bold text-[var(--text-secondary)] mb-1.5">
                            OPEN EXPOSED PORTS ({selected.ports.length})
                          </div>
                          <div className="flex flex-wrap gap-1.5">
                            {selected.ports.map((p) => (
                              <span
                                key={p}
                                className="px-2.5 py-1 rounded bg-[var(--bg-surface)] border border-[var(--border-subtle)] font-mono-ioc"
                              >
                                {p}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}

                      {selected.cves.length > 0 && (
                        <div>
                          <div className="text-[11px] font-bold text-rose-300 mb-1.5">
                            CORRELATED VULNERABILITIES / CVES ON HOST ({selected.cves.length})
                          </div>
                          <div className="flex flex-wrap gap-1.5">
                            {selected.cves.map((cve) => (
                              <Link
                                key={cve}
                                href={`/cve?tab=search&q=${encodeURIComponent(cve)}`}
                                className="px-2.5 py-1 rounded bg-rose-500/20 text-rose-300 border border-rose-500/35 font-mono-ioc hover:underline"
                              >
                                {cve} ↗
                              </Link>
                            ))}
                          </div>
                        </div>
                      )}

                      {selected.cpes.length > 0 && (
                        <div>
                          <div className="text-[11px] font-bold text-[var(--text-secondary)] mb-1.5">
                            DETECTED SERVICE FINGERPRINTS (CPE)
                          </div>
                          <div className="flex flex-wrap gap-1.5">
                            {selected.cpes.map((cpe) => (
                              <span
                                key={cpe}
                                className="px-2.5 py-1 rounded bg-[var(--bg-surface)] border border-[var(--border-subtle)] font-mono-ioc text-[11px] preserve-case"
                              >
                                {cpe}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>

                <div className="lg:col-span-5 space-y-5">
                  <div className="p-5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/45 space-y-2 text-xs sm:text-sm">
                    <div className="text-[11px] font-bold tracking-widest text-[var(--text-secondary)]">
                      NETWORK &amp; INFRASTRUCTURE TELEMETRY
                    </div>
                    <div>
                      <strong>HOSTNAME:</strong>{" "}
                      <span className="font-mono-ioc preserve-case">
                        {selected.hostname || "—"}
                      </span>
                    </div>
                    <div>
                      <strong>COUNTRY / ASN:</strong> {selected.country || "—"} ·{" "}
                      {selected.asn || "—"} {selected.asName || ""}
                    </div>
                    <div>
                      <strong>NETWORK CIDR:</strong>{" "}
                      <span className="font-mono-ioc">{selected.network || "—"}</span>
                    </div>
                    <div>
                      <strong>ABUSE CONTACT:</strong>{" "}
                      <span className="font-mono-ioc preserve-case">
                        {selected.abuseContact || "—"}
                      </span>
                    </div>
                  </div>

                  <div className="p-5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/45 space-y-2 text-xs sm:text-sm">
                    <div className="text-[11px] font-bold tracking-widest text-[var(--text-secondary)]">
                      TIMESTAMPS &amp; ATTACK METRICS
                    </div>
                    <div>
                      <strong>FIRST SEEN:</strong>{" "}
                      <span className="font-mono-ioc">{selected.firstSeen || "—"}</span>
                    </div>
                    <div>
                      <strong>LAST SEEN:</strong>{" "}
                      <span className="font-mono-ioc">{selected.lastSeen || "—"}</span>
                    </div>
                    <div>
                      <strong>ATTACK HITS:</strong>{" "}
                      {selected.attackCount !== null
                        ? selected.attackCount.toLocaleString()
                        : "—"}
                    </div>
                    <div>
                      <strong>SENSOR REPORTS:</strong>{" "}
                      {selected.reportCount !== null
                        ? selected.reportCount.toLocaleString()
                        : "—"}
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Sticky Footer */}
            <div className="shrink-0 flex flex-wrap items-center justify-between gap-3 border-t border-[var(--border-subtle)] bg-[var(--bg-surface)] px-5 sm:px-8 py-3.5">
              <Link
                href={`/?ioc=${encodeURIComponent(selected.ioc)}`}
                style={{ backgroundColor: "var(--accent)" }}
                className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl text-white text-xs font-bold"
              >
                INVESTIGATE IN FULL IOC LOOKUP
                <ArrowUpRight className="w-3.5 h-3.5" />
              </Link>

              <div className="flex items-center gap-2">
                {selected.referenceUrl && (
                  <a
                    href={selected.referenceUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1 px-3.5 py-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-xs font-bold"
                  >
                    OPEN SOURCE TELEMETRY <ExternalLink className="w-3.5 h-3.5" />
                  </a>
                )}
                <button
                  type="button"
                  onClick={() => setSelected(null)}
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
