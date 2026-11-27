"use client";

import React, { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { Search, Trash2, ArrowUpRight, Loader2 } from "lucide-react";
import { VerdictBadge } from "@/components/VerdictBadge";
import type { ThreatVerdict } from "@/lib/providers/types";

interface HistoryItem {
  id: string;
  iocValue: string;
  iocType: string;
  compositeScore: number | null;
  verdict: ThreatVerdict;
  coverageCount: number;
  totalApplicable: number;
  createdAt: string;
}

export default function HistoryPage() {
  const [items, setItems] = useState<HistoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [q, setQ] = useState("");
  const [type, setType] = useState("all");
  const [verdict, setVerdict] = useState("all");

  const fetchHistory = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (q.trim()) params.set("q", q.trim());
      if (type !== "all") params.set("type", type);
      if (verdict !== "all") params.set("verdict", verdict);
      const res = await fetch(`/api/history?${params.toString()}`, {
        cache: "no-store",
      });
      if (res.ok) {
        const data = await res.json();
        setItems(data.items || []);
      }
    } finally {
      setLoading(false);
    }
  }, [q, type, verdict]);

  useEffect(() => {
    fetchHistory();
  }, [fetchHistory]);

  const handleClear = async () => {
    const res = await fetch("/api/history", { method: "DELETE" });
    if (res.ok) {
      fetchHistory();
    }
  };

  return (
    <div className="space-y-6 w-full">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-extrabold tracking-tight">LOOKUP HISTORY</h1>
          <p className="text-xs sm:text-sm text-[var(--text-secondary)]">
            SEARCH PAST IOC ENRICHMENTS ACROSS THIS WORKSPACE. CLICK ANY INDICATOR TO INSPECT OR REFRESH.
          </p>
        </div>
        <button
          type="button"
          onClick={handleClear}
          className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl border border-rose-500/30 bg-rose-500/10 text-rose-400 hover:bg-rose-500/20 text-xs font-bold cursor-pointer"
        >
          <Trash2 className="w-3.5 h-3.5" />
          CLEAR HISTORY
        </button>
      </div>

      {/* Filters */}
      <div className="rounded-2xl glass-panel p-4 flex flex-col sm:flex-row sm:items-center gap-3">
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-[var(--text-secondary)] absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="FILTER BY IP, DOMAIN, URL, OR HASH..."
            className="w-full pl-9 pr-3 py-2.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] font-mono-ioc text-xs focus:outline-none focus:border-[var(--accent)]"
          />
        </div>

        <div className="grid grid-cols-2 sm:flex gap-2">
          <select
            value={type}
            onChange={(e) => setType(e.target.value)}
            className="px-3 py-2.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-xs font-bold"
          >
            <option value="all">ALL TYPES</option>
            <option value="ip">IP</option>
            <option value="domain">DOMAIN</option>
            <option value="url">URL</option>
            <option value="hash">HASH</option>
          </select>

          <select
            value={verdict}
            onChange={(e) => setVerdict(e.target.value)}
            className="px-3 py-2.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-xs font-bold"
          >
            <option value="all">ALL VERDICTS</option>
            <option value="malicious">MALICIOUS</option>
            <option value="suspicious">SUSPICIOUS</option>
            <option value="clean">CLEAN</option>
            <option value="unknown">UNKNOWN</option>
          </select>
        </div>
      </div>

      {/* Results */}
      <div className="rounded-2xl glass-panel overflow-hidden">
        {loading ? (
          <div className="p-10 text-center text-xs font-bold text-[var(--text-secondary)] flex items-center justify-center gap-2">
            <Loader2 className="w-4 h-4 animate-spin" /> LOADING HISTORY...
          </div>
        ) : items.length === 0 ? (
          <div className="p-10 text-center text-xs font-bold text-[var(--text-secondary)]">
            NO LOOKUP HISTORY FOUND. TRY INVESTIGATING AN IOC FIRST.
          </div>
        ) : (
          <>
            {/* Mobile Cards (< md) */}
            <div className="md:hidden divide-y divide-[var(--border-subtle)]">
              {items.map((item) => (
                <Link
                  key={item.id}
                  href={`/?ioc=${encodeURIComponent(item.iocValue)}`}
                  className="block p-4 space-y-2 hover:bg-[var(--bg-elevated)]/50 transition"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono-ioc preserve-case text-xs font-bold truncate">
                      {item.iocValue}
                    </span>
                    <VerdictBadge verdict={item.verdict} />
                  </div>
                  <div className="flex items-center justify-between text-[11px] text-[var(--text-secondary)]">
                    <span>
                      <strong style={{ color: "var(--accent)" }}>
                        {item.iocType}
                      </strong>{" "}
                      • SCORE {item.compositeScore ?? "—"} • {item.coverageCount}/
                      {item.totalApplicable} SOURCES
                    </span>
                    <ArrowUpRight
                      className="w-3.5 h-3.5 shrink-0"
                      style={{ color: "var(--accent)" }}
                    />
                  </div>
                </Link>
              ))}
            </div>

            {/* Desktop Table (>= md) */}
            <div className="hidden md:block overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-[var(--bg-elevated)]/70 text-[var(--text-secondary)] text-[10px] font-bold tracking-wider">
                  <tr>
                    <th className="px-4 py-3">IOC</th>
                    <th className="px-4 py-3">TYPE</th>
                    <th className="px-4 py-3">SCORE</th>
                    <th className="px-4 py-3">VERDICT</th>
                    <th className="px-4 py-3">COVERAGE</th>
                    <th className="px-4 py-3">TIMESTAMP</th>
                    <th className="px-4 py-3 text-right">ACTION</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--border-subtle)]">
                  {items.map((item) => (
                    <tr
                      key={item.id}
                      className="hover:bg-[var(--bg-elevated)]/50 transition"
                    >
                      <td className="px-4 py-3 font-mono-ioc preserve-case font-semibold max-w-md truncate">
                        {item.iocValue}
                      </td>
                      <td
                        className="px-4 py-3 text-[10px] font-bold"
                        style={{ color: "var(--accent)" }}
                      >
                        {item.iocType}
                      </td>
                      <td className="px-4 py-3 font-mono-ioc font-bold">
                        {item.compositeScore ?? "—"}
                      </td>
                      <td className="px-4 py-3">
                        <VerdictBadge verdict={item.verdict} />
                      </td>
                      <td className="px-4 py-3 font-semibold text-[var(--text-secondary)]">
                        {item.coverageCount}/{item.totalApplicable}
                      </td>
                      <td className="px-4 py-3 text-[var(--text-secondary)]">
                        {new Date(item.createdAt).toLocaleString()}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <Link
                          href={`/?ioc=${encodeURIComponent(item.iocValue)}`}
                          style={{ color: "var(--accent)" }}
                          className="inline-flex items-center gap-1 hover:underline font-bold"
                        >
                          INSPECT <ArrowUpRight className="w-3.5 h-3.5" />
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
