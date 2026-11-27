"use client";

import React, { useMemo, useRef, useState } from "react";
import {
  Play,
  Pause,
  Square,
  Download,
  Loader2,
  CheckCircle2,
  AlertCircle,
  Clock,
  FileText,
} from "lucide-react";
import { getByokHeaders } from "@/lib/client-byok";
import type { EnrichmentReport } from "@/lib/enrich";
import type { IocType } from "@/lib/providers/catalog";
import { VerdictBadge } from "@/components/VerdictBadge";
import { ReportView } from "@/components/ReportView";

interface QueuedItem {
  id: string;
  normalized: string;
  type: IocType;
  status: "pending" | "running" | "done" | "error";
  report?: EnrichmentReport;
  error?: string;
}

const CONCURRENCY = 3;

export default function BulkLookupPage() {
  const [rawInput, setRawInput] = useState("");
  const [queue, setQueue] = useState<QueuedItem[]>([]);
  const [parseStats, setParseStats] = useState<{
    invalidCount: number;
    duplicatesRemoved: number;
  } | null>(null);
  const [running, setRunning] = useState(false);
  const [paused, setPaused] = useState(false);
  const [verdictFilter, setVerdictFilter] = useState<string>("all");
  const [selectedReport, setSelectedReport] = useState<EnrichmentReport | null>(
    null,
  );
  const [forceRefresh, setForceRefresh] = useState(false);

  const pauseRef = useRef(false);
  const cancelRef = useRef(false);

  const parseAndStart = async () => {
    if (!rawInput.trim()) return;
    setSelectedReport(null);
    const res = await fetch("/api/bulk/parse", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: rawInput, maxItems: 100 }),
    });
    const data = await res.json();
    if (!res.ok) return;

    const items: QueuedItem[] = (data.iocs || []).map(
      (i: { normalized: string; type: IocType }, idx: number) => ({
        id: `${idx}-${i.normalized}`,
        normalized: i.normalized,
        type: i.type,
        status: "pending",
      }),
    );

    setParseStats({
      invalidCount: (data.invalidTokens || []).length,
      duplicatesRemoved: data.duplicatesRemoved || 0,
    });
    setQueue(items);

    if (items.length > 0) {
      runQueue(items);
    }
  };

  const runQueue = async (initialItems: QueuedItem[]) => {
    setRunning(true);
    setPaused(false);
    pauseRef.current = false;
    cancelRef.current = false;

    let cursor = 0;

    const worker = async () => {
      while (cursor < initialItems.length) {
        if (cancelRef.current) return;
        while (pauseRef.current) {
          if (cancelRef.current) return;
          await new Promise((r) => setTimeout(r, 250));
        }

        const idx = cursor++;
        if (idx >= initialItems.length) return;
        const item = initialItems[idx];

        setQueue((prev) =>
          prev.map((q) => (q.id === item.id ? { ...q, status: "running" } : q)),
        );

        try {
          const res = await fetch("/api/lookup", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              ...getByokHeaders(),
            },
            body: JSON.stringify({
              ioc: item.normalized,
              forceRefresh,
            }),
          });
          const data = await res.json();
          if (!res.ok) {
            setQueue((prev) =>
              prev.map((q) =>
                q.id === item.id
                  ? { ...q, status: "error", error: data.error || "FAILED" }
                  : q,
              ),
            );
          } else {
            setQueue((prev) =>
              prev.map((q) =>
                q.id === item.id ? { ...q, status: "done", report: data } : q,
              ),
            );
          }
        } catch {
          setQueue((prev) =>
            prev.map((q) =>
              q.id === item.id
                ? { ...q, status: "error", error: "NETWORK ERROR" }
                : q,
            ),
          );
        }
      }
    };

    await Promise.all(
      Array.from({ length: Math.min(CONCURRENCY, initialItems.length) }, () =>
        worker(),
      ),
    );
    setRunning(false);
  };

  const togglePause = () => {
    pauseRef.current = !pauseRef.current;
    setPaused(pauseRef.current);
  };

  const cancelRun = () => {
    cancelRef.current = true;
    pauseRef.current = false;
    setPaused(false);
    setRunning(false);
  };

  const completedReports = useMemo(
    () => queue.filter((q) => q.report).map((q) => q.report!),
    [queue],
  );

  const doneCount = queue.filter(
    (q) => q.status === "done" || q.status === "error",
  ).length;
  const progressPct =
    queue.length > 0 ? Math.round((doneCount / queue.length) * 100) : 0;

  const filteredQueue = useMemo(() => {
    if (verdictFilter === "all") return queue;
    return queue.filter((q) => q.report?.verdict === verdictFilter);
  }, [queue, verdictFilter]);

  const handleBulkExport = async (format: "json" | "csv" | "stix") => {
    if (completedReports.length === 0) return;
    const res = await fetch("/api/export", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ format, reports: completedReports }),
    });
    if (!res.ok) return;
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `eyesight-bulk-${format}.${format === "csv" ? "csv" : "json"}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6 w-full">
      <section className="rounded-2xl glass-panel p-5 sm:p-6 space-y-4">
        <div>
          <h1 className="text-xl font-extrabold tracking-tight">
            BULK / MULTI-IOC ENRICHMENT
          </h1>
          <p className="text-xs sm:text-sm text-[var(--text-secondary)] mt-1">
            PASTE IPS, DOMAINS, URLS, FILE HASHES, OR LOG SNIPPETS. CLIENT-ORCHESTRATED CHUNKS OF {CONCURRENCY} RESPECT API RATE LIMITS ON VERCEL & RENDER.
          </p>
        </div>

        <textarea
          rows={6}
          value={rawInput}
          onChange={(e) => setRawInput(e.target.value)}
          placeholder={`1.1.1.1\n8.8.8.8\nhxxps[:]//example[.]com/test\n44d88612fea8a8f36de82e1278abb02f`}
          className="w-full p-3.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] font-mono-ioc text-xs focus:outline-none focus:border-[var(--accent)]"
        />

        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              disabled={running || !rawInput.trim()}
              onClick={parseAndStart}
              style={{ backgroundColor: "var(--accent)" }}
              className="w-full sm:w-auto inline-flex items-center justify-center gap-1.5 px-4 py-2.5 rounded-xl hover:opacity-90 disabled:opacity-50 text-white text-xs font-bold transition cursor-pointer"
            >
              <Play className="w-3.5 h-3.5" />
              PARSE & ENRICH QUEUE
            </button>

            <button
              type="button"
              disabled={running}
              onClick={() =>
                setRawInput(
                  "1.1.1.1\n8.8.8.8\nexample.com\n44d88612fea8a8f36de82e1278abb02f",
                )
              }
              className="w-full sm:w-auto inline-flex items-center justify-center gap-1.5 px-3.5 py-2.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-xs font-bold hover:border-[var(--accent-border)] cursor-pointer"
            >
              <FileText className="w-3.5 h-3.5" />
              LOAD SAMPLE BATCH
            </button>

            <label className="inline-flex items-center gap-1.5 text-[11px] font-semibold text-[var(--text-secondary)] sm:ml-2 cursor-pointer">
              <input
                type="checkbox"
                checked={forceRefresh}
                onChange={(e) => setForceRefresh(e.target.checked)}
                style={{ accentColor: "var(--accent)" }}
              />
              FORCE REFRESH
            </label>
          </div>

          {running && (
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={togglePause}
                className="inline-flex items-center gap-1 px-3 py-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-xs font-bold cursor-pointer"
              >
                {paused ? (
                  <>
                    <Play className="w-3.5 h-3.5 text-emerald-400" /> RESUME
                  </>
                ) : (
                  <>
                    <Pause className="w-3.5 h-3.5 text-amber-400" /> PAUSE
                  </>
                )}
              </button>
              <button
                type="button"
                onClick={cancelRun}
                className="inline-flex items-center gap-1 px-3 py-2 rounded-xl border border-rose-500/30 bg-rose-500/10 text-rose-400 text-xs font-bold cursor-pointer"
              >
                <Square className="w-3.5 h-3.5" /> CANCEL
              </button>
            </div>
          )}
        </div>

        {parseStats && (
          <div className="text-[11px] font-semibold text-[var(--text-secondary)] flex flex-wrap gap-4">
            <span>
              QUEUED:{" "}
              <strong className="text-[var(--text-primary)]">{queue.length}</strong>{" "}
              UNIQUE IOCS
            </span>
            <span>DUPLICATES REMOVED: {parseStats.duplicatesRemoved}</span>
            <span>INVALID TOKENS IGNORED: {parseStats.invalidCount}</span>
          </div>
        )}
      </section>

      {queue.length > 0 && (
        <section className="rounded-2xl glass-panel overflow-hidden">
          <div className="p-4 border-b border-[var(--border-subtle)] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-center gap-3 flex-1">
              <div className="w-full sm:max-w-xs h-2 rounded-full bg-[var(--bg-elevated)] overflow-hidden">
                <div
                  className="h-full transition-all duration-300"
                  style={{
                    width: `${progressPct}%`,
                    backgroundColor: "var(--accent)",
                  }}
                />
              </div>
              <span className="text-xs font-mono-ioc font-bold text-[var(--text-secondary)] shrink-0">
                {doneCount}/{queue.length} ({progressPct}%)
              </span>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <select
                value={verdictFilter}
                onChange={(e) => setVerdictFilter(e.target.value)}
                className="px-3 py-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-xs font-bold"
              >
                <option value="all">ALL VERDICTS</option>
                <option value="malicious">MALICIOUS</option>
                <option value="suspicious">SUSPICIOUS</option>
                <option value="clean">CLEAN</option>
                <option value="unknown">UNKNOWN</option>
              </select>

              <div className="inline-flex rounded-xl border border-[var(--border-subtle)] overflow-hidden">
                <button
                  type="button"
                  disabled={completedReports.length === 0}
                  onClick={() => handleBulkExport("json")}
                  className="inline-flex items-center gap-1 px-3 py-2 bg-[var(--bg-elevated)] hover:bg-[var(--accent-soft)] text-[11px] font-bold disabled:opacity-40 border-r border-[var(--border-subtle)] cursor-pointer"
                >
                  <Download className="w-3 h-3" /> JSON
                </button>
                <button
                  type="button"
                  disabled={completedReports.length === 0}
                  onClick={() => handleBulkExport("csv")}
                  className="px-3 py-2 bg-[var(--bg-elevated)] hover:bg-[var(--accent-soft)] text-[11px] font-bold disabled:opacity-40 border-r border-[var(--border-subtle)] cursor-pointer"
                >
                  CSV
                </button>
                <button
                  type="button"
                  disabled={completedReports.length === 0}
                  onClick={() => handleBulkExport("stix")}
                  className="px-3 py-2 bg-[var(--bg-elevated)] hover:bg-[var(--accent-soft)] text-[11px] font-bold disabled:opacity-40 cursor-pointer"
                >
                  STIX 2.1
                </button>
              </div>
            </div>
          </div>

          {/* Mobile Adaptive Cards (< md) */}
          <div className="md:hidden divide-y divide-[var(--border-subtle)]">
            {filteredQueue.map((item) => (
              <div
                key={item.id}
                onClick={() => item.report && setSelectedReport(item.report)}
                className="p-4 space-y-2 active:bg-[var(--bg-elevated)]"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono-ioc preserve-case text-xs font-bold truncate">
                    {item.normalized}
                  </span>
                  {item.status === "running" && (
                    <Loader2
                      className="w-4 h-4 animate-spin shrink-0"
                      style={{ color: "var(--accent)" }}
                    />
                  )}
                  {item.status === "done" && (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                  )}
                  {item.status === "error" && (
                    <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
                  )}
                  {item.status === "pending" && (
                    <Clock className="w-4 h-4 text-slate-500 shrink-0" />
                  )}
                </div>
                <div className="flex items-center justify-between text-[11px]">
                  <span
                    className="font-bold"
                    style={{ color: "var(--accent)" }}
                  >
                    {item.type}
                  </span>
                  {item.report ? (
                    <div className="flex items-center gap-2">
                      <span className="font-mono-ioc font-bold">
                        SCORE: {item.report.compositeScore ?? "—"}
                      </span>
                      <VerdictBadge verdict={item.report.verdict} />
                    </div>
                  ) : (
                    <span className="text-[var(--text-secondary)]">
                      {item.error || "QUEUED"}
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>

          {/* Desktop Table (>= md) */}
          <div className="hidden md:block overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-[var(--bg-elevated)]/70 text-[var(--text-secondary)] text-[10px] font-bold tracking-wider">
                <tr>
                  <th className="px-4 py-3">STATUS</th>
                  <th className="px-4 py-3">IOC</th>
                  <th className="px-4 py-3">TYPE</th>
                  <th className="px-4 py-3">SCORE</th>
                  <th className="px-4 py-3">VERDICT</th>
                  <th className="px-4 py-3">COVERAGE</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border-subtle)]">
                {filteredQueue.map((item) => (
                  <tr
                    key={item.id}
                    onClick={() => item.report && setSelectedReport(item.report)}
                    className={`transition ${
                      item.report
                        ? "hover:bg-[var(--bg-elevated)]/60 cursor-pointer"
                        : ""
                    }`}
                  >
                    <td className="px-4 py-3">
                      {item.status === "running" && (
                        <Loader2
                          className="w-4 h-4 animate-spin"
                          style={{ color: "var(--accent)" }}
                        />
                      )}
                      {item.status === "done" && (
                        <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                      )}
                      {item.status === "error" && (
                        <span title={item.error}>
                          <AlertCircle className="w-4 h-4 text-rose-400" />
                        </span>
                      )}
                      {item.status === "pending" && (
                        <Clock className="w-4 h-4 text-slate-500" />
                      )}
                    </td>
                    <td className="px-4 py-3 font-mono-ioc preserve-case font-semibold max-w-md truncate">
                      {item.normalized}
                    </td>
                    <td
                      className="px-4 py-3 text-[10px] font-bold"
                      style={{ color: "var(--accent)" }}
                    >
                      {item.type}
                    </td>
                    <td className="px-4 py-3 font-mono-ioc font-bold">
                      {item.report ? (item.report.compositeScore ?? "—") : "—"}
                    </td>
                    <td className="px-4 py-3">
                      {item.report ? (
                        <VerdictBadge verdict={item.report.verdict} />
                      ) : item.error ? (
                        <span className="text-rose-400 font-semibold">
                          {item.error}
                        </span>
                      ) : (
                        <span className="text-[var(--text-secondary)]">QUEUED</span>
                      )}
                    </td>
                    <td className="px-4 py-3 font-semibold text-[var(--text-secondary)]">
                      {item.report
                        ? `${item.report.coverageCount}/${item.report.totalApplicable}`
                        : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {selectedReport && (
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <h2 className="text-xs font-bold tracking-wider">
              SELECTED IOC INSPECTION
            </h2>
            <button
              type="button"
              onClick={() => setSelectedReport(null)}
              className="text-xs font-bold text-[var(--text-secondary)] hover:text-[var(--text-primary)] cursor-pointer"
            >
              CLOSE INSPECTOR
            </button>
          </div>
          <ReportView report={selectedReport} />
        </div>
      )}
    </div>
  );
}
