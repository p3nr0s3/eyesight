"use client";

import React, { useCallback, useEffect, useState } from "react";
import { Bookmark, Plus, Trash2, ExternalLink, Loader2 } from "lucide-react";

interface WatchlistToolRow {
  id: string;
  name: string;
  category: string;
  status: "MONITORING" | "PLANNED" | "INTEGRATED";
  url: string | null;
  notes: string | null;
}

export function WatchlistSection() {
  const [loading, setLoading] = useState(true);
  const [watchlist, setWatchlist] = useState<WatchlistToolRow[]>([]);
  const [watchName, setWatchName] = useState("");
  const [watchCategory, setWatchCategory] = useState("THREAT INTEL");
  const [watchStatus, setWatchStatus] = useState<
    "MONITORING" | "PLANNED" | "INTEGRATED"
  >("MONITORING");
  const [watchUrl, setWatchUrl] = useState("");
  const [watchNotes, setWatchNotes] = useState("");
  const [message, setMessage] = useState<{ type: "ok" | "err"; text: string } | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/watchlist", { cache: "no-store" });
      if (res.ok) {
        const data = await res.json();
        setWatchlist(data.items || []);
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    setMessage(null);
    const res = await fetch("/api/watchlist", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: watchName,
        category: watchCategory,
        status: watchStatus,
        url: watchUrl || null,
        notes: watchNotes || null,
      }),
    });
    const data = await res.json();
    if (!res.ok) {
      setMessage({ type: "err", text: data.error || "FAILED TO ADD TOOL" });
    } else {
      setWatchName("");
      setWatchUrl("");
      setWatchNotes("");
      setMessage({ type: "ok", text: "TOOL ADDED TO WATCHLIST." });
      load();
    }
  };

  const handleStatusChange = async (
    id: string,
    status: "MONITORING" | "PLANNED" | "INTEGRATED",
  ) => {
    const res = await fetch("/api/watchlist", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id, status }),
    });
    if (res.ok) load();
  };

  const handleDelete = async (id: string) => {
    const res = await fetch(`/api/watchlist?id=${encodeURIComponent(id)}`, {
      method: "DELETE",
    });
    if (res.ok) load();
  };

  if (loading) {
    return (
      <div className="p-10 text-center text-xs font-bold text-[var(--text-secondary)] flex items-center justify-center gap-2">
        <Loader2 className="w-4 h-4 animate-spin" /> LOADING TOOLS WATCHLIST...
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {message && (
        <div
          className={`p-3.5 rounded-xl border text-xs font-bold ${
            message.type === "ok"
              ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
              : "border-rose-500/30 bg-rose-500/10 text-rose-400"
          }`}
        >
          {message.text}
        </div>
      )}

      <section className="rounded-2xl glass-panel p-4 sm:p-6 space-y-5">
        <div className="flex items-start sm:items-center gap-2">
          <Bookmark
            className="w-4 h-4 shrink-0 mt-0.5 sm:mt-0"
            style={{ color: "var(--accent)" }}
          />
          <div>
            <h2 className="text-sm sm:text-base font-bold">
              SECURITY TOOLS WATCHLIST ({watchlist.length})
            </h2>
            <p className="text-[11px] text-[var(--text-secondary)]">
              TRACK THREAT INTEL, OSINT, AND SECOPS TOOLS MONITORED OR PLANNED FOR INTEGRATION.
            </p>
          </div>
        </div>

        <form
          onSubmit={handleAdd}
          className="grid grid-cols-1 sm:grid-cols-12 gap-2.5 p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/50"
        >
          <input
            type="text"
            required
            value={watchName}
            onChange={(e) => setWatchName(e.target.value)}
            placeholder="TOOL NAME (E.G. VELOCIRAPTOR)"
            className="sm:col-span-3 px-3 py-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-surface)] text-xs"
          />
          <input
            type="text"
            required
            value={watchCategory}
            onChange={(e) => setWatchCategory(e.target.value)}
            placeholder="CATEGORY (DFIR / OSINT)"
            className="sm:col-span-2 px-3 py-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-surface)] text-xs"
          />
          <select
            value={watchStatus}
            onChange={(e) =>
              setWatchStatus(
                e.target.value as "MONITORING" | "PLANNED" | "INTEGRATED",
              )
            }
            className="sm:col-span-2 px-3 py-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-surface)] text-xs font-bold"
          >
            <option value="MONITORING">MONITORING</option>
            <option value="PLANNED">PLANNED</option>
            <option value="INTEGRATED">INTEGRATED</option>
          </select>
          <input
            type="url"
            value={watchUrl}
            onChange={(e) => setWatchUrl(e.target.value)}
            placeholder="https://tool-homepage.org"
            className="sm:col-span-3 px-3 py-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-surface)] font-mono-ioc text-xs"
          />
          <button
            type="submit"
            style={{ backgroundColor: "var(--accent)" }}
            className="sm:col-span-2 inline-flex items-center justify-center gap-1 px-3 py-2 rounded-xl text-white text-xs font-bold cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" /> ADD TOOL
          </button>
          <input
            type="text"
            value={watchNotes}
            onChange={(e) => setWatchNotes(e.target.value)}
            placeholder="NOTES / REASON FOR WATCHING (OPTIONAL)..."
            className="sm:col-span-12 px-3 py-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-surface)] text-xs"
          />
        </form>

        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
          {watchlist.map((tool) => (
            <div
              key={tool.id}
              className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/55 flex flex-col justify-between gap-3"
            >
              <div className="space-y-2">
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <div className="text-xs font-extrabold">{tool.name}</div>
                    <span
                      className="inline-block mt-1 text-[9px] font-bold px-2 py-0.5 rounded-full"
                      style={{
                        backgroundColor: "var(--accent-soft)",
                        color: "var(--accent)",
                      }}
                    >
                      {tool.category}
                    </span>
                  </div>
                  <button
                    type="button"
                    onClick={() => handleDelete(tool.id)}
                    className="p-1 rounded-lg text-rose-400 hover:bg-rose-500/15 cursor-pointer"
                    title="REMOVE FROM WATCHLIST"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>

                {tool.notes && (
                  <p className="text-[11px] text-[var(--text-secondary)] preserve-case leading-relaxed">
                    {tool.notes}
                  </p>
                )}
              </div>

              <div className="flex items-center justify-between gap-2 pt-2.5 border-t border-[var(--border-subtle)]">
                <select
                  value={tool.status}
                  onChange={(e) =>
                    handleStatusChange(
                      tool.id,
                      e.target.value as "MONITORING" | "PLANNED" | "INTEGRATED",
                    )
                  }
                  className="px-2.5 py-1 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-surface)] text-[10px] font-bold"
                >
                  <option value="MONITORING">MONITORING</option>
                  <option value="PLANNED">PLANNED</option>
                  <option value="INTEGRATED">INTEGRATED</option>
                </select>

                {tool.url && (
                  <a
                    href={tool.url}
                    target="_blank"
                    rel="noreferrer"
                    style={{ color: "var(--accent)" }}
                    className="inline-flex items-center gap-1 text-[10px] font-bold hover:underline"
                  >
                    SITE <ExternalLink className="w-3 h-3" />
                  </a>
                )}
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
