"use client";

import React, { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { Rss, Plus, Trash2, ExternalLink, Check, Sparkles, Loader2 } from "lucide-react";
import { useAuth } from "@/components/AppShell";
import { POPULAR_RSS_FEEDS, type PopularRssPreset } from "@/lib/popular-rss";

interface RssFeedRow {
  id: string;
  name: string;
  url: string;
  category: string;
  enabled: boolean;
}

export function RssFeedsSection() {
  const auth = useAuth();
  const [loading, setLoading] = useState(true);
  const [canManage, setCanManage] = useState(false);
  const [rssFeeds, setRssFeeds] = useState<RssFeedRow[]>([]);
  const [feedName, setFeedName] = useState("");
  const [feedUrl, setFeedUrl] = useState("");
  const [feedCategory, setFeedCategory] = useState("THREAT NEWS");
  const [integratingId, setIntegratingId] = useState<string | null>(null);
  const [message, setMessage] = useState<{ type: "ok" | "err"; text: string } | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/rss-feeds", { cache: "no-store" });
      if (res.ok) {
        const data = await res.json();
        setCanManage(Boolean(data.canManage));
        setRssFeeds(data.items || []);
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load, auth.user?.id]);

  const integratedUrls = useMemo(
    () => new Set(rssFeeds.map((f) => f.url.trim().toLowerCase())),
    [rssFeeds],
  );

  const handleAddRssFeed = async (e: React.FormEvent) => {
    e.preventDefault();
    setMessage(null);
    const res = await fetch("/api/rss-feeds", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: feedName,
        url: feedUrl,
        category: feedCategory,
      }),
    });
    const data = await res.json();
    if (!res.ok) {
      setMessage({ type: "err", text: data.error || "FAILED TO ADD RSS FEED" });
    } else {
      setFeedName("");
      setFeedUrl("");
      setMessage({ type: "ok", text: "RSS FEED INTEGRATED AND SYNCED." });
      load();
    }
  };

  const handleIntegratePreset = async (preset: PopularRssPreset) => {
    setMessage(null);
    setIntegratingId(preset.id);
    try {
      const res = await fetch("/api/rss-feeds", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: preset.name,
          url: preset.url,
          category: preset.category,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setMessage({ type: "err", text: data.error || "FAILED TO INTEGRATE FEED" });
      } else {
        setMessage({
          type: "ok",
          text: `${preset.name.toUpperCase()} INTEGRATED INTO CYBERSECURITY NEWS.`,
        });
        await load();
      }
    } finally {
      setIntegratingId(null);
    }
  };

  const handleToggleRssFeed = async (id: string, enabled: boolean) => {
    const res = await fetch("/api/rss-feeds", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id, enabled }),
    });
    if (res.ok) load();
  };

  const handleDeleteRssFeed = async (id: string) => {
    const res = await fetch(`/api/rss-feeds?id=${encodeURIComponent(id)}`, {
      method: "DELETE",
    });
    if (res.ok) load();
  };

  if (loading) {
    return (
      <div className="p-10 text-center text-xs font-bold text-[var(--text-secondary)] flex items-center justify-center gap-2">
        <Loader2 className="w-4 h-4 animate-spin" /> LOADING RSS FEEDS...
      </div>
    );
  }

  return (
    <div className="space-y-6">
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

      {/* Popular 1-Click Cybersecurity RSS Feeds Directory */}
      <section className="rounded-2xl glass-panel p-4 sm:p-6 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-start sm:items-center gap-2">
            <Sparkles
              className="w-4 h-4 shrink-0 mt-0.5 sm:mt-0"
              style={{ color: "var(--accent)" }}
            />
            <div>
              <h2 className="text-sm sm:text-base font-bold">
                POPULAR CYBERSECURITY RSS FEEDS (1-CLICK INTEGRATE)
              </h2>
              <p className="text-[11px] text-[var(--text-secondary)]">
                INSTANTLY INTEGRATE TRUSTED THREAT INTEL, RESEARCH, AND ADVISORY FEEDS INTO CYBERSECURITY NEWS.
              </p>
            </div>
          </div>

          <Link
            href="/news"
            style={{
              borderColor: "var(--accent-border)",
              backgroundColor: "var(--accent-soft)",
              color: "var(--accent)",
            }}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl border text-xs font-bold"
          >
            OPEN NEWS FEED <ExternalLink className="w-3.5 h-3.5" />
          </Link>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
          {POPULAR_RSS_FEEDS.map((preset) => {
            const isAdded = integratedUrls.has(preset.url.trim().toLowerCase());
            return (
              <div
                key={preset.id}
                className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/55 flex flex-col justify-between gap-3"
              >
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-extrabold">{preset.name}</span>
                    <span
                      className="text-[9px] font-bold px-2 py-0.5 rounded-full shrink-0"
                      style={{
                        backgroundColor: "var(--accent-soft)",
                        color: "var(--accent)",
                      }}
                    >
                      {preset.category}
                    </span>
                  </div>
                  <p className="text-[11px] text-[var(--text-secondary)] preserve-case leading-relaxed">
                    {preset.description}
                  </p>
                </div>

                <div className="pt-2 border-t border-[var(--border-subtle)] flex items-center justify-between gap-2">
                  <span className="font-mono-ioc preserve-case text-[10px] text-[var(--text-secondary)] truncate">
                    {preset.url}
                  </span>
                  {isAdded ? (
                    <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 text-[10px] font-bold shrink-0">
                      <Check className="w-3 h-3" /> INTEGRATED
                    </span>
                  ) : (
                    <button
                      type="button"
                      disabled={!canManage || integratingId === preset.id}
                      onClick={() => handleIntegratePreset(preset)}
                      style={{ backgroundColor: "var(--accent)" }}
                      className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-white text-[10px] font-bold cursor-pointer disabled:opacity-40 shrink-0"
                    >
                      <Plus className="w-3 h-3" />
                      {integratingId === preset.id ? "ADDING..." : "INTEGRATE"}
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* Active & Custom RSS Feeds */}
      <section className="rounded-2xl glass-panel p-4 sm:p-6 space-y-5">
        <div className="flex items-start sm:items-center gap-2">
          <Rss className="w-4 h-4 shrink-0 mt-0.5 sm:mt-0" style={{ color: "var(--accent)" }} />
          <div>
            <h2 className="text-sm sm:text-base font-bold">
              ACTIVE &amp; CUSTOM RSS FEEDS ({rssFeeds.length})
            </h2>
            <p className="text-[11px] text-[var(--text-secondary)]">
              ADD CUSTOM RSS/ATOM URLS OR TOGGLE ACTIVE SOURCES.
            </p>
          </div>
        </div>

        {canManage && (
          <form
            onSubmit={handleAddRssFeed}
            className="grid grid-cols-1 sm:grid-cols-12 gap-2.5 p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/50"
          >
            <input
              type="text"
              required
              value={feedName}
              onChange={(e) => setFeedName(e.target.value)}
              placeholder="CUSTOM FEED NAME..."
              className="sm:col-span-3 px-3 py-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-surface)] text-xs"
            />
            <input
              type="url"
              required
              value={feedUrl}
              onChange={(e) => setFeedUrl(e.target.value)}
              placeholder="https://example.com/feed.xml"
              className="sm:col-span-5 px-3 py-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-surface)] font-mono-ioc text-xs"
            />
            <input
              type="text"
              required
              value={feedCategory}
              onChange={(e) => setFeedCategory(e.target.value)}
              placeholder="CATEGORY"
              className="sm:col-span-2 px-3 py-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-surface)] text-xs"
            />
            <button
              type="submit"
              style={{ backgroundColor: "var(--accent)" }}
              className="sm:col-span-2 inline-flex items-center justify-center gap-1 px-3 py-2 rounded-xl text-white text-xs font-bold cursor-pointer"
            >
              <Plus className="w-3.5 h-3.5" /> ADD CUSTOM
            </button>
          </form>
        )}

        <div className="divide-y divide-[var(--border-subtle)] border border-[var(--border-subtle)] rounded-xl overflow-hidden">
          {rssFeeds.map((feed) => (
            <div
              key={feed.id}
              className="p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[var(--bg-elevated)]/35 text-xs"
            >
              <div className="flex items-start sm:items-center gap-3 min-w-0">
                <input
                  type="checkbox"
                  disabled={!canManage}
                  checked={feed.enabled}
                  onChange={(e) => handleToggleRssFeed(feed.id, e.target.checked)}
                  style={{ accentColor: "var(--accent)" }}
                  className="mt-1 sm:mt-0"
                />
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-bold">{feed.name}</span>
                    <span
                      className="text-[9px] font-bold px-2 py-0.5 rounded-full"
                      style={{
                        backgroundColor: "var(--accent-soft)",
                        color: "var(--accent)",
                      }}
                    >
                      {feed.category}
                    </span>
                  </div>
                  <div className="font-mono-ioc preserve-case text-[11px] text-[var(--text-secondary)] truncate">
                    {feed.url}
                  </div>
                </div>
              </div>

              {canManage && (
                <button
                  type="button"
                  onClick={() => handleDeleteRssFeed(feed.id)}
                  className="self-end sm:self-auto p-1.5 rounded-lg text-rose-400 hover:bg-rose-500/15 cursor-pointer"
                  title="REMOVE RSS FEED"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              )}
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
