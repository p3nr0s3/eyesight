"use client";

import React, { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  Newspaper,
  Search,
  RefreshCw,
  ExternalLink,
  Copy,
  Check,
  Rss,
  Loader2,
  Calendar,
  Settings,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";
import type { NewsArticle } from "@/lib/rss";

interface FeedStatus {
  id: string;
  name: string;
  category: string;
  ok: boolean;
  articleCount: number;
  error?: string;
}

const QUICK_TOPICS = ["ransomware", "zero-day", "vulnerability", "apt", "breach"];

export default function CybersecurityNewsPage() {
  const [articles, setArticles] = useState<NewsArticle[]>([]);
  const [feedStatuses, setFeedStatuses] = useState<FeedStatus[]>([]);
  const [totalFeeds, setTotalFeeds] = useState(0);
  const [enabledFeeds, setEnabledFeeds] = useState(0);
  const [fetchedAt, setFetchedAt] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [q, setQ] = useState("");
  const [source, setSource] = useState("ALL");
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(12);

  const loadNews = useCallback(
    async (refresh = false) => {
      setLoading(true);
      setError(null);
      try {
        const params = new URLSearchParams();
        if (refresh) params.set("refresh", "true");
        const res = await fetch(`/api/news?${params.toString()}`, {
          cache: "no-store",
        });
        const data = await res.json();
        if (!res.ok) {
          setError(data.error || "FAILED TO LOAD CYBERSECURITY NEWS");
        } else {
          setArticles(data.articles || []);
          setFeedStatuses(data.feedStatuses || []);
          setTotalFeeds(data.totalFeeds ?? 0);
          setEnabledFeeds(data.enabledFeeds ?? 0);
          setFetchedAt(data.fetchedAt || null);
        }
      } catch {
        setError("NETWORK ERROR WHILE FETCHING RSS NEWS FEEDS.");
      } finally {
        setLoading(false);
      }
    },
    [],
  );

  useEffect(() => {
    loadNews(false);
  }, [loadNews]);

  const filteredArticles = useMemo(() => {
    return articles.filter((a) => {
      if (source !== "ALL" && a.sourceName !== source) return false;
      if (!q.trim()) return true;
      const needle = q.trim().toLowerCase();
      return (
        a.title.toLowerCase().includes(needle) ||
        a.summary.toLowerCase().includes(needle) ||
        a.sourceName.toLowerCase().includes(needle) ||
        a.tags.some((t) => t.toLowerCase().includes(needle))
      );
    });
  }, [articles, q, source]);

  useEffect(() => {
    setPage(1);
  }, [q, source, pageSize, articles.length]);

  const totalPages = Math.max(1, Math.ceil(filteredArticles.length / pageSize));
  const safePage = Math.min(page, totalPages);
  const paginatedArticles = useMemo(() => {
    const start = (safePage - 1) * pageSize;
    return filteredArticles.slice(start, start + pageSize);
  }, [filteredArticles, safePage, pageSize]);

  const pageNumbers = useMemo(() => {
    const pages: Array<number | "..."> = [];
    for (let i = 1; i <= totalPages; i++) {
      if (
        i === 1 ||
        i === totalPages ||
        (i >= safePage - 1 && i <= safePage + 1)
      ) {
        pages.push(i);
      } else if (pages[pages.length - 1] !== "...") {
        pages.push("...");
      }
    }
    return pages;
  }, [totalPages, safePage]);

  const goToPage = (next: number) => {
    const clamped = Math.max(1, Math.min(totalPages, next));
    setPage(clamped);
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const copyLink = async (id: string, link: string) => {
    await navigator.clipboard.writeText(link);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1500);
  };

  return (
    <div className="space-y-6 w-full">
      {/* Header & KPI Cards */}
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
              <Newspaper className="w-3.5 h-3.5" />
              LIVE CYBERSECURITY RSS &amp; THREAT ADVISORIES
            </div>
            <h1 className="text-xl sm:text-2xl lg:text-3xl font-extrabold tracking-tight">
              CYBERSECURITY NEWS FEED
            </h1>
            <p className="text-xs sm:text-sm text-[var(--text-secondary)]">
              REAL-TIME SECURITY NEWS, ZERO-DAY DISCLOSURES, AND CISA ADVISORIES AGGREGATED FROM CONFIGURED RSS FEEDS.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <Link
              href="/settings/rss-feeds"
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] hover:border-[var(--accent-border)] text-xs font-bold"
            >
              <Settings className="w-3.5 h-3.5" />
              MANAGE RSS FEEDS
            </Link>
            <button
              type="button"
              onClick={() => loadNews(true)}
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

        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          <div className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/65">
            <div className="text-[10px] font-bold text-[var(--text-secondary)]">
              ARTICLES INDEXED
            </div>
            <div
              className="text-xl sm:text-2xl font-extrabold font-mono-ioc mt-1"
              style={{ color: "var(--accent)" }}
            >
              {articles.length}
            </div>
          </div>

          <div className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/65">
            <div className="text-[10px] font-bold text-[var(--text-secondary)]">
              ACTIVE RSS SOURCES
            </div>
            <div className="text-xl sm:text-2xl font-extrabold font-mono-ioc text-emerald-400 mt-1">
              {enabledFeeds}/{totalFeeds}
            </div>
          </div>

          <div className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/65">
            <div className="text-[10px] font-bold text-[var(--text-secondary)]">
              FILTERED MATCHES
            </div>
            <div className="text-xl sm:text-2xl font-extrabold font-mono-ioc mt-1">
              {filteredArticles.length}
            </div>
          </div>

          <div className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/65">
            <div className="text-[10px] font-bold text-[var(--text-secondary)]">
              LAST SYNC
            </div>
            <div className="text-xs font-mono-ioc font-bold mt-2">
              {fetchedAt ? new Date(fetchedAt).toLocaleTimeString() : "—"}
            </div>
          </div>
        </div>

        {/* Feed Status Strip */}
        {feedStatuses.length > 0 && (
          <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-[var(--border-subtle)]">
            <span className="text-[10px] font-bold text-[var(--text-secondary)] inline-flex items-center gap-1">
              <Rss className="w-3 h-3" /> FEEDS:
            </span>
            {feedStatuses.map((fs) => (
              <button
                key={fs.id}
                type="button"
                onClick={() =>
                  setSource(source === fs.name ? "ALL" : fs.name)
                }
                className={`text-[10px] font-bold px-2.5 py-1 rounded-full border transition cursor-pointer ${
                  source === fs.name
                    ? "border-[var(--accent-border)] bg-[var(--accent-soft)] text-[var(--accent)]"
                    : fs.ok
                      ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
                      : "border-rose-500/30 bg-rose-500/10 text-rose-300"
                }`}
              >
                {fs.name} ({fs.ok ? fs.articleCount : fs.error || "ERR"})
              </button>
            ))}
          </div>
        )}

        {/* Search & Filter */}
        <div className="flex flex-col sm:flex-row gap-2.5 pt-2 border-t border-[var(--border-subtle)]">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-[var(--text-secondary)] absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              type="text"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="SEARCH HEADLINES, RANSOMWARE, CVE, VENDOR, OR TAGS..."
              className="w-full pl-10 pr-4 py-2.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] font-mono-ioc text-xs focus:outline-none focus:border-[var(--accent)]"
            />
          </div>
          <select
            value={source}
            onChange={(e) => setSource(e.target.value)}
            className="px-3 py-2.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-xs font-bold"
          >
            <option value="ALL">ALL SOURCES</option>
            {feedStatuses.map((fs) => (
              <option key={fs.id} value={fs.name}>
                {fs.name.toUpperCase()}
              </option>
            ))}
          </select>
        </div>

        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-[10px] font-bold text-[var(--text-secondary)] mr-1">
            TOPICS:
          </span>
          {QUICK_TOPICS.map((topic) => (
            <button
              key={topic}
              type="button"
              onClick={() => setQ(q === topic ? "" : topic)}
              style={
                q.toLowerCase() === topic
                  ? {
                      backgroundColor: "var(--accent-soft)",
                      borderColor: "var(--accent-border)",
                      color: "var(--accent)",
                    }
                  : undefined
              }
              className="text-[10px] font-bold px-2.5 py-1 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-elevated)] cursor-pointer"
            >
              {topic}
            </button>
          ))}
        </div>
      </section>

      {error && (
        <div className="p-4 rounded-xl border border-rose-500/30 bg-rose-500/10 text-rose-300 text-xs font-bold">
          {error}
        </div>
      )}

      {loading && articles.length === 0 ? (
        <div className="rounded-2xl glass-panel p-12 text-center space-y-3">
          <Loader2
            className="w-8 h-8 animate-spin mx-auto"
            style={{ color: "var(--accent)" }}
          />
          <p className="text-xs font-bold text-[var(--text-secondary)]">
            FETCHING LIVE CYBERSECURITY RSS FEEDS...
          </p>
        </div>
      ) : filteredArticles.length === 0 ? (
        <div className="rounded-2xl glass-panel p-12 text-center text-xs font-bold text-[var(--text-secondary)]">
          NO ARTICLES MATCH YOUR CURRENT FILTER.
        </div>
      ) : (
        <div className="space-y-5">
          {/* Top Pagination Summary & Per-Page Selector */}
          <div className="flex flex-wrap items-center justify-between gap-3 px-1 text-xs font-bold text-[var(--text-secondary)]">
            <span>
              SHOWING {(safePage - 1) * pageSize + 1}–
              {Math.min(safePage * pageSize, filteredArticles.length)} OF{" "}
              {filteredArticles.length} ARTICLES (PAGE {safePage}/{totalPages})
            </span>
            <div className="flex items-center gap-2">
              <span>PER PAGE:</span>
              <select
                value={pageSize}
                onChange={(e) => setPageSize(Number(e.target.value))}
                className="px-2.5 py-1.5 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-xs font-bold text-[var(--text-primary)]"
              >
                <option value={12}>12</option>
                <option value={24}>24</option>
                <option value={36}>36</option>
                <option value={48}>48</option>
              </select>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-4">
            {paginatedArticles.map((art) => (
              <article
                key={art.id}
                className="rounded-2xl glass-panel p-5 flex flex-col justify-between gap-4 hover:border-[var(--accent-border)] transition"
              >
                <div className="space-y-2.5">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span
                      className="text-[9px] font-extrabold px-2 py-0.5 rounded-full"
                      style={{
                        backgroundColor: "var(--accent-soft)",
                        border: "1px solid var(--accent-border)",
                        color: "var(--accent)",
                      }}
                    >
                      {art.sourceName} · {art.sourceCategory}
                    </span>
                    <span className="text-[10px] font-mono-ioc text-[var(--text-secondary)] flex items-center gap-1">
                      <Calendar className="w-3 h-3" />
                      {new Date(art.publishedAt).toISOString().slice(0, 10)}
                    </span>
                  </div>

                  <h2 className="text-sm font-extrabold leading-snug">
                    <a
                      href={art.link}
                      target="_blank"
                      rel="noreferrer"
                      className="hover:underline"
                    >
                      {art.title}
                    </a>
                  </h2>

                  {art.summary && (
                    <p className="text-xs text-[var(--text-secondary)] preserve-case line-clamp-3 leading-relaxed">
                      {art.summary}
                    </p>
                  )}

                  {art.tags.length > 0 && (
                    <div className="flex flex-wrap gap-1 pt-1">
                      {art.tags.slice(0, 3).map((t) => (
                        <span
                          key={t}
                          className="text-[9px] font-bold px-2 py-0.5 rounded border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-[var(--text-secondary)]"
                        >
                          {t}
                        </span>
                      ))}
                    </div>
                  )}
                </div>

                <div className="flex items-center justify-between gap-2 pt-3 border-t border-[var(--border-subtle)]">
                  <a
                    href={art.link}
                    target="_blank"
                    rel="noreferrer"
                    style={{ color: "var(--accent)" }}
                    className="inline-flex items-center gap-1 text-[11px] font-extrabold hover:underline"
                  >
                    READ ADVISORY <ExternalLink className="w-3 h-3" />
                  </a>
                  <button
                    type="button"
                    onClick={() => copyLink(art.id, art.link)}
                    className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-[10px] font-bold cursor-pointer"
                  >
                    {copiedId === art.id ? (
                      <>
                        <Check className="w-3 h-3 text-emerald-400" /> COPIED
                      </>
                    ) : (
                      <>
                        <Copy className="w-3 h-3" /> COPY URL
                      </>
                    )}
                  </button>
                </div>
              </article>
            ))}
          </div>

          {/* Bottom Pagination Controls */}
          {totalPages > 1 && (
            <div className="rounded-2xl glass-panel p-3 sm:p-4 flex flex-wrap items-center justify-between gap-3">
              <button
                type="button"
                disabled={safePage <= 1}
                onClick={() => goToPage(safePage - 1)}
                className="inline-flex items-center gap-1 px-3 py-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-xs font-bold disabled:opacity-40 cursor-pointer"
              >
                <ChevronLeft className="w-3.5 h-3.5" /> PREV
              </button>

              <div className="flex flex-wrap items-center gap-1">
                {pageNumbers.map((p, idx) =>
                  p === "..." ? (
                    <span
                      key={`dots-${idx}`}
                      className="px-2 text-xs text-[var(--text-secondary)]"
                    >
                      …
                    </span>
                  ) : (
                    <button
                      key={p}
                      type="button"
                      onClick={() => goToPage(p)}
                      style={
                        p === safePage
                          ? {
                              backgroundColor: "var(--accent)",
                              borderColor: "var(--accent)",
                              color: "#ffffff",
                            }
                          : undefined
                      }
                      className={`min-w-8 px-2.5 py-1.5 rounded-lg border text-xs font-mono-ioc font-bold transition cursor-pointer ${
                        p === safePage
                          ? ""
                          : "border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
                      }`}
                    >
                      {p}
                    </button>
                  ),
                )}
              </div>

              <button
                type="button"
                disabled={safePage >= totalPages}
                onClick={() => goToPage(safePage + 1)}
                className="inline-flex items-center gap-1 px-3 py-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-xs font-bold disabled:opacity-40 cursor-pointer"
              >
                NEXT <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
