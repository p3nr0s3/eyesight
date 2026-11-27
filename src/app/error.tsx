"use client";

import React, { useEffect } from "react";
import Link from "next/link";
import { AlertTriangle, RefreshCw, Home } from "lucide-react";

export default function AppError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  const isChunkError =
    error.name === "ChunkLoadError" ||
    /loading chunk|failed to fetch dynamically imported module|chunkloaderror/i.test(
      error.message,
    );

  useEffect(() => {
    console.error("EYESIGHT UI Error Boundary caught error:", error);
  }, [error]);

  return (
    <div className="mx-auto flex min-h-[60vh] max-w-2xl items-center justify-center px-4 py-12">
      <div className="w-full rounded-2xl border border-rose-500/35 bg-[var(--bg-surface)] p-6 shadow-2xl backdrop-blur-xl sm:p-8">
        <div className="flex items-start gap-4">
          <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border border-rose-500/40 bg-rose-500/15 text-rose-300">
            <AlertTriangle className="h-5 w-5" />
          </div>
          <div className="min-w-0 flex-1 space-y-2">
            <p className="text-[11px] font-semibold tracking-wider text-rose-300">
              {isChunkError
                ? "APPLICATION UPDATE DETECTED"
                : "RUNTIME RECOVERY GUARD"}
            </p>
            <h2 className="text-lg font-bold tracking-wide text-[var(--text-primary)]">
              {isChunkError
                ? "MODULE CHUNK UPDATED — RELOAD TO SYNC"
                : "A VIEW ENCOUNTERED AN UNEXPECTED ERROR"}
            </h2>
            <p className="text-xs leading-relaxed text-[var(--text-secondary)]">
              {isChunkError
                ? "A background update refreshed frontend bundles while this tab was open. Reload the page to load the latest compiled assets cleanly."
                : error.message || "Unexpected rendering error."}
            </p>
            {error.digest && (
              <p className="font-mono text-[10px] text-[var(--text-secondary)]">
                DIGEST: {error.digest}
              </p>
            )}
          </div>
        </div>

        <div className="mt-6 flex flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={() => {
              if (isChunkError && typeof window !== "undefined") {
                window.location.reload();
              } else {
                reset();
              }
            }}
            className="inline-flex items-center gap-2 rounded-xl border border-[var(--accent-border)] bg-[var(--accent-soft)] px-4 py-2 text-xs font-semibold text-[var(--text-primary)] transition hover:brightness-110"
          >
            <RefreshCw className="h-3.5 w-3.5" />
            {isChunkError ? "RELOAD APPLICATION" : "RETRY VIEW"}
          </button>

          <button
            type="button"
            onClick={() => window.location.reload()}
            className="inline-flex items-center gap-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] px-4 py-2 text-xs font-semibold text-[var(--text-secondary)] transition hover:text-[var(--text-primary)]"
          >
            HARD REFRESH
          </button>

          <Link
            href="/"
            className="inline-flex items-center gap-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] px-4 py-2 text-xs font-semibold text-[var(--text-secondary)] transition hover:text-[var(--text-primary)]"
          >
            <Home className="h-3.5 w-3.5" />
            IOC LOOKUP HOME
          </Link>
        </div>
      </div>
    </div>
  );
}
