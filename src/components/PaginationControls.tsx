"use client";

import React, { useMemo } from "react";
import { ChevronLeft, ChevronRight } from "lucide-react";

export function PaginationControls({
  totalItems,
  page,
  pageSize,
  onPageChange,
  onPageSizeChange,
  pageSizeOptions = [12, 24, 36, 48],
  label = "ITEMS",
}: {
  totalItems: number;
  page: number;
  pageSize: number;
  onPageChange: (nextPage: number) => void;
  onPageSizeChange?: (nextSize: number) => void;
  pageSizeOptions?: number[];
  label?: string;
}) {
  const totalPages = Math.max(1, Math.ceil(totalItems / pageSize));
  const safePage = Math.min(page, totalPages);

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

  if (totalItems === 0) return null;

  const start = (safePage - 1) * pageSize + 1;
  const end = Math.min(safePage * pageSize, totalItems);

  return (
    <div className="rounded-2xl glass-panel p-3 sm:p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
      <div className="flex flex-wrap items-center gap-3 text-[11px] font-bold text-[var(--text-secondary)]">
        <span>
          SHOWING {start}–{end} OF {totalItems} {label} (PAGE {safePage}/
          {totalPages})
        </span>
        {onPageSizeChange && (
          <div className="flex items-center gap-1.5">
            <span>PER PAGE:</span>
            <select
              value={pageSize}
              onChange={(e) => onPageSizeChange(Number(e.target.value))}
              className="px-2 py-1 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-[11px] font-bold text-[var(--text-primary)]"
            >
              {pageSizeOptions.map((opt) => (
                <option key={opt} value={opt}>
                  {opt}
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      {totalPages > 1 && (
        <div className="flex flex-wrap items-center gap-1.5">
          <button
            type="button"
            disabled={safePage <= 1}
            onClick={() => onPageChange(safePage - 1)}
            className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-[11px] font-bold disabled:opacity-40 cursor-pointer"
          >
            <ChevronLeft className="w-3.5 h-3.5" /> PREV
          </button>

          {pageNumbers.map((p, idx) =>
            p === "..." ? (
              <span
                key={`dots-${idx}`}
                className="px-1.5 text-xs text-[var(--text-secondary)]"
              >
                …
              </span>
            ) : (
              <button
                key={p}
                type="button"
                onClick={() => onPageChange(p)}
                style={
                  p === safePage
                    ? {
                        backgroundColor: "var(--accent)",
                        borderColor: "var(--accent)",
                        color: "#ffffff",
                      }
                    : undefined
                }
                className={`min-w-8 px-2.5 py-1.5 rounded-lg border text-[11px] font-mono-ioc font-bold transition cursor-pointer ${
                  p === safePage
                    ? ""
                    : "border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
                }`}
              >
                {p}
              </button>
            ),
          )}

          <button
            type="button"
            disabled={safePage >= totalPages}
            onClick={() => onPageChange(safePage + 1)}
            className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-[11px] font-bold disabled:opacity-40 cursor-pointer"
          >
            NEXT <ChevronRight className="w-3.5 h-3.5" />
          </button>
        </div>
      )}
    </div>
  );
}
