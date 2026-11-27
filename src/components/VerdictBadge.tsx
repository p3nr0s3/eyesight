"use client";

import type { ThreatVerdict } from "@/lib/providers/types";

const VERDICT_STYLES: Record<
  ThreatVerdict,
  { label: string; classes: string; dot: string }
> = {
  malicious: {
    label: "MALICIOUS",
    classes: "bg-rose-500/15 text-rose-400 border-rose-500/35",
    dot: "bg-rose-400",
  },
  suspicious: {
    label: "SUSPICIOUS",
    classes: "bg-amber-500/15 text-amber-400 border-amber-500/35",
    dot: "bg-amber-400",
  },
  clean: {
    label: "CLEAN",
    classes: "bg-emerald-500/15 text-emerald-400 border-emerald-500/35",
    dot: "bg-emerald-400",
  },
  unknown: {
    label: "UNKNOWN",
    classes: "bg-slate-500/15 text-slate-400 border-slate-500/35",
    dot: "bg-slate-400",
  },
};

export function VerdictBadge({
  verdict,
  size = "sm",
}: {
  verdict: ThreatVerdict;
  size?: "sm" | "md";
}) {
  const cfg = VERDICT_STYLES[verdict] || VERDICT_STYLES.unknown;
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border font-bold tracking-wider ${cfg.classes} ${
        size === "md" ? "px-3 py-1 text-[11px]" : "px-2 py-0.5 text-[10px]"
      }`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot}`} />
      {cfg.label}
    </span>
  );
}
