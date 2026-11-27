"use client";

import type { ThreatVerdict } from "@/lib/providers/types";

export function RiskGauge({
  score,
  verdict,
}: {
  score: number | null;
  verdict: ThreatVerdict;
}) {
  const radius = 36;
  const circumference = 2 * Math.PI * radius;
  const pct = score === null ? 0 : Math.max(0, Math.min(100, score));
  const strokeDashoffset = circumference - (pct / 100) * circumference;

  const strokeColor =
    verdict === "malicious"
      ? "#f43f5e"
      : verdict === "suspicious"
        ? "#f59e0b"
        : verdict === "clean"
          ? "#10b981"
          : "#64748b";

  return (
    <div className="relative w-24 h-24 flex items-center justify-center shrink-0">
      <svg className="w-24 h-24 -rotate-90" viewBox="0 0 88 88">
        <circle
          cx="44"
          cy="44"
          r={radius}
          fill="none"
          stroke="currentColor"
          strokeWidth="7"
          className="text-slate-700/30"
        />
        <circle
          cx="44"
          cy="44"
          r={radius}
          fill="none"
          stroke={strokeColor}
          strokeWidth="7"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          style={{ transition: "stroke-dashoffset 0.5s ease" }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-xl font-bold font-mono-ioc leading-none">
          {score === null ? "—" : score}
        </span>
        <span className="text-[10px] uppercase tracking-wider text-[var(--text-secondary)] mt-0.5">
          / 100
        </span>
      </div>
    </div>
  );
}
