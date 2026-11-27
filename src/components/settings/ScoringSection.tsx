"use client";

import React, { useCallback, useEffect, useState } from "react";
import { Save, Sliders, Loader2 } from "lucide-react";
import { useAuth } from "@/components/AppShell";
import type { ProviderMeta } from "@/lib/providers/catalog";

interface ProviderSettingRow extends ProviderMeta {
  weight: number;
  ttlSeconds: number;
  enabled: boolean;
  hasEnvKey: boolean;
  hasServerKey: boolean;
  serverKeyMask: string | null;
}

export function ScoringSection() {
  const auth = useAuth();
  const [loading, setLoading] = useState(true);
  const [canManageWorkspace, setCanManageWorkspace] = useState(false);
  const [maliciousThreshold, setMaliciousThreshold] = useState(70);
  const [suspiciousThreshold, setSuspiciousThreshold] = useState(30);
  const [providers, setProviders] = useState<ProviderSettingRow[]>([]);
  const [serverKeyInputs, setServerKeyInputs] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<{ type: "ok" | "err"; text: string } | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/settings", { cache: "no-store" });
      if (res.ok) {
        const data = await res.json();
        setCanManageWorkspace(Boolean(data.canManageWorkspace));
        setMaliciousThreshold(data.thresholds?.maliciousThreshold ?? 70);
        setSuspiciousThreshold(data.thresholds?.suspiciousThreshold ?? 30);
        setProviders(data.providers || []);
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load, auth.user?.id]);

  const handleSave = async () => {
    setSaving(true);
    setMessage(null);
    try {
      const res = await fetch("/api/settings", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          thresholds: { maliciousThreshold, suspiciousThreshold },
          providers: providers.map((p) => {
            const item: Record<string, unknown> = {
              providerId: p.id,
              weight: p.weight,
              ttlSeconds: p.ttlSeconds,
              enabled: p.enabled,
            };
            if (serverKeyInputs[p.id] !== undefined) {
              item.serverApiKey = serverKeyInputs[p.id] || null;
            }
            return item;
          }),
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setMessage({ type: "err", text: data.error || "FAILED TO SAVE SETTINGS" });
      } else {
        setServerKeyInputs({});
        setMessage({ type: "ok", text: "SCORING WEIGHTS & PROVIDER CONFIG SAVED." });
        await load();
      }
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="p-10 text-center text-xs font-bold text-[var(--text-secondary)] flex items-center justify-center gap-2">
        <Loader2 className="w-4 h-4 animate-spin" /> LOADING SCORING CONFIGURATION...
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
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Sliders className="w-4 h-4" style={{ color: "var(--accent)" }} />
            <h2 className="text-sm sm:text-base font-bold">
              VERDICT THRESHOLDS, PROVIDER WEIGHTS &amp; SERVER KEYS
            </h2>
          </div>
          {canManageWorkspace ? (
            <button
              type="button"
              disabled={saving}
              onClick={handleSave}
              style={{ backgroundColor: "var(--accent)" }}
              className="w-full sm:w-auto inline-flex items-center justify-center gap-1.5 px-4 py-2 rounded-xl hover:opacity-90 disabled:opacity-50 text-white text-xs font-bold cursor-pointer"
            >
              <Save className="w-3.5 h-3.5" />
              {saving ? "SAVING..." : "SAVE WORKSPACE CONFIG"}
            </button>
          ) : (
            <span className="text-[11px] font-bold text-amber-400">
              ADMIN SIGN-IN REQUIRED TO MODIFY GLOBAL WEIGHTS
            </span>
          )}
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/50">
          <div>
            <label className="flex items-center justify-between text-xs font-bold mb-2">
              <span>SUSPICIOUS THRESHOLD (≥ SCORE)</span>
              <span className="font-mono-ioc text-amber-400">{suspiciousThreshold}</span>
            </label>
            <input
              type="range"
              min={5}
              max={85}
              disabled={!canManageWorkspace}
              value={suspiciousThreshold}
              onChange={(e) => setSuspiciousThreshold(Number(e.target.value))}
              className="w-full accent-amber-500"
            />
          </div>
          <div>
            <label className="flex items-center justify-between text-xs font-bold mb-2">
              <span>MALICIOUS THRESHOLD (≥ SCORE)</span>
              <span className="font-mono-ioc text-rose-400">{maliciousThreshold}</span>
            </label>
            <input
              type="range"
              min={15}
              max={100}
              disabled={!canManageWorkspace}
              value={maliciousThreshold}
              onChange={(e) => setMaliciousThreshold(Number(e.target.value))}
              className="w-full accent-rose-500"
            />
          </div>
        </div>

        {/* Mobile Cards */}
        <div className="md:hidden space-y-3">
          {providers.map((p) => (
            <div
              key={p.id}
              className="p-3.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/50 space-y-3 text-xs"
            >
              <div className="flex items-center justify-between gap-2">
                <div>
                  <div className="font-bold">{p.name}</div>
                  <div className="text-[10px] text-[var(--text-secondary)]">
                    {p.supportedTypes.join(", ")}
                  </div>
                </div>
                <input
                  type="checkbox"
                  disabled={!canManageWorkspace}
                  checked={p.enabled}
                  onChange={(e) =>
                    setProviders((prev) =>
                      prev.map((row) =>
                        row.id === p.id ? { ...row, enabled: e.target.checked } : row,
                      ),
                    )
                  }
                  style={{ accentColor: "var(--accent)" }}
                />
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="block text-[10px] font-bold text-[var(--text-secondary)] mb-1">
                    WEIGHT (0–100)
                  </label>
                  <input
                    type="number"
                    min={0}
                    max={100}
                    disabled={!canManageWorkspace}
                    value={p.weight}
                    onChange={(e) =>
                      setProviders((prev) =>
                        prev.map((row) =>
                          row.id === p.id ? { ...row, weight: Number(e.target.value) } : row,
                        ),
                      )
                    }
                    className="w-full px-2.5 py-1.5 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-surface)] font-mono-ioc"
                  />
                </div>
                <div>
                  <label className="block text-[10px] font-bold text-[var(--text-secondary)] mb-1">
                    CACHE TTL (SEC)
                  </label>
                  <input
                    type="number"
                    min={0}
                    max={604800}
                    disabled={!canManageWorkspace}
                    value={p.ttlSeconds}
                    onChange={(e) =>
                      setProviders((prev) =>
                        prev.map((row) =>
                          row.id === p.id ? { ...row, ttlSeconds: Number(e.target.value) } : row,
                        ),
                      )
                    }
                    className="w-full px-2.5 py-1.5 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-surface)] font-mono-ioc"
                  />
                </div>
              </div>
              {canManageWorkspace && p.keyRequirement !== "none" && (
                <input
                  type="password"
                  value={serverKeyInputs[p.id] ?? ""}
                  onChange={(e) =>
                    setServerKeyInputs((prev) => ({ ...prev, [p.id]: e.target.value }))
                  }
                  placeholder={p.hasServerKey ? "REPLACE SERVER KEY..." : "SET SERVER KEY..."}
                  className="w-full px-2.5 py-1.5 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-surface)] font-mono-ioc text-xs"
                />
              )}
            </div>
          ))}
        </div>

        {/* Desktop Table */}
        <div className="hidden md:block overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[var(--bg-elevated)]/70 text-[var(--text-secondary)] text-[10px] font-bold tracking-wider">
              <tr>
                <th className="px-3 py-2.5">ENABLED</th>
                <th className="px-3 py-2.5">PROVIDER</th>
                <th className="px-3 py-2.5">WEIGHT (0–100)</th>
                <th className="px-3 py-2.5">CACHE TTL (SEC)</th>
                <th className="px-3 py-2.5">SERVER KEY STATUS</th>
                {canManageWorkspace && <th className="px-3 py-2.5">SET SERVER KEY</th>}
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--border-subtle)]">
              {providers.map((p) => (
                <tr key={p.id}>
                  <td className="px-3 py-3">
                    <input
                      type="checkbox"
                      disabled={!canManageWorkspace}
                      checked={p.enabled}
                      onChange={(e) =>
                        setProviders((prev) =>
                          prev.map((row) =>
                            row.id === p.id ? { ...row, enabled: e.target.checked } : row,
                          ),
                        )
                      }
                      style={{ accentColor: "var(--accent)" }}
                    />
                  </td>
                  <td className="px-3 py-3">
                    <div className="font-bold">{p.name}</div>
                    <div className="text-[10px] text-[var(--text-secondary)]">
                      {p.supportedTypes.join(", ")}
                    </div>
                  </td>
                  <td className="px-3 py-3">
                    <input
                      type="number"
                      min={0}
                      max={100}
                      disabled={!canManageWorkspace}
                      value={p.weight}
                      onChange={(e) =>
                        setProviders((prev) =>
                          prev.map((row) =>
                            row.id === p.id ? { ...row, weight: Number(e.target.value) } : row,
                          ),
                        )
                      }
                      className="w-20 px-2 py-1 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-elevated)] font-mono-ioc"
                    />
                  </td>
                  <td className="px-3 py-3">
                    <input
                      type="number"
                      min={0}
                      max={604800}
                      disabled={!canManageWorkspace}
                      value={p.ttlSeconds}
                      onChange={(e) =>
                        setProviders((prev) =>
                          prev.map((row) =>
                            row.id === p.id ? { ...row, ttlSeconds: Number(e.target.value) } : row,
                          ),
                        )
                      }
                      className="w-24 px-2 py-1 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-elevated)] font-mono-ioc"
                    />
                  </td>
                  <td className="px-3 py-3 font-semibold">
                    {p.keyRequirement === "none" ? (
                      <span className="text-emerald-400">ZERO-KEY BUILT-IN</span>
                    ) : p.hasServerKey ? (
                      <span className="font-mono-ioc preserve-case" style={{ color: "var(--accent)" }}>
                        DB ({p.serverKeyMask})
                      </span>
                    ) : p.hasEnvKey ? (
                      <span className="text-emerald-400">ENV CONFIGURED</span>
                    ) : (
                      <span className="text-[var(--text-secondary)]">
                        {p.keyRequirement === "optional" ? "OPTIONAL" : "NOT SET"}
                      </span>
                    )}
                  </td>
                  {canManageWorkspace && (
                    <td className="px-3 py-3">
                      {p.keyRequirement !== "none" ? (
                        <input
                          type="password"
                          value={serverKeyInputs[p.id] ?? ""}
                          onChange={(e) =>
                            setServerKeyInputs((prev) => ({
                              ...prev,
                              [p.id]: e.target.value,
                            }))
                          }
                          placeholder={p.hasServerKey ? "REPLACE DB KEY..." : "SET SERVER KEY..."}
                          className="w-44 px-2.5 py-1.5 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-elevated)] font-mono-ioc text-xs"
                        />
                      ) : (
                        <span className="text-[var(--text-secondary)]">—</span>
                      )}
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
