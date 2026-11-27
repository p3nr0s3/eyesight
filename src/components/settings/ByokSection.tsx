"use client";

import React, { useCallback, useEffect, useState } from "react";
import { Save, KeyRound, ShieldCheck, Loader2 } from "lucide-react";
import { useAuth } from "@/components/AppShell";
import { loadBrowserByokKeys, saveBrowserByokKeys } from "@/lib/client-byok";
import type { ProviderId, ProviderMeta } from "@/lib/providers/catalog";

interface ProviderKeyRow extends ProviderMeta {
  hasEnvKey: boolean;
  hasServerKey: boolean;
  hasUserKey: boolean;
  userKeyMask: string | null;
}

export function ByokSection() {
  const auth = useAuth();
  const [loading, setLoading] = useState(true);
  const [providers, setProviders] = useState<ProviderKeyRow[]>([]);
  const [browserByok, setBrowserByok] = useState<Partial<Record<ProviderId, string>>>({});
  const [userKeyInputs, setUserKeyInputs] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<{ type: "ok" | "err"; text: string } | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/settings", { cache: "no-store" });
      if (res.ok) {
        const data = await res.json();
        setProviders(data.providers || []);
      }
      setBrowserByok(loadBrowserByokKeys());
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load, auth.user?.id]);

  const handleSaveBrowserByok = () => {
    saveBrowserByokKeys(browserByok);
    setMessage({
      type: "ok",
      text: "BROWSER BYOK KEYS SAVED LOCALLY FOR YOUR ENRICHMENT REQUESTS.",
    });
  };

  const handleSaveProfileKeys = async () => {
    setSaving(true);
    setMessage(null);
    try {
      const res = await fetch("/api/settings", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ userProviderKeys: userKeyInputs }),
      });
      const data = await res.json();
      if (!res.ok) {
        setMessage({ type: "err", text: data.error || "FAILED TO SAVE PROFILE KEYS" });
      } else {
        setUserKeyInputs({});
        setMessage({ type: "ok", text: "ENCRYPTED PROFILE BYOK KEYS SAVED." });
        await load();
      }
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="p-10 text-center text-xs font-bold text-[var(--text-secondary)] flex items-center justify-center gap-2">
        <Loader2 className="w-4 h-4 animate-spin" /> LOADING BYOK VAULT...
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
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-start sm:items-center gap-2">
            <KeyRound
              className="w-4 h-4 shrink-0 mt-0.5 sm:mt-0"
              style={{ color: "var(--accent)" }}
            />
            <div>
              <h2 className="text-sm sm:text-base font-bold">
                BRING-YOUR-OWN-KEY (BYOK) OVERRIDES
              </h2>
              <p className="text-[11px] text-[var(--text-secondary)]">
                BROWSER BYOK KEYS STAY IN LOCAL STORAGE AND OVERRIDE SERVER DEFAULTS PER REQUEST.
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={handleSaveBrowserByok}
              style={{
                borderColor: "var(--accent-border)",
                backgroundColor: "var(--accent-soft)",
                color: "var(--accent)",
              }}
              className="w-full sm:w-auto inline-flex items-center justify-center gap-1.5 px-3.5 py-2 rounded-xl border text-xs font-bold cursor-pointer"
            >
              <Save className="w-3.5 h-3.5" />
              SAVE BROWSER BYOK
            </button>
            {auth.user && (
              <button
                type="button"
                disabled={saving}
                onClick={handleSaveProfileKeys}
                style={{ backgroundColor: "var(--accent)" }}
                className="w-full sm:w-auto inline-flex items-center justify-center gap-1.5 px-3.5 py-2 rounded-xl text-white text-xs font-bold cursor-pointer disabled:opacity-50"
              >
                <ShieldCheck className="w-3.5 h-3.5" />
                {saving ? "SAVING..." : "SAVE ENCRYPTED PROFILE KEYS"}
              </button>
            )}
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
          {providers
            .filter((p) => p.keyRequirement !== "none")
            .map((p) => (
              <div
                key={p.id}
                className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/55 space-y-2.5"
              >
                <div className="flex items-center justify-between text-xs">
                  <span className="font-bold">{p.name}</span>
                  <span className="text-[10px] text-[var(--text-secondary)] font-mono-ioc">
                    {p.envVarName}
                  </span>
                </div>
                <div className="text-[10px] text-[var(--text-secondary)]">
                  SERVER:{" "}
                  {p.hasServerKey || p.hasEnvKey ? (
                    <span className="text-emerald-400 font-bold">CONFIGURED</span>
                  ) : (
                    <span>{p.keyRequirement === "optional" ? "OPTIONAL" : "UNCONFIGURED"}</span>
                  )}
                </div>
                <input
                  type="password"
                  value={browserByok[p.id] ?? ""}
                  onChange={(e) =>
                    setBrowserByok((prev) => ({
                      ...prev,
                      [p.id]: e.target.value,
                    }))
                  }
                  placeholder="BROWSER BYOK OVERRIDE..."
                  className="w-full px-3 py-2 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-surface)] font-mono-ioc text-xs"
                />
                {auth.user && (
                  <input
                    type="password"
                    value={userKeyInputs[p.id] ?? ""}
                    onChange={(e) =>
                      setUserKeyInputs((prev) => ({
                        ...prev,
                        [p.id]: e.target.value,
                      }))
                    }
                    placeholder={
                      p.hasUserKey
                        ? `ENCRYPTED PROFILE KEY (${p.userKeyMask})`
                        : "OR SAVE ENCRYPTED TO PROFILE..."
                    }
                    className="w-full px-3 py-2 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-surface)] font-mono-ioc text-xs"
                  />
                )}
              </div>
            ))}
        </div>
      </section>
    </div>
  );
}
