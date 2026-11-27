"use client";

import React, { useCallback, useEffect, useState } from "react";
import { Terminal, Plus, Trash2, Check, Copy, Loader2 } from "lucide-react";
import { useAuth } from "@/components/AppShell";

interface RestApiKeyRow {
  id: string;
  name: string;
  keyPrefix: string;
  lastUsedAt: string | null;
  createdAt: string;
}

export function ApiTokensSection() {
  const auth = useAuth();
  const [loading, setLoading] = useState(true);
  const [restKeys, setRestKeys] = useState<RestApiKeyRow[]>([]);
  const [newKeyName, setNewKeyName] = useState("");
  const [newlyCreatedKey, setNewlyCreatedKey] = useState<string | null>(null);
  const [copiedNewKey, setCopiedNewKey] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/api-keys", { cache: "no-store" });
      if (res.ok) {
        const data = await res.json();
        setRestKeys(data.items || []);
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load, auth.user?.id]);

  const createRestApiKey = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newKeyName.trim()) return;
    setError(null);
    const res = await fetch("/api/api-keys", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: newKeyName.trim() }),
    });
    const data = await res.json();
    if (res.ok) {
      setNewlyCreatedKey(data.rawKey);
      setNewKeyName("");
      load();
    } else {
      setError(data.error || "FAILED TO CREATE API KEY");
    }
  };

  const revokeRestApiKey = async (id: string) => {
    await fetch(`/api/api-keys/${id}`, { method: "DELETE" });
    load();
  };

  if (loading) {
    return (
      <div className="p-10 text-center text-xs font-bold text-[var(--text-secondary)] flex items-center justify-center gap-2">
        <Loader2 className="w-4 h-4 animate-spin" /> LOADING REST API TOKENS...
      </div>
    );
  }

  return (
    <section className="rounded-2xl glass-panel p-4 sm:p-6 space-y-5">
      <div className="flex items-start sm:items-center gap-2">
        <Terminal
          className="w-4 h-4 shrink-0 mt-0.5 sm:mt-0"
          style={{ color: "var(--accent)" }}
        />
        <div>
          <h2 className="text-sm sm:text-base font-bold">
            REST API TOKENS (SOAR / CLI AUTOMATION)
          </h2>
          <p className="text-[11px] text-[var(--text-secondary)]">
            AUTHENTICATE AUTOMATED SCRIPTS AGAINST{" "}
            <code className="font-mono-ioc preserve-case">/api/lookup</code>,{" "}
            <code className="font-mono-ioc preserve-case">/api/cve</code>, AND{" "}
            <code className="font-mono-ioc preserve-case">/api/news</code> USING{" "}
            <code className="font-mono-ioc preserve-case">X-API-Key</code>.
          </p>
        </div>
      </div>

      {error && (
        <div className="p-3 rounded-xl border border-rose-500/30 bg-rose-500/10 text-rose-400 text-xs font-bold">
          {error}
        </div>
      )}

      {!auth.user ? (
        <div className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/40 text-xs font-semibold text-[var(--text-secondary)]">
          SIGN IN TO CREATE AND MANAGE PERSONAL REST API KEYS.
        </div>
      ) : (
        <div className="space-y-4">
          <form
            onSubmit={createRestApiKey}
            className="flex flex-col sm:flex-row gap-2 max-w-md"
          >
            <input
              type="text"
              value={newKeyName}
              onChange={(e) => setNewKeyName(e.target.value)}
              placeholder="KEY NAME (E.G. SPLUNK SOAR)"
              className="flex-1 px-3 py-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-xs"
            />
            <button
              type="submit"
              style={{ backgroundColor: "var(--accent)" }}
              className="inline-flex items-center justify-center gap-1 px-4 py-2 rounded-xl text-white text-xs font-bold cursor-pointer"
            >
              <Plus className="w-3.5 h-3.5" /> GENERATE KEY
            </button>
          </form>

          {newlyCreatedKey && (
            <div className="p-3.5 rounded-xl border border-emerald-500/30 bg-emerald-500/10 space-y-2">
              <div className="text-xs font-bold text-emerald-400">
                COPY YOUR NEW API KEY NOW — IT WON&apos;T BE SHOWN AGAIN:
              </div>
              <div className="flex items-center gap-2">
                <code className="font-mono-ioc preserve-case text-xs px-2.5 py-1.5 rounded-lg bg-black/40 text-emerald-300 flex-1 break-all">
                  {newlyCreatedKey}
                </code>
                <button
                  type="button"
                  onClick={async () => {
                    await navigator.clipboard.writeText(newlyCreatedKey);
                    setCopiedNewKey(true);
                    setTimeout(() => setCopiedNewKey(false), 1500);
                  }}
                  className="px-2.5 py-1.5 rounded-lg border border-emerald-500/30 text-xs font-bold text-emerald-300 inline-flex items-center gap-1 cursor-pointer"
                >
                  {copiedNewKey ? (
                    <Check className="w-3.5 h-3.5" />
                  ) : (
                    <Copy className="w-3.5 h-3.5" />
                  )}
                  COPY
                </button>
              </div>
            </div>
          )}

          {restKeys.length > 0 && (
            <div className="divide-y divide-[var(--border-subtle)] border border-[var(--border-subtle)] rounded-xl overflow-hidden">
              {restKeys.map((k) => (
                <div
                  key={k.id}
                  className="p-3.5 flex items-center justify-between gap-3 bg-[var(--bg-elevated)]/30 text-xs"
                >
                  <div>
                    <div className="font-bold">{k.name}</div>
                    <div className="font-mono-ioc preserve-case text-[11px] text-[var(--text-secondary)]">
                      {k.keyPrefix}•••••••• • CREATED{" "}
                      {new Date(k.createdAt).toLocaleDateString()}
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => revokeRestApiKey(k.id)}
                    className="p-1.5 rounded-lg text-rose-400 hover:bg-rose-500/15 cursor-pointer"
                    title="REVOKE API KEY"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      <pre className="p-3.5 rounded-xl border border-[var(--border-subtle)] bg-[#04070e] text-slate-300 font-mono-ioc text-xs overflow-x-auto">
{`curl -s "https://your-eyesight-host/api/lookup?ioc=1.1.1.1" \\
  -H "X-API-Key: ey_your_api_key_here"`}
      </pre>
    </section>
  );
}
