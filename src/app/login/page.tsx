"use client";

import React, { Suspense, useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import {
  ShieldCheck,
  Lock,
  Mail,
  User,
  ArrowRight,
  Loader2,
  AlertTriangle,
} from "lucide-react";
import { useAuth } from "@/components/AppShell";

function LoginPortalContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const nextPath = searchParams.get("next") || "/";
  const auth = useAuth();

  const [mode, setMode] = useState<"login" | "register">("login");
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!auth.loading && !auth.hasUsers) {
      setMode("register");
    }
  }, [auth.loading, auth.hasUsers]);

  useEffect(() => {
    if (!auth.loading && auth.authenticated) {
      router.replace(nextPath.startsWith("/") ? nextPath : "/");
    }
  }, [auth.loading, auth.authenticated, nextPath, router]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const endpoint =
        mode === "login" ? "/api/auth/login" : "/api/auth/register";
      const payload =
        mode === "login" ? { email, password } : { email, name, password };
      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || "AUTHENTICATION FAILED");
      } else {
        await auth.refreshAuth();
        router.replace(nextPath.startsWith("/") ? nextPath : "/");
      }
    } catch {
      setError("NETWORK ERROR WHILE CONNECTING TO AUTH PORTAL.");
    } finally {
      setSubmitting(false);
    }
  };

  if (auth.loading) {
    return (
      <div className="min-h-[75vh] flex items-center justify-center">
        <div className="flex items-center gap-2 text-xs font-bold text-[var(--text-secondary)]">
          <Loader2
            className="w-5 h-5 animate-spin"
            style={{ color: "var(--accent)" }}
          />
          INITIALIZING SECURITY PORTAL...
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-[calc(100vh-5rem)] w-full flex items-center justify-center px-3 py-8">
      <div className="w-full max-w-4xl grid grid-cols-1 lg:grid-cols-12 rounded-2xl glass-panel overflow-hidden shadow-2xl">
        {/* Left Portal Info Panel */}
        <div className="lg:col-span-5 p-6 sm:p-8 border-b lg:border-b-0 lg:border-r border-[var(--border-subtle)] bg-[var(--bg-elevated)]/65 flex flex-col justify-between gap-6">
          <div className="space-y-4">
            <div className="flex items-center gap-3">
              <span
                className="h-11 w-11 rounded-2xl flex items-center justify-center shadow-md"
                style={{
                  backgroundColor: "var(--accent-soft)",
                  border: "1px solid var(--accent-border)",
                  color: "var(--accent)",
                }}
              >
                <svg
                  viewBox="0 0 24 24"
                  className="w-6 h-6"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                >
                  <path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z" />
                  <circle cx="12" cy="12" r="3" />
                </svg>
              </span>
              <div>
                <div className="text-lg font-extrabold tracking-widest">
                  EYESIGHT
                </div>
                <div
                  className="text-[10px] font-bold tracking-widest"
                  style={{ color: "var(--accent)" }}
                >
                  THREAT INTELLIGENCE PORTAL
                </div>
              </div>
            </div>

            <h1 className="text-xl sm:text-2xl font-extrabold tracking-tight leading-snug">
              ANALYST AUTHENTICATION REQUIRED
            </h1>
            <p className="text-xs text-[var(--text-secondary)] leading-relaxed">
              SIGN IN TO ACCESS IOC INVESTIGATION, BULK QUEUE ENRICHMENT, STIX 2.1 EXPORTS, AND CONFIGURABLE PROVIDER API KEYS.
            </p>
          </div>

          <div className="space-y-2.5 text-[11px] font-semibold">
            <div className="flex items-center gap-2 text-[var(--text-secondary)]">
              <ShieldCheck
                className="w-4 h-4 shrink-0"
                style={{ color: "var(--accent)" }}
              />
              <span>9 THREAT INTEL & OSINT ENGINES</span>
            </div>
            <div className="flex items-center gap-2 text-[var(--text-secondary)]">
              <Lock
                className="w-4 h-4 shrink-0"
                style={{ color: "var(--accent)" }}
              />
              <span>ENCRYPTED HYBRID BYOK & REST API KEYS</span>
            </div>
          </div>
        </div>

        {/* Right Form Panel */}
        <div className="lg:col-span-7 p-6 sm:p-8 flex flex-col justify-center">
          <div className="flex items-center justify-between gap-2 mb-5">
            <div className="inline-flex rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] p-1">
              <button
                type="button"
                onClick={() => {
                  setError(null);
                  setMode("login");
                }}
                style={
                  mode === "login"
                    ? {
                        backgroundColor: "var(--accent)",
                        color: "#ffffff",
                      }
                    : undefined
                }
                className={`px-4 py-1.5 rounded-lg text-xs font-bold transition cursor-pointer ${
                  mode === "login" ? "" : "text-[var(--text-secondary)]"
                }`}
              >
                SIGN IN
              </button>
              <button
                type="button"
                onClick={() => {
                  setError(null);
                  setMode("register");
                }}
                style={
                  mode === "register"
                    ? {
                        backgroundColor: "var(--accent)",
                        color: "#ffffff",
                      }
                    : undefined
                }
                className={`px-4 py-1.5 rounded-lg text-xs font-bold transition cursor-pointer ${
                  mode === "register" ? "" : "text-[var(--text-secondary)]"
                }`}
              >
                {auth.hasUsers ? "REGISTER" : "SETUP ADMIN"}
              </button>
            </div>
          </div>

          {!auth.hasUsers && mode === "register" && (
            <div
              className="mb-4 p-3.5 rounded-xl text-[11px] font-bold"
              style={{
                backgroundColor: "var(--accent-soft)",
                border: "1px solid var(--accent-border)",
                color: "var(--accent)",
              }}
            >
              FIRST-TIME SETUP: NO ACCOUNTS EXIST YET. THIS ACCOUNT WILL BE
              PROVISIONED AS WORKSPACE ADMIN.
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            {mode === "register" && (
              <div>
                <label className="block text-[11px] font-bold text-[var(--text-secondary)] mb-1.5">
                  DISPLAY NAME
                </label>
                <div className="relative">
                  <User className="w-4 h-4 text-[var(--text-secondary)] absolute left-3.5 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    required
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="SOC Analyst"
                    className="w-full pl-10 pr-3.5 py-3 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-sm focus:outline-none focus:border-[var(--accent)]"
                  />
                </div>
              </div>
            )}

            <div>
              <label className="block text-[11px] font-bold text-[var(--text-secondary)] mb-1.5">
                EMAIL ADDRESS
              </label>
              <div className="relative">
                <Mail className="w-4 h-4 text-[var(--text-secondary)] absolute left-3.5 top-1/2 -translate-y-1/2" />
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="analyst@soc.local"
                  className="w-full pl-10 pr-3.5 py-3 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-sm focus:outline-none focus:border-[var(--accent)]"
                />
              </div>
            </div>

            <div>
              <label className="block text-[11px] font-bold text-[var(--text-secondary)] mb-1.5">
                PASSWORD
              </label>
              <div className="relative">
                <Lock className="w-4 h-4 text-[var(--text-secondary)] absolute left-3.5 top-1/2 -translate-y-1/2" />
                <input
                  type="password"
                  required
                  minLength={mode === "register" ? 8 : 6}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  className="w-full pl-10 pr-3.5 py-3 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-sm focus:outline-none focus:border-[var(--accent)]"
                />
              </div>
            </div>

            {error && (
              <div className="p-3 rounded-xl border border-rose-500/30 bg-rose-500/10 text-rose-400 text-xs font-bold flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>{error}</span>
              </div>
            )}

            <button
              type="submit"
              disabled={submitting}
              style={{ backgroundColor: "var(--accent)" }}
              className="w-full py-3 rounded-xl hover:opacity-90 disabled:opacity-50 text-white text-xs font-extrabold tracking-wider inline-flex items-center justify-center gap-2 transition cursor-pointer shadow-lg"
            >
              {submitting ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  AUTHENTICATING...
                </>
              ) : (
                <>
                  {mode === "login"
                    ? "ENTER EYESIGHT PORTAL"
                    : auth.hasUsers
                      ? "CREATE ANALYST ACCOUNT"
                      : "INITIALIZE ADMIN & ENTER"}
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense
      fallback={
        <div className="p-12 text-center text-xs font-bold text-[var(--text-secondary)]">
          LOADING PORTAL...
        </div>
      }
    >
      <LoginPortalContent />
    </Suspense>
  );
}
