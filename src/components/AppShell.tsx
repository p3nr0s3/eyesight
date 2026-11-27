"use client";

import React, { createContext, useContext, useEffect, useState } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import {
  Search,
  Layers,
  History,
  Settings,
  Palette,
  LogIn,
  LogOut,
  User,
  X,
  ChevronDown,
  ChevronRight,
  Shield,
  Bug,
  Radar,
  Globe,
  Sliders,
  Check,
  Menu,
  Loader2,
  ShieldAlert,
  Newspaper,
  Skull,
  Wrench,
} from "lucide-react";
import type { ProviderId, ToolCategoryId } from "@/lib/providers/catalog";
import { applyUiPreferences, loadUiPreferences } from "@/lib/ui-preferences";

interface AuthUser {
  id: string;
  email: string;
  name: string;
  role: "admin" | "analyst";
}

interface AuthState {
  authenticated: boolean;
  authRequired: boolean;
  hasUsers: boolean;
  user: AuthUser | null;
  loading: boolean;
  refreshAuth: () => Promise<void>;
}

export type ThemeId = "obsidian" | "emerald" | "crimson" | "violet" | "arctic";

interface ThemeOption {
  id: ThemeId;
  name: string;
  swatch: string;
  isLight?: boolean;
}

export const THEME_OPTIONS: ThemeOption[] = [
  { id: "obsidian", name: "OBSIDIAN CYAN", swatch: "#06b6d4" },
  { id: "emerald", name: "MIDNIGHT MATRIX", swatch: "#10b981" },
  { id: "crimson", name: "CRIMSON SENTINEL", swatch: "#f43f5e" },
  { id: "violet", name: "SYNTHWAVE VIOLET", swatch: "#a855f7" },
  { id: "arctic", name: "ARCTIC SLATE", swatch: "#0284c7", isLight: true },
];

export interface MenuChildItem {
  id: string;
  label: string;
  description: string;
  href: string;
  category?: ToolCategoryId;
  tool?: ProviderId | null;
}

export interface MenuGroup {
  id: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  items: MenuChildItem[];
}

export const TOOL_MENU_GROUPS: MenuGroup[] = [
  {
    id: "ioc_investigation",
    label: "IOC INVESTIGATION",
    icon: Search,
    items: [
      {
        id: "ioc_lookup",
        label: "IOC LOOKUP",
        description: "SINGLE IP, DOMAIN, URL, OR FILE HASH ENRICHMENT",
        href: "/",
        category: "all",
        tool: null,
      },
      {
        id: "bulk_lookup",
        label: "BULK IOC QUEUE",
        description: "CHUNKED MULTI-IOC BATCH ENRICHMENT & EXPORT",
        href: "/bulk",
        category: "all",
        tool: null,
      },
      {
        id: "live_attacks",
        label: "LIVE ATTACK IOCS",
        description: "REAL-TIME BOTNET C2, PHISHING, DSHIELD & HASH FEED",
        href: "/attacks",
      },
    ],
  },
  {
    id: "reputation",
    label: "REPUTATION & AV",
    icon: Shield,
    items: [
      {
        id: "rep_all",
        label: "ALL REPUTATION ENGINES",
        description: "FOCUS ON MULTI-ENGINE AV & IP ABUSE SCORING",
        href: "/?category=reputation",
        category: "reputation",
        tool: null,
      },
      {
        id: "rep_vt",
        label: "VIRUSTOTAL",
        description: "70+ AV ENGINES FOR IP, DOMAIN, URL & HASH",
        href: "/?category=reputation&tool=virustotal",
        category: "reputation",
        tool: "virustotal",
      },
      {
        id: "rep_abuseipdb",
        label: "ABUSEIPDB",
        description: "CROWDSOURCED IP ABUSE CONFIDENCE & REPORTS",
        href: "/?category=reputation&tool=abuseipdb",
        category: "reputation",
        tool: "abuseipdb",
      },
    ],
  },
  {
    id: "malware_feeds",
    label: "MALWARE FEEDS",
    icon: Bug,
    items: [
      {
        id: "mal_all",
        label: "ALL MALWARE FEEDS",
        description: "ABUSE.CH LIVE MALWARE & C2 INTELLIGENCE",
        href: "/?category=malware_feeds",
        category: "malware_feeds",
        tool: null,
      },
      {
        id: "mal_urlhaus",
        label: "ABUSE.CH URLHAUS",
        description: "MALWARE DISTRIBUTION URLS, HOSTS & PAYLOADS",
        href: "/?category=malware_feeds&tool=urlhaus",
        category: "malware_feeds",
        tool: "urlhaus",
      },
      {
        id: "mal_threatfox",
        label: "ABUSE.CH THREATFOX",
        description: "C2 SERVERS, MALWARE IOCS & CONFIDENCE SCORES",
        href: "/?category=malware_feeds&tool=threatfox",
        category: "malware_feeds",
        tool: "threatfox",
      },
      {
        id: "mal_bazaar",
        label: "ABUSE.CH MALWAREBAZAAR",
        description: "MALWARE SAMPLE SIGNATURES & METADATA BY HASH",
        href: "/?category=malware_feeds&tool=malwarebazaar",
        category: "malware_feeds",
        tool: "malwarebazaar",
      },
    ],
  },
  {
    id: "exposure_noise",
    label: "EXPOSURE & NOISE",
    icon: Radar,
    items: [
      {
        id: "exp_all",
        label: "ALL EXPOSURE & NOISE",
        description: "PULSES, OPEN PORTS, CVES & SCANNER NOISE",
        href: "/?category=exposure_noise",
        category: "exposure_noise",
        tool: null,
      },
      {
        id: "exp_otx",
        label: "ALIENVAULT OTX",
        description: "THREAT PULSES & ADVERSARY CONTEXT",
        href: "/?category=exposure_noise&tool=otx",
        category: "exposure_noise",
        tool: "otx",
      },
      {
        id: "exp_shodan",
        label: "SHODAN",
        description: "OPEN PORTS, BANNERS & KNOWN CVES",
        href: "/?category=exposure_noise&tool=shodan",
        category: "exposure_noise",
        tool: "shodan",
      },
      {
        id: "exp_greynoise",
        label: "GREYNOISE",
        description: "RIOT BENIGN INFRASTRUCTURE VS MASS SCANNERS",
        href: "/?category=exposure_noise&tool=greynoise",
        category: "exposure_noise",
        tool: "greynoise",
      },
    ],
  },
  {
    id: "network_osint",
    label: "NETWORK & OSINT",
    icon: Globe,
    items: [
      {
        id: "net_rdap",
        label: "DNS / RDAP / GEOIP",
        description: "ZERO-KEY LIVE DNS, WHOIS/RDAP, GEOIP & ASN",
        href: "/?category=network_osint&tool=network_rdap",
        category: "network_osint",
        tool: "network_rdap",
      },
    ],
  },
  {
    id: "soc_workbench",
    label: "SOC WORKBENCH",
    icon: Wrench,
    items: [
      {
        id: "soc_extractor",
        label: "IOC EXTRACTOR & DEFANGER",
        description: "EXTRACT, DEFANG & REFANG IPS, DOMAINS, URLS, HASHES & CVES",
        href: "/soc-tools?tool=extractor",
      },
      {
        id: "soc_email_headers",
        label: "EMAIL HEADER ANALYZER",
        description: "SPF, DKIM, DMARC, SPOOFING & SMTP RELAY HOP TRACE",
        href: "/soc-tools?tool=email-headers",
      },
      {
        id: "soc_decoder",
        label: "PAYLOAD DECODER & HASH",
        description: "BASE64, POWERSHELL UTF-16LE, HEX, URL, JWT & SHA-256",
        href: "/soc-tools?tool=decoder",
      },
      {
        id: "soc_cidr",
        label: "SUBNET / CIDR INSPECTOR",
        description: "CALCULATE NETWORK, BROADCAST, ACL WILDCARD & HOST RANGE",
        href: "/soc-tools?tool=cidr",
      },
      {
        id: "soc_siem_query",
        label: "SIEM & SIGMA / YARA BUILDER",
        description: "GENERATE SPLUNK SPL, SENTINEL KQL, ELASTIC, SIGMA & YARA",
        href: "/soc-tools?tool=siem-query",
      },
      {
        id: "soc_playbook",
        label: "INCIDENT TRIAGE PLAYBOOKS",
        description: "PHISHING, C2/RANSOMWARE, INFOSTEALER & MARKDOWN REPORTS",
        href: "/soc-tools?tool=playbook",
      },
    ],
  },
  {
    id: "cve_lookup",
    label: "CVE LOOKUP",
    icon: ShieldAlert,
    items: [
      {
        id: "cve_overview",
        label: "CVE DASHBOARD",
        description: "TOP 10 LATEST CVES, ACTIVE EXPLOITS & TELEMETRY",
        href: "/cve",
      },
      {
        id: "cve_latest",
        label: "TOP 10 LATEST CVES",
        description: "NEWEST PUBLISHED VULNERABILITIES SORTED LATEST FIRST",
        href: "/cve?tab=latest",
      },
      {
        id: "cve_kev",
        label: "ACTIVE EXPLOITS (CISA KEV)",
        description: "CONFIRMED IN-THE-WILD EXPLOITED CVES & RANSOMWARE",
        href: "/cve?tab=kev",
      },
      {
        id: "cve_search",
        label: "CVE SEARCH (LATEST)",
        description: "SEARCH CVE ID OR VENDOR/PRODUCT SORTED LATEST FIRST",
        href: "/cve?tab=search",
      },
    ],
  },
  {
    id: "cyber_news",
    label: "CYBERSECURITY NEWS",
    icon: Newspaper,
    items: [
      {
        id: "news_feed",
        label: "NEWS & ADVISORIES FEED",
        description: "AGGREGATED CYBERSECURITY NEWS & ADVISORY RSS STREAM",
        href: "/news",
      },
      {
        id: "news_rss_cfg",
        label: "RSS FEEDS INTEGRATION",
        description: "ADD, ENABLE OR MANAGE CUSTOM RSS / ATOM SOURCES",
        href: "/settings/rss-feeds",
      },
    ],
  },
  {
    id: "darkweb_monitor",
    label: "DARKWEB MONITOR",
    icon: Skull,
    items: [
      {
        id: "dw_ransomware",
        label: "RANSOMWARE LEAK SITES",
        description: "RECENT EXTORTION VICTIMS FROM TOR LEAK SITES",
        href: "/darkweb",
      },
      {
        id: "dw_credentials",
        label: "CREDENTIAL LEAKS",
        description: "UNCENSORED COMB PAIRS, INFOSTEALERS & BREACH EVIDENCE",
        href: "/darkweb?tab=credentials",
      },
      {
        id: "dw_breaches",
        label: "BREACHES & STEALER LOGS",
        description: "HIBP DATA BREACHES, STEALER LOGS & LEAKED DBS",
        href: "/darkweb?tab=breaches",
      },
      {
        id: "dw_actors",
        label: "GANGS & MARKETS",
        description: "TRACKED RANSOMWARE GROUPS & DARKNET MARKETS",
        href: "/darkweb?tab=actors",
      },
      {
        id: "dw_monitors",
        label: "WATCHLIST MONITORS",
        description: "MONITOR ORG DOMAINS, BRANDS & VIP EMAILS",
        href: "/darkweb?tab=monitors",
      },
    ],
  },
  {
    id: "system_api",
    label: "SYSTEM & API",
    icon: Sliders,
    items: [
      {
        id: "sys_scoring",
        label: "SCORING & WEIGHTS",
        description: "CONFIGURE PROVIDER WEIGHTS, TTLS & THRESHOLDS",
        href: "/settings/scoring",
      },
      {
        id: "sys_byok",
        label: "BYOK & SERVER KEYS",
        description: "MANAGE ENCRYPTED & BROWSER API KEYS",
        href: "/settings/byok",
      },
      {
        id: "sys_rest",
        label: "REST API TOKENS",
        description: "GENERATE EY_ AUTOMATION KEYS FOR SOAR/CLI",
        href: "/settings/api-tokens",
      },
      {
        id: "sys_rss",
        label: "RSS FEEDS INTEGRATION",
        description: "INTEGRATE POPULAR OR CUSTOM CYBERSECURITY RSS FEEDS",
        href: "/settings/rss-feeds",
      },
      {
        id: "sys_watchlist",
        label: "TOOLS WATCHLIST",
        description: "TRACK SECURITY TOOLS PLANNED OR MONITORED",
        href: "/settings/watchlist",
      },
      {
        id: "sys_appearance",
        label: "APPEARANCE & FONTS",
        description: "CUSTOMIZE FONT FAMILY, TEXT CASE, SIZE, CORNERS & BLUR",
        href: "/settings/appearance",
      },
    ],
  },
];

const STANDALONE_TOP_IDS = new Set([
  "cve_lookup",
  "cyber_news",
  "darkweb_monitor",
  "system_api",
]);
const THREAT_TOOL_GROUPS = TOOL_MENU_GROUPS.filter(
  (g) => !STANDALONE_TOP_IDS.has(g.id),
);
const CVE_TOOL_GROUP = TOOL_MENU_GROUPS.find(
  (g) => g.id === "cve_lookup",
)!;
const NEWS_TOOL_GROUP = TOOL_MENU_GROUPS.find(
  (g) => g.id === "cyber_news",
)!;
const DARKWEB_TOOL_GROUP = TOOL_MENU_GROUPS.find(
  (g) => g.id === "darkweb_monitor",
)!;
const SYSTEM_TOOL_GROUP = TOOL_MENU_GROUPS.find(
  (g) => g.id === "system_api",
)!;

const AuthContext = createContext<AuthState>({
  authenticated: false,
  authRequired: true,
  hasUsers: false,
  user: null,
  loading: true,
  refreshAuth: async () => {},
});

const ToolCategoryContext = createContext<{
  selectedCategory: ToolCategoryId;
  setSelectedCategory: (cat: ToolCategoryId) => void;
  selectedTool: ProviderId | null;
  setSelectedTool: (tool: ProviderId | null) => void;
  activeTrail: { group: string; item: string };
  setActiveTrail: (trail: { group: string; item: string }) => void;
}>({
  selectedCategory: "all",
  setSelectedCategory: () => {},
  selectedTool: null,
  setSelectedTool: () => {},
  activeTrail: { group: "IOC INVESTIGATION", item: "IOC LOOKUP" },
  setActiveTrail: () => {},
});

const ThemeContext = createContext<{
  themeId: ThemeId;
  applyTheme: (id: ThemeId) => void;
}>({
  themeId: "obsidian",
  applyTheme: () => {},
});

export function useAuth() {
  return useContext(AuthContext);
}

export function useToolCategory() {
  return useContext(ToolCategoryContext);
}

export function useThemeControl() {
  return useContext(ThemeContext);
}

const MOBILE_DOCK_ITEMS = [
  { href: "/", label: "LOOKUP", icon: Search },
  { href: "/cve", label: "CVE", icon: ShieldAlert },
  { href: "/news", label: "NEWS", icon: Newspaper },
  { href: "/history", label: "HISTORY", icon: History },
  { href: "/settings", label: "SETTINGS", icon: Settings },
];

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const isLoginPage = pathname === "/login";

  const [themeId, setThemeId] = useState<ThemeId>("obsidian");
  const [themeMenuOpen, setThemeMenuOpen] = useState(false);

  const [selectedCategory, setSelectedCategory] = useState<ToolCategoryId>("all");
  const [selectedTool, setSelectedTool] = useState<ProviderId | null>(null);
  const [activeTrail, setActiveTrail] = useState<{
    group: string;
    item: string;
  }>({ group: "IOC INVESTIGATION", item: "IOC LOOKUP" });

  const [openDropdownId, setOpenDropdownId] = useState<string | null>(null);
  const [activeSideGroupId, setActiveSideGroupId] = useState<string>(
    "ioc_investigation",
  );
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [expandedMobileGroup, setExpandedMobileGroup] = useState<string | null>(
    "ioc_investigation",
  );

  const [auth, setAuth] = useState<Omit<AuthState, "refreshAuth">>({
    authenticated: false,
    authRequired: true,
    hasUsers: false,
    user: null,
    loading: true,
  });

  const refreshAuth = async () => {
    try {
      const res = await fetch("/api/auth/me", { cache: "no-store" });
      if (res.ok) {
        const data = await res.json();
        setAuth({
          authenticated: Boolean(data.authenticated),
          authRequired: Boolean(data.authRequired),
          hasUsers: Boolean(data.hasUsers),
          user: data.user ?? null,
          loading: false,
        });
      } else {
        setAuth((prev) => ({ ...prev, loading: false }));
      }
    } catch {
      setAuth((prev) => ({ ...prev, loading: false }));
    }
  };

  const applyTheme = (id: ThemeId) => {
    setThemeId(id);
    const meta = THEME_OPTIONS.find((t) => t.id === id);
    document.documentElement.setAttribute("data-theme", id);
    document.documentElement.classList.toggle("dark", !meta?.isLight);
    window.localStorage.setItem("eyesight_theme_id", id);
  };

  useEffect(() => {
    const saved = window.localStorage.getItem("eyesight_theme_id") as ThemeId | null;
    const valid = THEME_OPTIONS.some((t) => t.id === saved);
    applyTheme(valid && saved ? saved : "obsidian");
    applyUiPreferences(loadUiPreferences());
    refreshAuth();
  }, []);

  // Sync trail on route changes
  useEffect(() => {
    if (pathname === "/bulk") {
      setActiveTrail({ group: "IOC INVESTIGATION", item: "BULK IOC QUEUE" });
      setSelectedCategory("all");
      setSelectedTool(null);
    } else if (pathname === "/history") {
      setActiveTrail({
        group: "INVESTIGATION HISTORY",
        item: "AUDIT LOG",
      });
      setSelectedCategory("all");
      setSelectedTool(null);
    } else if (pathname === "/cve") {
      setActiveTrail({ group: "CVE LOOKUP", item: "CVE DASHBOARD" });
    } else if (pathname === "/news") {
      setActiveTrail({ group: "CYBERSECURITY NEWS", item: "NEWS & ADVISORIES" });
    } else if (pathname === "/darkweb") {
      setActiveTrail({ group: "DARKWEB MONITOR", item: "RANSOMWARE LEAK SITES" });
    } else if (pathname === "/settings" || pathname === "/settings/scoring") {
      setActiveTrail({ group: "SYSTEM & API", item: "SCORING & WEIGHTS" });
    } else if (pathname === "/settings/byok") {
      setActiveTrail({ group: "SYSTEM & API", item: "BYOK & SERVER KEYS" });
    } else if (pathname === "/settings/api-tokens") {
      setActiveTrail({ group: "SYSTEM & API", item: "REST API TOKENS" });
    } else if (pathname === "/settings/rss-feeds") {
      setActiveTrail({ group: "SYSTEM & API", item: "RSS FEEDS INTEGRATION" });
    } else if (pathname === "/settings/watchlist") {
      setActiveTrail({ group: "SYSTEM & API", item: "TOOLS WATCHLIST" });
    } else if (pathname === "/settings/appearance") {
      setActiveTrail({ group: "SYSTEM & API", item: "APPEARANCE & FONTS" });
    } else if (pathname === "/" && selectedCategory === "all" && !selectedTool) {
      setActiveTrail({ group: "IOC INVESTIGATION", item: "IOC LOOKUP" });
    }
  }, [pathname, selectedCategory, selectedTool]);

  // Enforce login portal redirect whenever authRequired & unauthenticated
  const needsPortalRedirect =
    !auth.loading && auth.authRequired && !auth.authenticated && !isLoginPage;

  useEffect(() => {
    if (needsPortalRedirect) {
      const target =
        pathname && pathname !== "/"
          ? `/login?next=${encodeURIComponent(pathname)}`
          : "/login";
      router.replace(target);
    }
  }, [needsPortalRedirect, pathname, router]);

  const handleLogout = async () => {
    await fetch("/api/auth/logout", { method: "POST" });
    setSelectedCategory("all");
    setSelectedTool(null);
    setActiveTrail({ group: "IOC INVESTIGATION", item: "IOC LOOKUP" });
    await refreshAuth();
    router.replace("/login");
  };

  const handleMenuItemClick = (group: MenuGroup, item: MenuChildItem) => {
    setActiveTrail({ group: group.label, item: item.label });
    if (item.category !== undefined) {
      setSelectedCategory(item.category);
    }
    if (item.tool !== undefined) {
      setSelectedTool(item.tool);
    } else {
      setSelectedTool(null);
    }
    setOpenDropdownId(null);
    setMobileMenuOpen(false);
    router.push(item.href);
  };

  const activeTheme =
    THEME_OPTIONS.find((t) => t.id === themeId) || THEME_OPTIONS[0];

  const themePicker = (
    <div className="relative">
      <button
        type="button"
        onClick={() => setThemeMenuOpen((v) => !v)}
        className="flex items-center gap-1.5 px-2.5 sm:px-3 py-1.5 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-elevated)] hover:border-[var(--accent-border)] text-[11px] font-semibold transition cursor-pointer"
        aria-label="Select theme"
      >
        <span
          className="w-2.5 h-2.5 rounded-full shrink-0"
          style={{ backgroundColor: activeTheme.swatch }}
        />
        <Palette className="w-3.5 h-3.5 text-[var(--text-secondary)] sm:hidden" />
        <span className="hidden sm:inline">{activeTheme.name}</span>
        <ChevronDown className="w-3 h-3 text-[var(--text-secondary)]" />
      </button>

      {themeMenuOpen && (
        <>
          <div
            className="fixed inset-0 z-40"
            onClick={() => setThemeMenuOpen(false)}
          />
          <div className="absolute right-0 mt-2 w-56 z-50 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-surface-solid)] shadow-2xl p-1.5 space-y-0.5">
            <div className="px-2.5 py-1.5 text-[10px] font-bold tracking-widest text-[var(--text-secondary)]">
              SELECT CONSOLE THEME
            </div>
            {THEME_OPTIONS.map((opt) => {
              const selected = opt.id === themeId;
              return (
                <button
                  key={opt.id}
                  type="button"
                  onClick={() => {
                    applyTheme(opt.id);
                    setThemeMenuOpen(false);
                  }}
                  className="w-full flex items-center justify-between gap-2 px-2.5 py-2 rounded-lg text-xs font-semibold hover:bg-[var(--bg-elevated)] transition cursor-pointer"
                  style={
                    selected
                      ? {
                          backgroundColor: "var(--accent-soft)",
                          color: "var(--accent)",
                        }
                      : undefined
                  }
                >
                  <span className="flex items-center gap-2">
                    <span
                      className="w-3 h-3 rounded-full border border-white/20"
                      style={{ backgroundColor: opt.swatch }}
                    />
                    {opt.name}
                  </span>
                  {selected && <Check className="w-3.5 h-3.5" />}
                </button>
              );
            })}
          </div>
        </>
      )}
    </div>
  );

  return (
    <AuthContext.Provider value={{ ...auth, refreshAuth }}>
      <ThemeContext.Provider value={{ themeId, applyTheme }}>
        <ToolCategoryContext.Provider
          value={{
            selectedCategory,
            setSelectedCategory,
            selectedTool,
            setSelectedTool,
            activeTrail,
            setActiveTrail,
          }}
        >
        <div className="min-h-screen w-full flex flex-col bg-transparent text-[var(--text-primary)]">
          {/* Dedicated Portal Header on /login */}
          {isLoginPage ? (
            <header className="w-full border-b border-[var(--border-subtle)] bg-[var(--bg-surface)] backdrop-blur-xl">
              <div className="w-full px-4 sm:px-6 lg:px-8 h-14 flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <span
                    className="h-8 w-8 rounded-xl flex items-center justify-center"
                    style={{
                      backgroundColor: "var(--accent-soft)",
                      border: "1px solid var(--accent-border)",
                      color: "var(--accent)",
                    }}
                  >
                    <svg
                      viewBox="0 0 24 24"
                      className="w-4.5 h-4.5"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="2"
                    >
                      <path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z" />
                      <circle cx="12" cy="12" r="3" />
                    </svg>
                  </span>
                  <span className="font-extrabold tracking-widest text-sm">
                    EYESIGHT PORTAL
                  </span>
                </div>
                {themePicker}
              </div>
            </header>
          ) : (
            /* Full Workspace Header + Hierarchical Dropdown Menu Bar */
            <header className="sticky top-0 z-40 w-full border-b border-[var(--border-subtle)] bg-[var(--bg-surface)] backdrop-blur-xl">
              <div className="w-full px-3 sm:px-6 lg:px-8 h-14 flex items-center justify-between gap-3">
                <div className="flex items-center gap-3 min-w-0">
                  <button
                    type="button"
                    onClick={() => setMobileMenuOpen((v) => !v)}
                    className="lg:hidden p-2 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-[var(--text-primary)] cursor-pointer"
                    aria-label="Open classification menu"
                  >
                    {mobileMenuOpen ? (
                      <X className="w-4 h-4" />
                    ) : (
                      <Menu className="w-4 h-4" />
                    )}
                  </button>

                  <Link
                    href="/"
                    onClick={() => {
                      setSelectedCategory("all");
                      setSelectedTool(null);
                      setActiveTrail({
                        group: "IOC INVESTIGATION",
                        item: "IOC LOOKUP",
                      });
                    }}
                    className="flex items-center gap-2.5 group focus:outline-none shrink-0"
                  >
                    <span
                      className="h-9 w-9 rounded-xl flex items-center justify-center transition shadow-sm"
                      style={{
                        backgroundColor: "var(--accent-soft)",
                        border: "1px solid var(--accent-border)",
                        color: "var(--accent)",
                      }}
                    >
                      <svg
                        viewBox="0 0 24 24"
                        className="w-5 h-5"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="2"
                      >
                        <path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z" />
                        <circle cx="12" cy="12" r="3" />
                      </svg>
                    </span>
                    <div className="flex items-center gap-2">
                      <span className="font-extrabold tracking-wider text-base sm:text-lg">
                        EYESIGHT
                      </span>
                      <span
                        className="hidden sm:inline text-[10px] font-bold tracking-widest px-2 py-0.5 rounded-md"
                        style={{
                          backgroundColor: "var(--accent-soft)",
                          border: "1px solid var(--accent-border)",
                          color: "var(--accent)",
                        }}
                      >
                        THREAT OSINT
                      </span>
                    </div>
                  </Link>
                </div>

                {/* Right Controls: History Icon + Theme + Auth */}
                <div className="flex items-center gap-2 shrink-0">
                  <Link
                    href="/history"
                    title="INVESTIGATION HISTORY"
                    aria-label="Investigation History"
                    onClick={() => {
                      setOpenDropdownId(null);
                      setActiveTrail({
                        group: "INVESTIGATION HISTORY",
                        item: "AUDIT LOG",
                      });
                    }}
                    style={
                      pathname === "/history"
                        ? {
                            backgroundColor: "var(--accent-soft)",
                            borderColor: "var(--accent-border)",
                            color: "var(--accent)",
                          }
                        : undefined
                    }
                    className={`p-2 rounded-lg border transition ${
                      pathname === "/history"
                        ? ""
                        : "border-[var(--border-subtle)] bg-[var(--bg-elevated)] hover:border-[var(--accent-border)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
                    }`}
                  >
                    <History className="w-4 h-4" />
                  </Link>
                  {themePicker}

                  {auth.user ? (
                    <div className="flex items-center gap-2">
                      <div className="hidden md:flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-[11px] font-semibold">
                        <User
                          className="w-3.5 h-3.5"
                          style={{ color: "var(--accent)" }}
                        />
                        <span>{auth.user.name}</span>
                        <span
                          className="text-[9px] px-1.5 py-0.5 rounded font-bold"
                          style={{
                            backgroundColor: "var(--accent-soft)",
                            color: "var(--accent)",
                          }}
                        >
                          {auth.user.role}
                        </span>
                      </div>
                      <button
                        type="button"
                        onClick={handleLogout}
                        className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[11px] font-semibold border border-[var(--border-subtle)] bg-[var(--bg-elevated)] hover:border-rose-500/40 transition cursor-pointer"
                      >
                        <LogOut className="w-3.5 h-3.5" />
                        <span className="hidden sm:inline">SIGN OUT</span>
                      </button>
                    </div>
                  ) : (
                    <Link
                      href="/login"
                      style={{ backgroundColor: "var(--accent)" }}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-bold text-white hover:opacity-90 transition shadow-sm"
                    >
                      <LogIn className="w-3.5 h-3.5" />
                      <span>LOGIN PORTAL</span>
                    </Link>
                  )}
                </div>
              </div>

              {/* Desktop Unified Menu Bar with Cascading Side-Dropdown */}
              <div className="hidden lg:block w-full border-t border-[var(--border-subtle)] bg-[var(--bg-elevated)]/70">
                <div className="w-full px-6 lg:px-8 h-11 flex items-center justify-between gap-4">
                  <nav className="flex items-center gap-1.5">
                    {/* Single Unified Tools & Investigation Cascading Side-Menu Dropdown */}
                    <div
                      className="relative"
                      onMouseEnter={() => {
                        setOpenDropdownId("unified_tools");
                        const matched = THREAT_TOOL_GROUPS.find(
                          (g) => g.label === activeTrail.group,
                        );
                        if (matched) setActiveSideGroupId(matched.id);
                      }}
                      onMouseLeave={() => setOpenDropdownId(null)}
                    >
                      <button
                        type="button"
                        onClick={() => setOpenDropdownId("unified_tools")}
                        style={
                          THREAT_TOOL_GROUPS.some(
                            (g) => g.label === activeTrail.group,
                          ) || openDropdownId === "unified_tools"
                            ? {
                                backgroundColor: "var(--accent-soft)",
                                borderColor: "var(--accent-border)",
                                color: "var(--accent)",
                              }
                            : undefined
                        }
                        className={`inline-flex items-center gap-2 px-3.5 py-1.5 rounded-lg border text-[11px] font-bold transition cursor-pointer ${
                          THREAT_TOOL_GROUPS.some(
                            (g) => g.label === activeTrail.group,
                          ) || openDropdownId === "unified_tools"
                            ? ""
                            : "border-transparent text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-surface)]/70"
                        }`}
                      >
                        <Layers className="w-3.5 h-3.5" />
                        <span>TOOLS &amp; INVESTIGATION</span>
                        <ChevronDown
                          className={`w-3 h-3 transition-transform ${
                            openDropdownId === "unified_tools" ? "rotate-180" : ""
                          }`}
                        />
                      </button>

                      {openDropdownId === "unified_tools" && (
                        <div className="absolute left-0 top-full pt-1.5 z-50">
                          <div className="flex rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-surface-solid)] shadow-2xl overflow-hidden">
                            {/* Left Classification Column */}
                            <div className="w-60 p-2 border-r border-[var(--border-subtle)] bg-[var(--bg-elevated)]/55 space-y-1">
                              <div className="px-2.5 py-1 text-[9px] font-extrabold tracking-widest text-[var(--text-secondary)]">
                                CLASSIFICATIONS
                              </div>
                              {THREAT_TOOL_GROUPS.map((group) => {
                                const Icon = group.icon;
                                const isSideActive =
                                  activeSideGroupId === group.id;
                                return (
                                  <button
                                    key={group.id}
                                    type="button"
                                    onMouseEnter={() =>
                                      setActiveSideGroupId(group.id)
                                    }
                                    onClick={() =>
                                      setActiveSideGroupId(group.id)
                                    }
                                    style={
                                      isSideActive
                                        ? {
                                            backgroundColor:
                                              "var(--accent-soft)",
                                            borderColor: "var(--accent-border)",
                                            color: "var(--accent)",
                                          }
                                        : undefined
                                    }
                                    className={`w-full flex items-center justify-between gap-2 px-3 py-2.5 rounded-xl border text-[11px] font-bold transition cursor-pointer ${
                                      isSideActive
                                        ? ""
                                        : "border-transparent text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-surface)]/60"
                                    }`}
                                  >
                                    <span className="flex items-center gap-2 truncate">
                                      <Icon className="w-3.5 h-3.5 shrink-0" />
                                      <span className="truncate">
                                        {group.label}
                                      </span>
                                    </span>
                                    <ChevronRight className="w-3.5 h-3.5 shrink-0" />
                                  </button>
                                );
                              })}
                            </div>

                            {/* Right Side-Menu Sub-Tools Flyout */}
                            <div className="w-80 p-2.5 space-y-1 bg-[var(--bg-surface-solid)]">
                              {(() => {
                                const currentGroup =
                                  THREAT_TOOL_GROUPS.find(
                                    (g) => g.id === activeSideGroupId,
                                  ) || THREAT_TOOL_GROUPS[0];
                                return (
                                  <>
                                    <div className="px-2.5 py-1 text-[9px] font-extrabold tracking-widest text-[var(--text-secondary)] flex items-center justify-between">
                                      <span>{currentGroup.label}</span>
                                      <span className="font-mono-ioc">
                                        {currentGroup.items.length} OPTIONS
                                      </span>
                                    </div>
                                    {currentGroup.items.map((item) => {
                                      const isSelected =
                                        activeTrail.group ===
                                          currentGroup.label &&
                                        activeTrail.item === item.label;
                                      return (
                                        <button
                                          key={item.id}
                                          type="button"
                                          onClick={() =>
                                            handleMenuItemClick(
                                              currentGroup,
                                              item,
                                            )
                                          }
                                          style={
                                            isSelected
                                              ? {
                                                  backgroundColor:
                                                    "var(--accent-soft)",
                                                  color: "var(--accent)",
                                                }
                                              : undefined
                                          }
                                          className="w-full text-left px-3 py-2.5 rounded-xl hover:bg-[var(--bg-elevated)] transition cursor-pointer flex items-start justify-between gap-2"
                                        >
                                          <div>
                                            <div className="text-[11px] font-bold flex items-center gap-1.5">
                                              <ChevronRight className="w-3 h-3 opacity-75" />
                                              {item.label}
                                            </div>
                                            <div className="text-[9px] text-[var(--text-secondary)] pl-4 mt-0.5 leading-relaxed">
                                              {item.description}
                                            </div>
                                          </div>
                                          {isSelected && (
                                            <Check className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                                          )}
                                        </button>
                                      );
                                    })}
                                  </>
                                );
                              })()}
                            </div>
                          </div>
                        </div>
                      )}
                    </div>

                    {/* CVE Lookup, Cybersecurity News, Darkweb Monitor & System & API Dropdowns */}
                    {[
                      CVE_TOOL_GROUP,
                      NEWS_TOOL_GROUP,
                      DARKWEB_TOOL_GROUP,
                      SYSTEM_TOOL_GROUP,
                    ].map((group) => {
                      const GroupIcon = group.icon;
                      const isOpen = openDropdownId === group.id;
                      const isActive = activeTrail.group === group.label;
                      return (
                        <div
                          key={group.id}
                          className="relative"
                          onMouseEnter={() => setOpenDropdownId(group.id)}
                          onMouseLeave={() => setOpenDropdownId(null)}
                        >
                          <button
                            type="button"
                            onClick={() => setOpenDropdownId(group.id)}
                            style={
                              isActive || isOpen
                                ? {
                                    backgroundColor: "var(--accent-soft)",
                                    borderColor: "var(--accent-border)",
                                    color: "var(--accent)",
                                  }
                                : undefined
                            }
                            className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-[11px] font-bold transition cursor-pointer ${
                              isActive || isOpen
                                ? ""
                                : "border-transparent text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-surface)]/70"
                            }`}
                          >
                            <GroupIcon className="w-3.5 h-3.5" />
                            <span>{group.label}</span>
                            <ChevronDown
                              className={`w-3 h-3 transition-transform ${
                                isOpen ? "rotate-180" : ""
                              }`}
                            />
                          </button>

                          {isOpen && (
                            <div className="absolute left-0 top-full pt-1.5 z-50 w-76">
                              <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-surface-solid)] shadow-2xl p-1.5 space-y-0.5">
                                <div className="px-2.5 py-1 text-[9px] font-extrabold tracking-widest text-[var(--text-secondary)]">
                                  {group.label}
                                </div>
                                {group.items.map((item) => {
                                  const isSelected =
                                    activeTrail.group === group.label &&
                                    activeTrail.item === item.label;
                                  return (
                                    <button
                                      key={item.id}
                                      type="button"
                                      onClick={() =>
                                        handleMenuItemClick(group, item)
                                      }
                                      style={
                                        isSelected
                                          ? {
                                              backgroundColor:
                                                "var(--accent-soft)",
                                              color: "var(--accent)",
                                            }
                                          : undefined
                                      }
                                      className="w-full text-left px-3 py-2 rounded-lg hover:bg-[var(--bg-elevated)] transition cursor-pointer flex items-start justify-between gap-2"
                                    >
                                      <div>
                                        <div className="text-[11px] font-bold flex items-center gap-1.5">
                                          <ChevronRight className="w-3 h-3 opacity-70" />
                                          {item.label}
                                        </div>
                                        <div className="text-[9px] text-[var(--text-secondary)] pl-4 mt-0.5">
                                          {item.description}
                                        </div>
                                      </div>
                                      {isSelected && (
                                        <Check className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                                      )}
                                    </button>
                                  );
                                })}
                              </div>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </nav>

                  {/* Active Classification Breadcrumb Trail */}
                  <div className="flex items-center gap-1.5 text-[10px] font-bold tracking-wider text-[var(--text-secondary)] shrink-0">
                    <span>{activeTrail.group}</span>
                    <ChevronRight className="w-3 h-3" />
                    <span style={{ color: "var(--accent)" }}>
                      {activeTrail.item}
                    </span>
                  </div>
                </div>
              </div>

              {/* Mobile Breadcrumb Strip (< lg) */}
              <div className="lg:hidden w-full border-t border-[var(--border-subtle)] bg-[var(--bg-elevated)]/60 px-3 sm:px-6 h-9 flex items-center justify-between text-[10px] font-bold">
                <div className="flex items-center gap-1.5 truncate">
                  <span className="text-[var(--text-secondary)] truncate">
                    {activeTrail.group}
                  </span>
                  <ChevronRight className="w-3 h-3 shrink-0" />
                  <span className="truncate" style={{ color: "var(--accent)" }}>
                    {activeTrail.item}
                  </span>
                </div>
                <button
                  type="button"
                  onClick={() => setMobileMenuOpen(true)}
                  style={{ color: "var(--accent)" }}
                  className="shrink-0 underline cursor-pointer"
                >
                  SWITCH TOOL
                </button>
              </div>

              {/* Mobile Hierarchical Accordion Dropdown Drawer */}
              {mobileMenuOpen && (
                <div className="lg:hidden border-t border-[var(--border-subtle)] bg-[var(--bg-surface-solid)] max-h-[75vh] overflow-y-auto px-3 py-3 space-y-2 shadow-2xl">
                  {TOOL_MENU_GROUPS.map((group) => {
                    const Icon = group.icon;
                    const expanded = expandedMobileGroup === group.id;
                    return (
                      <div
                        key={group.id}
                        className="rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/55 overflow-hidden"
                      >
                        <button
                          type="button"
                          onClick={() =>
                            setExpandedMobileGroup(expanded ? null : group.id)
                          }
                          className="w-full px-3.5 py-2.5 flex items-center justify-between text-xs font-bold cursor-pointer"
                        >
                          <span className="flex items-center gap-2">
                            <Icon className="w-3.5 h-3.5" />
                            {group.label}
                          </span>
                          <ChevronDown
                            className={`w-3.5 h-3.5 transition-transform ${
                              expanded ? "rotate-180" : ""
                            }`}
                          />
                        </button>
                        {expanded && (
                          <div className="border-t border-[var(--border-subtle)] p-1.5 space-y-1">
                            {group.items.map((item) => (
                              <button
                                key={item.id}
                                type="button"
                                onClick={() => handleMenuItemClick(group, item)}
                                className="w-full text-left px-3 py-2 rounded-lg hover:bg-[var(--bg-surface)] text-[11px] font-bold flex items-center justify-between gap-2 cursor-pointer"
                              >
                                <div>
                                  <div className="flex items-center gap-1.5">
                                    <ChevronRight
                                      className="w-3 h-3"
                                      style={{ color: "var(--accent)" }}
                                    />
                                    {item.label}
                                  </div>
                                  <div className="text-[9px] text-[var(--text-secondary)] pl-4 mt-0.5">
                                    {item.description}
                                  </div>
                                </div>
                              </button>
                            ))}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </header>
          )}

          {/* Full-Width Adaptive Main Workspace */}
          <main
            className={`flex-1 w-full px-3 sm:px-6 lg:px-8 py-5 sm:py-6 ${
              isLoginPage ? "" : "pb-24 md:pb-8"
            }`}
          >
            {needsPortalRedirect || (auth.loading && !isLoginPage) ? (
              <div className="min-h-[60vh] flex items-center justify-center">
                <div className="flex items-center gap-2 text-xs font-bold text-[var(--text-secondary)]">
                  <Loader2
                    className="w-5 h-5 animate-spin"
                    style={{ color: "var(--accent)" }}
                  />
                  VERIFYING SESSION...
                </div>
              </div>
            ) : (
              children
            )}
          </main>

          {/* Adaptive Mobile Bottom Dock Navigation (< md, hidden on /login) */}
          {!isLoginPage && !needsPortalRedirect && (
            <nav className="md:hidden fixed bottom-0 inset-x-0 z-40 border-t border-[var(--border-subtle)] bg-[var(--bg-surface-solid)]/95 backdrop-blur-xl px-2 py-1.5 grid grid-cols-5 gap-1">
              {MOBILE_DOCK_ITEMS.map((item) => {
                const active =
                  item.href === "/"
                    ? pathname === "/"
                    : pathname.startsWith(item.href);
                const Icon = item.icon;
                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    style={
                      active
                        ? {
                            backgroundColor: "var(--accent-soft)",
                            color: "var(--accent)",
                          }
                        : undefined
                    }
                    className={`flex flex-col items-center justify-center py-1.5 rounded-xl text-[9px] font-bold tracking-wider transition ${
                      active ? "" : "text-[var(--text-secondary)]"
                    }`}
                  >
                    <Icon className="w-4 h-4 mb-0.5" />
                    <span>{item.label}</span>
                  </Link>
                );
              })}
            </nav>
          )}
        </div>
        </ToolCategoryContext.Provider>
      </ThemeContext.Provider>
    </AuthContext.Provider>
  );
}
