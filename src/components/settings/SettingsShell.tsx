"use client";

import React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Sliders, KeyRound, Terminal, Rss, Bookmark, Palette } from "lucide-react";

const SETTINGS_TABS = [
  { href: "/settings/scoring", label: "SCORING & WEIGHTS", icon: Sliders },
  { href: "/settings/byok", label: "BYOK KEYS", icon: KeyRound },
  { href: "/settings/api-tokens", label: "REST API TOKENS", icon: Terminal },
  { href: "/settings/rss-feeds", label: "RSS FEEDS", icon: Rss },
  { href: "/settings/watchlist", label: "TOOLS WATCHLIST", icon: Bookmark },
  { href: "/settings/appearance", label: "APPEARANCE & FONTS", icon: Palette },
];

export function SettingsShell({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle: string;
  children: React.ReactNode;
}) {
  const pathname = usePathname();

  return (
    <div className="space-y-6 w-full">
      <div className="space-y-3">
        <div>
          <h1 className="text-xl sm:text-2xl font-extrabold tracking-tight">
            {title}
          </h1>
          <p className="text-xs sm:text-sm text-[var(--text-secondary)] mt-1">
            {subtitle}
          </p>
        </div>

        <div className="flex items-center gap-1.5 overflow-x-auto no-scrollbar border-b border-[var(--border-subtle)] pb-2">
          {SETTINGS_TABS.map((t) => {
            const Icon = t.icon;
            const active =
              pathname === t.href ||
              (pathname === "/settings" && t.href === "/settings/scoring");
            return (
              <Link
                key={t.href}
                href={t.href}
                style={
                  active
                    ? {
                        backgroundColor: "var(--accent-soft)",
                        borderColor: "var(--accent-border)",
                        color: "var(--accent)",
                      }
                    : undefined
                }
                className={`inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl border text-xs font-bold whitespace-nowrap transition ${
                  active
                    ? ""
                    : "border-[var(--border-subtle)] bg-[var(--bg-surface)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                {t.label}
              </Link>
            );
          })}
        </div>
      </div>

      {children}
    </div>
  );
}
