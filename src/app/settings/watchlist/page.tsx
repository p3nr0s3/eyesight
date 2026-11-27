"use client";

import { SettingsShell } from "@/components/settings/SettingsShell";
import { WatchlistSection } from "@/components/settings/WatchlistSection";

export default function WatchlistSettingsPage() {
  return (
    <SettingsShell
      title="SECURITY TOOLS WATCHLIST"
      subtitle="TRACK EXTERNAL THREAT INTEL, OSINT, DFIR, AND SCANNING TOOLS MONITORED OR PLANNED BY YOUR TEAM."
    >
      <WatchlistSection />
    </SettingsShell>
  );
}
