"use client";

import { SettingsShell } from "@/components/settings/SettingsShell";
import { ScoringSection } from "@/components/settings/ScoringSection";

export default function ScoringSettingsPage() {
  return (
    <SettingsShell
      title="SCORING & PROVIDER WEIGHTS"
      subtitle="CONFIGURE COMPOSITE VERDICT THRESHOLDS, PER-PROVIDER WEIGHTS, CACHE TTLS, AND SERVER API KEYS."
    >
      <ScoringSection />
    </SettingsShell>
  );
}
