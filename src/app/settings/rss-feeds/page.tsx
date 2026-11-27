"use client";

import { SettingsShell } from "@/components/settings/SettingsShell";
import { RssFeedsSection } from "@/components/settings/RssFeedsSection";

export default function RssFeedsSettingsPage() {
  return (
    <SettingsShell
      title="RSS FEEDS INTEGRATION"
      subtitle="INTEGRATE POPULAR CYBERSECURITY RSS FEEDS IN ONE CLICK OR ADD CUSTOM FEEDS FOR CYBERSECURITY NEWS."
    >
      <RssFeedsSection />
    </SettingsShell>
  );
}
