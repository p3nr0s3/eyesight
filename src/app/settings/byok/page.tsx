"use client";

import { SettingsShell } from "@/components/settings/SettingsShell";
import { ByokSection } from "@/components/settings/ByokSection";

export default function ByokSettingsPage() {
  return (
    <SettingsShell
      title="BYOK & PERSONAL API KEYS"
      subtitle="MANAGE BROWSER-LOCAL OR ENCRYPTED DATABASE PROFILE API KEY OVERRIDES."
    >
      <ByokSection />
    </SettingsShell>
  );
}
