"use client";

import { SettingsShell } from "@/components/settings/SettingsShell";
import { ApiTokensSection } from "@/components/settings/ApiTokensSection";

export default function ApiTokensSettingsPage() {
  return (
    <SettingsShell
      title="REST API TOKENS"
      subtitle="GENERATE AND REVOKE EY_ AUTOMATION TOKENS FOR CLI, SOAR, AND CI/CD INTEGRATIONS."
    >
      <ApiTokensSection />
    </SettingsShell>
  );
}
