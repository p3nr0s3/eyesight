"use client";

import { SettingsShell } from "@/components/settings/SettingsShell";
import { AppearanceSection } from "@/components/settings/AppearanceSection";

export default function AppearanceSettingsPage() {
  return (
    <SettingsShell
      title="APPEARANCE, FONTS & CUSTOMIZATION"
      subtitle="CUSTOMIZE FONT FAMILY, TEXT CASE, FONT SCALE, LETTER SPACING, CORNERS, BLUR, AND CONSOLE THEME."
    >
      <AppearanceSection />
    </SettingsShell>
  );
}
