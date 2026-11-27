export type UiFontId = "inter" | "jetbrains" | "space" | "ibm" | "system";
export type UiTextCase = "uppercase" | "normal";
export type UiFontSize = "compact" | "default" | "large";
export type UiLetterSpacing = "tight" | "normal" | "wide";
export type UiCornerStyle = "sharp" | "rounded" | "ultra";
export type UiDensity = "compact" | "comfortable";

export interface UiPreferences {
  fontFamily: UiFontId;
  textCase: UiTextCase;
  fontSize: UiFontSize;
  letterSpacing: UiLetterSpacing;
  cornerStyle: UiCornerStyle;
  glassBlur: boolean;
  ambientGlow: boolean;
  density: UiDensity;
}

export const DEFAULT_UI_PREFERENCES: UiPreferences = {
  fontFamily: "inter",
  textCase: "uppercase",
  fontSize: "default",
  letterSpacing: "normal",
  cornerStyle: "rounded",
  glassBlur: true,
  ambientGlow: true,
  density: "comfortable",
};

const STORAGE_KEY = "eyesight_ui_preferences";

export const FONT_OPTIONS: Array<{
  id: UiFontId;
  label: string;
  sample: string;
  cssValue: string;
}> = [
  {
    id: "inter",
    label: "INTER (MODERN SANS)",
    sample: "CLEAN SOC INTERFACE & HIGH LEGIBILITY",
    cssValue: 'var(--font-inter), ui-sans-serif, system-ui, sans-serif',
  },
  {
    id: "jetbrains",
    label: "JETBRAINS MONO (TERMINAL)",
    sample: "TACTICAL CYBER MONOSPACE TYPOGRAPHY",
    cssValue: 'var(--font-jetbrains), ui-monospace, monospace',
  },
  {
    id: "space",
    label: "SPACE GROTESK (FUTURISTIC)",
    sample: "GEOMETRIC MODERN SECURITY CONSOLE",
    cssValue: 'var(--font-space), ui-sans-serif, system-ui, sans-serif',
  },
  {
    id: "ibm",
    label: "IBM PLEX SANS (ENTERPRISE)",
    sample: "PRECISION TECHNICAL ANALYST WORKBENCH",
    cssValue: 'var(--font-ibm), ui-sans-serif, system-ui, sans-serif',
  },
  {
    id: "system",
    label: "SYSTEM NATIVE",
    sample: "DEFAULT OPERATING SYSTEM FONT",
    cssValue:
      'system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
  },
];

export function loadUiPreferences(): UiPreferences {
  if (typeof window === "undefined") return DEFAULT_UI_PREFERENCES;
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return DEFAULT_UI_PREFERENCES;
    const parsed = JSON.parse(raw) as Partial<UiPreferences>;
    return {
      ...DEFAULT_UI_PREFERENCES,
      ...parsed,
    };
  } catch {
    return DEFAULT_UI_PREFERENCES;
  }
}

export function saveUiPreferences(prefs: UiPreferences): void {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(STORAGE_KEY, JSON.stringify(prefs));
  applyUiPreferences(prefs);
}

export function applyUiPreferences(prefs: UiPreferences): void {
  if (typeof document === "undefined") return;
  const root = document.documentElement;

  const fontMeta =
    FONT_OPTIONS.find((f) => f.id === prefs.fontFamily) || FONT_OPTIONS[0];
  root.style.setProperty("--ui-font-sans", fontMeta.cssValue);

  root.style.setProperty(
    "--ui-text-transform",
    prefs.textCase === "normal" ? "none" : "uppercase",
  );

  const fontSizeMap: Record<UiFontSize, string> = {
    compact: "14px",
    default: "16px",
    large: "17.5px",
  };
  root.style.setProperty("--ui-root-size", fontSizeMap[prefs.fontSize] || "16px");

  const spacingMap: Record<UiLetterSpacing, string> = {
    tight: "0em",
    normal: "0.025em",
    wide: "0.06em",
  };
  root.style.setProperty(
    "--ui-letter-spacing",
    spacingMap[prefs.letterSpacing] || "0.025em",
  );

  const radiusMap: Record<UiCornerStyle, string> = {
    sharp: "4px",
    rounded: "16px",
    ultra: "24px",
  };
  root.style.setProperty(
    "--ui-radius-card",
    radiusMap[prefs.cornerStyle] || "16px",
  );

  root.style.setProperty("--ui-blur", prefs.glassBlur ? "18px" : "0px");
  root.setAttribute("data-glow", prefs.ambientGlow ? "on" : "off");
  root.setAttribute("data-density", prefs.density);
}
