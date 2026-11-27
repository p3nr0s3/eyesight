"use client";

import React, { useEffect, useState } from "react";
import {
  Type,
  Palette,
  RotateCcw,
  Check,
  Sparkles,
  SlidersHorizontal,
} from "lucide-react";
import { THEME_OPTIONS, useThemeControl } from "@/components/AppShell";
import {
  DEFAULT_UI_PREFERENCES,
  FONT_OPTIONS,
  applyUiPreferences,
  loadUiPreferences,
  saveUiPreferences,
  type UiCornerStyle,
  type UiDensity,
  type UiFontSize,
  type UiLetterSpacing,
  type UiPreferences,
  type UiTextCase,
} from "@/lib/ui-preferences";

export function AppearanceSection() {
  const { themeId, applyTheme } = useThemeControl();
  const [prefs, setPrefs] = useState<UiPreferences>(DEFAULT_UI_PREFERENCES);
  const [savedNotice, setSavedNotice] = useState(false);

  useEffect(() => {
    const loaded = loadUiPreferences();
    setPrefs(loaded);
  }, []);

  const updatePrefs = (patch: Partial<UiPreferences>) => {
    const next = { ...prefs, ...patch };
    setPrefs(next);
    saveUiPreferences(next);
    setSavedNotice(true);
    setTimeout(() => setSavedNotice(false), 1200);
  };

  const resetDefaults = () => {
    setPrefs(DEFAULT_UI_PREFERENCES);
    saveUiPreferences(DEFAULT_UI_PREFERENCES);
    applyUiPreferences(DEFAULT_UI_PREFERENCES);
    applyTheme("obsidian");
    setSavedNotice(true);
    setTimeout(() => setSavedNotice(false), 1200);
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="text-xs font-bold text-[var(--text-secondary)]">
          ALL CHANGES APPLY LIVE AND SAVE AUTOMATICALLY TO THIS BROWSER.
        </div>
        <div className="flex items-center gap-2">
          {savedNotice && (
            <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 text-[10px] font-bold">
              <Check className="w-3 h-3" /> APPLIED
            </span>
          )}
          <button
            type="button"
            onClick={resetDefaults}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] hover:border-[var(--accent-border)] text-xs font-bold cursor-pointer"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            RESET DEFAULTS
          </button>
        </div>
      </div>

      {/* Console Theme Picker */}
      <section className="rounded-2xl glass-panel p-4 sm:p-6 space-y-4">
        <div className="flex items-center gap-2">
          <Palette className="w-4 h-4" style={{ color: "var(--accent)" }} />
          <h2 className="text-sm sm:text-base font-bold">CONSOLE THEME</h2>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
          {THEME_OPTIONS.map((t) => {
            const active = t.id === themeId;
            return (
              <button
                key={t.id}
                type="button"
                onClick={() => applyTheme(t.id)}
                style={
                  active
                    ? {
                        borderColor: "var(--accent-border)",
                        backgroundColor: "var(--accent-soft)",
                      }
                    : undefined
                }
                className="p-3.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/55 text-left flex items-center justify-between gap-2 transition cursor-pointer"
              >
                <span className="flex items-center gap-2.5 text-xs font-bold">
                  <span
                    className="w-4 h-4 rounded-full border border-white/25 shrink-0"
                    style={{ backgroundColor: t.swatch }}
                  />
                  {t.name}
                </span>
                {active && (
                  <Check className="w-4 h-4 shrink-0" style={{ color: "var(--accent)" }} />
                )}
              </button>
            );
          })}
        </div>
      </section>

      {/* Typography & Font Family */}
      <section className="rounded-2xl glass-panel p-4 sm:p-6 space-y-5">
        <div className="flex items-center gap-2">
          <Type className="w-4 h-4" style={{ color: "var(--accent)" }} />
          <h2 className="text-sm sm:text-base font-bold">
            TYPOGRAPHY &amp; FONT CONTROLS
          </h2>
        </div>

        <div>
          <label className="block text-[11px] font-bold text-[var(--text-secondary)] mb-2.5">
            FONT FAMILY
          </label>
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
            {FONT_OPTIONS.map((font) => {
              const active = prefs.fontFamily === font.id;
              return (
                <button
                  key={font.id}
                  type="button"
                  onClick={() => updatePrefs({ fontFamily: font.id })}
                  style={{
                    fontFamily: font.cssValue,
                    ...(active
                      ? {
                          borderColor: "var(--accent-border)",
                          backgroundColor: "var(--accent-soft)",
                        }
                      : {}),
                  }}
                  className="p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/55 text-left space-y-1.5 transition cursor-pointer"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-bold">{font.label}</span>
                    {active && (
                      <Check
                        className="w-4 h-4 shrink-0"
                        style={{ color: "var(--accent)" }}
                      />
                    )}
                  </div>
                  <p className="text-[11px] text-[var(--text-secondary)]">
                    {font.sample}
                  </p>
                </button>
              );
            })}
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-3 border-t border-[var(--border-subtle)]">
          {/* Text Case */}
          <div className="space-y-2">
            <label className="block text-[11px] font-bold text-[var(--text-secondary)]">
              TEXT CASE
            </label>
            <div className="grid grid-cols-2 gap-2">
              {(
                [
                  { id: "uppercase", label: "ALL CAPS" },
                  { id: "normal", label: "NORMAL CASE" },
                ] as Array<{ id: UiTextCase; label: string }>
              ).map((opt) => (
                <button
                  key={opt.id}
                  type="button"
                  onClick={() => updatePrefs({ textCase: opt.id })}
                  style={
                    prefs.textCase === opt.id
                      ? {
                          backgroundColor: "var(--accent)",
                          borderColor: "var(--accent)",
                          color: "#ffffff",
                        }
                      : undefined
                  }
                  className="px-3 py-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-xs font-bold cursor-pointer"
                >
                  {opt.label}
                </button>
              ))}
            </div>
          </div>

          {/* Font Size */}
          <div className="space-y-2">
            <label className="block text-[11px] font-bold text-[var(--text-secondary)]">
              FONT SCALE
            </label>
            <div className="grid grid-cols-3 gap-2">
              {(
                [
                  { id: "compact", label: "SMALL" },
                  { id: "default", label: "DEFAULT" },
                  { id: "large", label: "LARGE" },
                ] as Array<{ id: UiFontSize; label: string }>
              ).map((opt) => (
                <button
                  key={opt.id}
                  type="button"
                  onClick={() => updatePrefs({ fontSize: opt.id })}
                  style={
                    prefs.fontSize === opt.id
                      ? {
                          backgroundColor: "var(--accent)",
                          borderColor: "var(--accent)",
                          color: "#ffffff",
                        }
                      : undefined
                  }
                  className="px-2.5 py-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-xs font-bold cursor-pointer"
                >
                  {opt.label}
                </button>
              ))}
            </div>
          </div>

          {/* Letter Spacing */}
          <div className="space-y-2">
            <label className="block text-[11px] font-bold text-[var(--text-secondary)]">
              LETTER SPACING
            </label>
            <div className="grid grid-cols-3 gap-2">
              {(
                [
                  { id: "tight", label: "TIGHT" },
                  { id: "normal", label: "NORMAL" },
                  { id: "wide", label: "WIDE" },
                ] as Array<{ id: UiLetterSpacing; label: string }>
              ).map((opt) => (
                <button
                  key={opt.id}
                  type="button"
                  onClick={() => updatePrefs({ letterSpacing: opt.id })}
                  style={
                    prefs.letterSpacing === opt.id
                      ? {
                          backgroundColor: "var(--accent)",
                          borderColor: "var(--accent)",
                          color: "#ffffff",
                        }
                      : undefined
                  }
                  className="px-2.5 py-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-xs font-bold cursor-pointer"
                >
                  {opt.label}
                </button>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* Surface, Corner Radius & Visual Effects */}
      <section className="rounded-2xl glass-panel p-4 sm:p-6 space-y-5">
        <div className="flex items-center gap-2">
          <SlidersHorizontal className="w-4 h-4" style={{ color: "var(--accent)" }} />
          <h2 className="text-sm sm:text-base font-bold">
            LAYOUT, CORNERS &amp; VISUAL EFFECTS
          </h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          {/* Corner Radius */}
          <div className="space-y-2">
            <label className="block text-[11px] font-bold text-[var(--text-secondary)]">
              PANEL CORNER STYLE
            </label>
            <div className="grid grid-cols-3 gap-2">
              {(
                [
                  { id: "sharp", label: "SHARP" },
                  { id: "rounded", label: "ROUNDED" },
                  { id: "ultra", label: "PILL / ULTRA" },
                ] as Array<{ id: UiCornerStyle; label: string }>
              ).map((opt) => (
                <button
                  key={opt.id}
                  type="button"
                  onClick={() => updatePrefs({ cornerStyle: opt.id })}
                  style={
                    prefs.cornerStyle === opt.id
                      ? {
                          backgroundColor: "var(--accent)",
                          borderColor: "var(--accent)",
                          color: "#ffffff",
                        }
                      : undefined
                  }
                  className="px-3 py-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-xs font-bold cursor-pointer"
                >
                  {opt.label}
                </button>
              ))}
            </div>
          </div>

          {/* UI Density */}
          <div className="space-y-2">
            <label className="block text-[11px] font-bold text-[var(--text-secondary)]">
              WORKSPACE DENSITY
            </label>
            <div className="grid grid-cols-2 gap-2">
              {(
                [
                  { id: "comfortable", label: "COMFORTABLE" },
                  { id: "compact", label: "COMPACT SOC" },
                ] as Array<{ id: UiDensity; label: string }>
              ).map((opt) => (
                <button
                  key={opt.id}
                  type="button"
                  onClick={() => updatePrefs({ density: opt.id })}
                  style={
                    prefs.density === opt.id
                      ? {
                          backgroundColor: "var(--accent)",
                          borderColor: "var(--accent)",
                          color: "#ffffff",
                        }
                      : undefined
                  }
                  className="px-3 py-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-xs font-bold cursor-pointer"
                >
                  {opt.label}
                </button>
              ))}
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2 border-t border-[var(--border-subtle)]">
          <label className="p-3.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/55 flex items-center justify-between gap-3 cursor-pointer">
            <div>
              <div className="text-xs font-bold">GLASSMORPHISM BLUR</div>
              <div className="text-[10px] text-[var(--text-secondary)]">
                TRANSLUCENT BACKDROP BLUR ON PANELS &amp; MODALS
              </div>
            </div>
            <input
              type="checkbox"
              checked={prefs.glassBlur}
              onChange={(e) => updatePrefs({ glassBlur: e.target.checked })}
              style={{ accentColor: "var(--accent)" }}
              className="w-4 h-4"
            />
          </label>

          <label className="p-3.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/55 flex items-center justify-between gap-3 cursor-pointer">
            <div>
              <div className="text-xs font-bold">AMBIENT BACKGROUND GLOW</div>
              <div className="text-[10px] text-[var(--text-secondary)]">
                SUBTLE RADIAL ACCENT GRADIENT BEHIND WORKSPACE
              </div>
            </div>
            <input
              type="checkbox"
              checked={prefs.ambientGlow}
              onChange={(e) => updatePrefs({ ambientGlow: e.target.checked })}
              style={{ accentColor: "var(--accent)" }}
              className="w-4 h-4"
            />
          </label>
        </div>
      </section>

      {/* Live Preview */}
      <section className="rounded-2xl glass-panel p-5 space-y-2">
        <div className="text-[10px] font-bold tracking-widest text-[var(--text-secondary)] flex items-center gap-1.5">
          <Sparkles className="w-3.5 h-3.5" style={{ color: "var(--accent)" }} />
          LIVE TYPOGRAPHY &amp; SURFACE PREVIEW
        </div>
        <div className="text-base font-extrabold">
          EYESIGHT THREAT INTELLIGENCE — INDICATOR ENRICHMENT READY
        </div>
        <p className="text-xs text-[var(--text-secondary)]">
          SAMPLE HEADLINE: CRITICAL ZERO-DAY DISCLOSED IN ENTERPRISE EDGE GATEWAY (CVSS 9.8).
        </p>
      </section>
    </div>
  );
}
