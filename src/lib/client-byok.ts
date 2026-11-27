"use client";

import type { ProviderId } from "@/lib/providers/catalog";

const STORAGE_KEY = "eyesight_byok_keys";

export function loadBrowserByokKeys(): Partial<Record<ProviderId, string>> {
  if (typeof window === "undefined") return {};
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    const clean: Partial<Record<ProviderId, string>> = {};
    for (const [k, v] of Object.entries(parsed)) {
      if (typeof v === "string" && v.trim()) {
        clean[k as ProviderId] = v.trim();
      }
    }
    return clean;
  } catch {
    return {};
  }
}

export function saveBrowserByokKeys(keys: Partial<Record<ProviderId, string>>): void {
  if (typeof window === "undefined") return;
  const clean: Record<string, string> = {};
  for (const [k, v] of Object.entries(keys)) {
    if (typeof v === "string" && v.trim()) {
      clean[k] = v.trim();
    }
  }
  window.localStorage.setItem(STORAGE_KEY, JSON.stringify(clean));
}

export function getByokHeaders(): Record<string, string> {
  const keys = loadBrowserByokKeys();
  if (Object.keys(keys).length === 0) return {};
  return { "X-Provider-Keys": JSON.stringify(keys) };
}
