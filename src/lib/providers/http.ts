export async function fetchJsonWithTimeout<T = unknown>(
  url: string,
  init: RequestInit = {},
  timeoutMs = 7500,
): Promise<{
  ok: boolean;
  status: number;
  data: T | null;
  errorText?: string;
}> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      ...init,
      signal: controller.signal,
      headers: {
        "User-Agent": "eyesight-threat-intel/0.1",
        ...(init.headers || {}),
      },
    });
    const text = await res.text();
    let parsed: T | null = null;
    try {
      parsed = text ? (JSON.parse(text) as T) : null;
    } catch {
      parsed = null;
    }
    return {
      ok: res.ok,
      status: res.status,
      data: parsed,
      errorText: res.ok ? undefined : text.slice(0, 300),
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : "Network error";
    return { ok: false, status: 0, data: null, errorText: msg };
  } finally {
    clearTimeout(timer);
  }
}

export function dedupePivots<T extends { type: string; value: string }>(
  pivots: T[],
  excludeValue?: string,
  limit = 20,
): T[] {
  const seen = new Set<string>();
  const out: T[] = [];
  for (const p of pivots) {
    const val = p.value?.trim();
    if (!val) continue;
    if (excludeValue && val.toLowerCase() === excludeValue.toLowerCase()) continue;
    const key = `${p.type}:${val.toLowerCase()}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ ...p, value: val });
    if (out.length >= limit) break;
  }
  return out;
}
