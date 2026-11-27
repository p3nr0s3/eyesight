import { NextResponse } from "next/server";
import { getAuthContext, type AuthContext } from "@/lib/auth";
import type { ProviderId } from "@/lib/providers/catalog";

export function parseByokHeader(
  request: Request,
): Partial<Record<ProviderId, string>> {
  const raw = request.headers.get("x-provider-keys")?.trim();
  if (!raw) return {};
  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    const out: Partial<Record<ProviderId, string>> = {};
    for (const [k, v] of Object.entries(parsed)) {
      if (typeof v === "string" && v.trim()) {
        out[k as ProviderId] = v.trim();
      }
    }
    return out;
  } catch {
    return {};
  }
}

export async function enforceAuthGuard(
  request: Request,
): Promise<{ ctx: AuthContext; errorResponse?: NextResponse }> {
  const ctx = await getAuthContext(request);
  if (ctx.authRequired && !ctx.authenticated) {
    return {
      ctx,
      errorResponse: NextResponse.json(
        { error: "Authentication required. Sign in or provide a valid X-API-Key." },
        { status: 401 },
      ),
    };
  }
  return { ctx };
}
