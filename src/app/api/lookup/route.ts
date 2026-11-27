import { NextResponse } from "next/server";
import { z } from "zod";
import { enforceAuthGuard, parseByokHeader } from "@/lib/api-utils";
import { enrichIoc } from "@/lib/enrich";
import { PROVIDER_CATALOG, type ProviderId } from "@/lib/providers/catalog";

export const dynamic = "force-dynamic";

const VALID_PROVIDER_IDS = new Set<string>(PROVIDER_CATALOG.map((p) => p.id));

const lookupBodySchema = z.object({
  ioc: z.string().min(1).max(2048),
  forceRefresh: z.boolean().optional().default(false),
  recordHistory: z.boolean().optional().default(true),
  providers: z.array(z.string()).optional(),
});

export async function POST(request: Request) {
  const { ctx, errorResponse } = await enforceAuthGuard(request);
  if (errorResponse) return errorResponse;

  try {
    const body = await request.json();
    const parsed = lookupBodySchema.safeParse(body);
    if (!parsed.success) {
      return NextResponse.json(
        { error: "Invalid lookup payload", issues: parsed.error.issues },
        { status: 400 },
      );
    }

    const providers = parsed.data.providers
      ?.filter((id) => VALID_PROVIDER_IDS.has(id))
      .map((id) => id as ProviderId);

    const report = await enrichIoc({
      rawIoc: parsed.data.ioc,
      forceRefresh: parsed.data.forceRefresh,
      recordHistory: parsed.data.recordHistory,
      providers: providers?.length ? providers : undefined,
      byokOverrides: parseByokHeader(request),
      authContext: ctx,
    });

    return NextResponse.json(report);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Lookup failed";
    const status = message.includes("Unsupported or invalid IOC") ? 400 : 500;
    return NextResponse.json({ error: message }, { status });
  }
}

export async function GET(request: Request) {
  const { ctx, errorResponse } = await enforceAuthGuard(request);
  if (errorResponse) return errorResponse;

  const { searchParams } = new URL(request.url);
  const ioc = searchParams.get("ioc")?.trim();
  const forceRefresh = searchParams.get("forceRefresh") === "true";
  const rawProviders = searchParams.get("providers")?.trim();
  const providers = rawProviders
    ? rawProviders
        .split(",")
        .map((s) => s.trim())
        .filter((id) => VALID_PROVIDER_IDS.has(id))
        .map((id) => id as ProviderId)
    : undefined;

  if (!ioc) {
    return NextResponse.json(
      { error: "Missing required query parameter: ioc" },
      { status: 400 },
    );
  }

  try {
    const report = await enrichIoc({
      rawIoc: ioc,
      forceRefresh,
      providers: providers?.length ? providers : undefined,
      byokOverrides: parseByokHeader(request),
      authContext: ctx,
    });
    return NextResponse.json(report);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Lookup failed";
    const status = message.includes("Unsupported or invalid IOC") ? 400 : 500;
    return NextResponse.json({ error: message }, { status });
  }
}
