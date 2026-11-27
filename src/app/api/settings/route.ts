import { NextResponse } from "next/server";
import { and, eq } from "drizzle-orm";
import { z } from "zod";
import { getDb, schema } from "@/db";
import { enforceAuthGuard } from "@/lib/api-utils";
import { canManageWorkspaceSettings } from "@/lib/auth";
import { decryptSecret, encryptSecret, maskSecret } from "@/lib/crypto";
import { PROVIDER_CATALOG, type ProviderId } from "@/lib/providers/catalog";

export const dynamic = "force-dynamic";

function hasEnvKey(envVarName?: string): boolean {
  if (!envVarName) return false;
  return Boolean(process.env[envVarName]?.trim());
}

export async function GET(request: Request) {
  const { ctx, errorResponse } = await enforceAuthGuard(request);
  if (errorResponse) return errorResponse;

  const db = await getDb();
  const [thresholdRows, configRows, userKeyRows] = await Promise.all([
    db
      .select()
      .from(schema.scoringSettings)
      .where(eq(schema.scoringSettings.id, "default"))
      .limit(1),
    db.select().from(schema.providerConfigs),
    ctx.user
      ? db
          .select()
          .from(schema.userProviderKeys)
          .where(eq(schema.userProviderKeys.userId, ctx.user.id))
      : Promise.resolve([]),
  ]);

  const configMap = new Map(configRows.map((c) => [c.providerId, c]));
  const userKeyMap = new Map(userKeyRows.map((k) => [k.providerId, k]));

  const providers = PROVIDER_CATALOG.map((meta) => {
    const cfg = configMap.get(meta.id);
    const userRow = userKeyMap.get(meta.id);
    const serverPlain = cfg?.encryptedApiKey
      ? decryptSecret(cfg.encryptedApiKey)
      : null;
    const userPlain = userRow?.encryptedApiKey
      ? decryptSecret(userRow.encryptedApiKey)
      : null;

    return {
      ...meta,
      weight: cfg?.weight ?? meta.defaultWeight,
      ttlSeconds: cfg?.ttlSeconds ?? meta.defaultTtlSeconds,
      enabled: cfg?.enabled ?? true,
      hasEnvKey: hasEnvKey(meta.envVarName),
      hasServerKey: Boolean(serverPlain),
      serverKeyMask: serverPlain ? maskSecret(serverPlain) : null,
      hasUserKey: Boolean(userPlain),
      userKeyMask: userPlain ? maskSecret(userPlain) : null,
    };
  });

  return NextResponse.json({
    canManageWorkspace: canManageWorkspaceSettings(ctx),
    thresholds: {
      maliciousThreshold: thresholdRows[0]?.maliciousThreshold ?? 70,
      suspiciousThreshold: thresholdRows[0]?.suspiciousThreshold ?? 30,
    },
    providers,
  });
}

const updateSettingsSchema = z.object({
  thresholds: z
    .object({
      maliciousThreshold: z.number().int().min(10).max(100),
      suspiciousThreshold: z.number().int().min(1).max(99),
    })
    .optional(),
  providers: z
    .array(
      z.object({
        providerId: z.string(),
        weight: z.number().int().min(0).max(100).optional(),
        ttlSeconds: z.number().int().min(0).max(604800).optional(),
        enabled: z.boolean().optional(),
        serverApiKey: z.string().nullable().optional(),
      }),
    )
    .optional(),
  userProviderKeys: z
    .record(z.string(), z.string().nullable())
    .optional(),
});

export async function PUT(request: Request) {
  const { ctx, errorResponse } = await enforceAuthGuard(request);
  if (errorResponse) return errorResponse;

  try {
    const body = await request.json();
    const parsed = updateSettingsSchema.safeParse(body);
    if (!parsed.success) {
      return NextResponse.json(
        { error: "Invalid settings payload", issues: parsed.error.issues },
        { status: 400 },
      );
    }

    const db = await getDb();
    const canManage = canManageWorkspaceSettings(ctx);

    if (parsed.data.thresholds || parsed.data.providers) {
      if (!canManage) {
        return NextResponse.json(
          {
            error:
              "Only workspace administrators can modify global scoring weights, TTLs, or server API keys.",
          },
          { status: 403 },
        );
      }

      if (parsed.data.thresholds) {
        const { maliciousThreshold, suspiciousThreshold } = parsed.data.thresholds;
        if (suspiciousThreshold >= maliciousThreshold) {
          return NextResponse.json(
            {
              error:
                "Suspicious threshold must be lower than malicious threshold.",
            },
            { status: 400 },
          );
        }
        await db
          .insert(schema.scoringSettings)
          .values({
            id: "default",
            maliciousThreshold,
            suspiciousThreshold,
            updatedAt: new Date(),
          })
          .onConflictDoUpdate({
            target: schema.scoringSettings.id,
            set: {
              maliciousThreshold,
              suspiciousThreshold,
              updatedAt: new Date(),
            },
          });
      }

      if (parsed.data.providers) {
        const validIds = new Set<string>(PROVIDER_CATALOG.map((p) => p.id));
        for (const item of parsed.data.providers) {
          if (!validIds.has(item.providerId)) continue;
          const updates: Partial<typeof schema.providerConfigs.$inferInsert> = {
            updatedAt: new Date(),
          };
          if (item.weight !== undefined) updates.weight = item.weight;
          if (item.ttlSeconds !== undefined) updates.ttlSeconds = item.ttlSeconds;
          if (item.enabled !== undefined) updates.enabled = item.enabled;
          if (item.serverApiKey !== undefined) {
            updates.encryptedApiKey =
              item.serverApiKey && item.serverApiKey.trim()
                ? encryptSecret(item.serverApiKey.trim())
                : null;
          }

          await db
            .update(schema.providerConfigs)
            .set(updates)
            .where(eq(schema.providerConfigs.providerId, item.providerId));
        }
      }
    }

    // Authenticated user saving personal BYOK overrides to DB
    if (parsed.data.userProviderKeys) {
      if (!ctx.user) {
        return NextResponse.json(
          { error: "Sign in to save personal BYOK keys in your database profile (or use browser storage)." },
          { status: 401 },
        );
      }
      const validIds = new Set<string>(PROVIDER_CATALOG.map((p) => p.id));
      for (const [providerId, keyVal] of Object.entries(
        parsed.data.userProviderKeys,
      )) {
        if (!validIds.has(providerId)) continue;
        if (!keyVal || !keyVal.trim()) {
          await db
            .delete(schema.userProviderKeys)
            .where(
              and(
                eq(schema.userProviderKeys.userId, ctx.user.id),
                eq(schema.userProviderKeys.providerId, providerId),
              ),
            );
        } else {
          const encrypted = encryptSecret(keyVal.trim());
          await db
            .insert(schema.userProviderKeys)
            .values({
              id: crypto.randomUUID(),
              userId: ctx.user.id,
              providerId: providerId as ProviderId,
              encryptedApiKey: encrypted,
              updatedAt: new Date(),
            })
            .onConflictDoUpdate({
              target: [
                schema.userProviderKeys.userId,
                schema.userProviderKeys.providerId,
              ],
              set: {
                encryptedApiKey: encrypted,
                updatedAt: new Date(),
              },
            });
        }
      }
    }

    return NextResponse.json({ updated: true });
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Failed to update settings" },
      { status: 500 },
    );
  }
}
