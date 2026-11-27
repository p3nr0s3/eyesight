import { cookies } from "next/headers";
import { and, count, eq, gt } from "drizzle-orm";
import { getDb, schema } from "@/db";
import { generateSessionToken, sha256Hex } from "@/lib/crypto";

export const SESSION_COOKIE_NAME = "eyesight_session";
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

export interface AuthUser {
  id: string;
  email: string;
  name: string;
  role: "admin" | "analyst";
}

export interface AuthContext {
  authenticated: boolean;
  authRequired: boolean;
  hasUsers: boolean;
  user: AuthUser | null;
  authMethod: "session" | "api_key" | "anonymous";
}

export function isAuthRequired(): boolean {
  return process.env.AUTH_REQUIRED?.trim().toLowerCase() !== "false";
}

function parseCookieValue(cookieHeader: string | null, name: string): string | null {
  if (!cookieHeader) return null;
  const parts = cookieHeader.split(";");
  for (const part of parts) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    const k = part.slice(0, idx).trim();
    if (k === name) {
      return decodeURIComponent(part.slice(idx + 1).trim());
    }
  }
  return null;
}

export async function getAuthContext(request?: Request): Promise<AuthContext> {
  const db = await getDb();
  const authRequired = isAuthRequired();

  const [userCountRow] = await db
    .select({ total: count() })
    .from(schema.users);
  const hasUsers = Number(userCountRow?.total ?? 0) > 0;

  // 1. Check REST API key header
  const xApiKey = request?.headers.get("x-api-key")?.trim();
  const authHeader = request?.headers.get("authorization")?.trim();
  const bearerKey = authHeader?.toLowerCase().startsWith("bearer ")
    ? authHeader.slice(7).trim()
    : null;
  const candidateApiKey = xApiKey || bearerKey;

  if (candidateApiKey && candidateApiKey.startsWith("ey_")) {
    const keyHash = sha256Hex(candidateApiKey);
    const rows = await db
      .select({
        keyId: schema.apiKeys.id,
        userId: schema.users.id,
        email: schema.users.email,
        name: schema.users.name,
        role: schema.users.role,
      })
      .from(schema.apiKeys)
      .innerJoin(schema.users, eq(schema.apiKeys.userId, schema.users.id))
      .where(eq(schema.apiKeys.keyHash, keyHash))
      .limit(1);

    if (rows.length > 0) {
      const row = rows[0];
      await db
        .update(schema.apiKeys)
        .set({ lastUsedAt: new Date() })
        .where(eq(schema.apiKeys.id, row.keyId));

      return {
        authenticated: true,
        authRequired,
        hasUsers,
        user: {
          id: row.userId,
          email: row.email,
          name: row.name,
          role: row.role === "admin" ? "admin" : "analyst",
        },
        authMethod: "api_key",
      };
    }
  }

  // 2. Check session cookie
  let sessionToken: string | null = null;
  if (request) {
    sessionToken = parseCookieValue(
      request.headers.get("cookie"),
      SESSION_COOKIE_NAME,
    );
  } else {
    try {
      const cookieStore = await cookies();
      sessionToken = cookieStore.get(SESSION_COOKIE_NAME)?.value ?? null;
    } catch {
      sessionToken = null;
    }
  }

  if (sessionToken) {
    const tokenHash = sha256Hex(sessionToken);
    const rows = await db
      .select({
        userId: schema.users.id,
        email: schema.users.email,
        name: schema.users.name,
        role: schema.users.role,
      })
      .from(schema.sessions)
      .innerJoin(schema.users, eq(schema.sessions.userId, schema.users.id))
      .where(
        and(
          eq(schema.sessions.tokenHash, tokenHash),
          gt(schema.sessions.expiresAt, new Date()),
        ),
      )
      .limit(1);

    if (rows.length > 0) {
      const row = rows[0];
      return {
        authenticated: true,
        authRequired,
        hasUsers,
        user: {
          id: row.userId,
          email: row.email,
          name: row.name,
          role: row.role === "admin" ? "admin" : "analyst",
        },
        authMethod: "session",
      };
    }
  }

  return {
    authenticated: false,
    authRequired,
    hasUsers,
    user: null,
    authMethod: "anonymous",
  };
}

export async function createUserSession(userId: string): Promise<{
  token: string;
  expiresAt: Date;
}> {
  const db = await getDb();
  const token = generateSessionToken();
  const expiresAt = new Date(Date.now() + SESSION_TTL_MS);

  await db.insert(schema.sessions).values({
    id: crypto.randomUUID(),
    userId,
    tokenHash: sha256Hex(token),
    expiresAt,
  });

  return { token, expiresAt };
}

export async function deleteSessionByToken(token: string): Promise<void> {
  const db = await getDb();
  await db
    .delete(schema.sessions)
    .where(eq(schema.sessions.tokenHash, sha256Hex(token)));
}

export function canManageWorkspaceSettings(ctx: AuthContext): boolean {
  if (ctx.user?.role === "admin") return true;
  if (!ctx.authRequired && !ctx.hasUsers) return true;
  return false;
}
