import { NextResponse } from "next/server";
import { count, eq } from "drizzle-orm";
import { z } from "zod";
import { getDb, schema } from "@/db";
import { createUserSession, SESSION_COOKIE_NAME } from "@/lib/auth";
import { hashPassword } from "@/lib/crypto";

export const dynamic = "force-dynamic";

const registerSchema = z.object({
  email: z.string().email(),
  name: z.string().min(2).max(80),
  password: z.string().min(8).max(128),
});

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const parsed = registerSchema.safeParse(body);
    if (!parsed.success) {
      return NextResponse.json(
        {
          error:
            "Provide a valid email, name (2+ chars), and password (8+ chars).",
        },
        { status: 400 },
      );
    }

    const db = await getDb();
    const email = parsed.data.email.trim().toLowerCase();

    const existing = await db
      .select({ id: schema.users.id })
      .from(schema.users)
      .where(eq(schema.users.email, email))
      .limit(1);

    if (existing.length > 0) {
      return NextResponse.json(
        { error: "An account with this email already exists." },
        { status: 409 },
      );
    }

    // First registered user becomes workspace Admin
    const [countRow] = await db.select({ total: count() }).from(schema.users);
    const isFirstUser = Number(countRow?.total ?? 0) === 0;
    const role = isFirstUser ? "admin" : "analyst";

    const userId = crypto.randomUUID();
    await db.insert(schema.users).values({
      id: userId,
      email,
      name: parsed.data.name.trim(),
      passwordHash: hashPassword(parsed.data.password),
      role,
    });

    const session = await createUserSession(userId);
    const res = NextResponse.json(
      {
        user: {
          id: userId,
          email,
          name: parsed.data.name.trim(),
          role,
        },
      },
      { status: 201 },
    );

    const isHttps =
      request.headers.get("x-forwarded-proto") === "https" ||
      request.url.startsWith("https://");
    res.cookies.set(SESSION_COOKIE_NAME, session.token, {
      httpOnly: true,
      sameSite: "lax",
      secure: isHttps,
      path: "/",
      expires: session.expiresAt,
    });

    return res;
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Registration failed" },
      { status: 500 },
    );
  }
}
