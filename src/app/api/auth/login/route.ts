import { NextResponse } from "next/server";
import { eq } from "drizzle-orm";
import { z } from "zod";
import { getDb, schema } from "@/db";
import { createUserSession, SESSION_COOKIE_NAME } from "@/lib/auth";
import { verifyPassword } from "@/lib/crypto";

export const dynamic = "force-dynamic";

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6).max(128),
});

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const parsed = loginSchema.safeParse(body);
    if (!parsed.success) {
      return NextResponse.json(
        { error: "Valid email and password required." },
        { status: 400 },
      );
    }

    const db = await getDb();
    const email = parsed.data.email.trim().toLowerCase();
    const rows = await db
      .select()
      .from(schema.users)
      .where(eq(schema.users.email, email))
      .limit(1);

    const user = rows[0];
    if (!user || !verifyPassword(parsed.data.password, user.passwordHash)) {
      return NextResponse.json(
        { error: "Invalid email or password." },
        { status: 401 },
      );
    }

    const session = await createUserSession(user.id);
    const res = NextResponse.json({
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
      },
    });
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
      { error: err instanceof Error ? err.message : "Login failed" },
      { status: 500 },
    );
  }
}
