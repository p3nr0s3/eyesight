import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { deleteSessionByToken, SESSION_COOKIE_NAME } from "@/lib/auth";

export const dynamic = "force-dynamic";

export async function POST() {
  const cookieStore = await cookies();
  const token = cookieStore.get(SESSION_COOKIE_NAME)?.value;
  if (token) {
    await deleteSessionByToken(token);
  }
  const res = NextResponse.json({ ok: true });
  res.cookies.set(SESSION_COOKIE_NAME, "", {
    httpOnly: true,
    sameSite: "lax",
    path: "/",
    expires: new Date(0),
  });
  return res;
}
