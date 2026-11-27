import crypto from "node:crypto";

const DEV_FALLBACK_KEY = "eyesight-local-dev-secret-change-in-prod";

function getEncryptionKey(): Buffer {
  const secret = process.env.ENCRYPTION_SECRET?.trim() || DEV_FALLBACK_KEY;
  return crypto.createHash("sha256").update(secret).digest();
}

/** Encrypts sensitive strings (such as provider API keys) using AES-256-GCM. */
export function encryptSecret(plaintext: string): string {
  const key = getEncryptionKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return `${iv.toString("base64url")}.${tag.toString("base64url")}.${encrypted.toString("base64url")}`;
}

/** Decrypts an AES-256-GCM payload created by `encryptSecret`. */
export function decryptSecret(payload: string): string | null {
  try {
    const parts = payload.split(".");
    if (parts.length !== 3) return null;
    const [ivStr, tagStr, dataStr] = parts;
    const key = getEncryptionKey();
    const iv = Buffer.from(ivStr, "base64url");
    const tag = Buffer.from(tagStr, "base64url");
    const data = Buffer.from(dataStr, "base64url");
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(data), decipher.final()]).toString(
      "utf8",
    );
  } catch {
    return null;
  }
}

export function maskSecret(secret: string): string {
  if (!secret) return "";
  if (secret.length <= 8) return "••••••••";
  return `${secret.slice(0, 4)}••••${secret.slice(-4)}`;
}

export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16).toString("hex");
  const derived = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${derived}`;
}

export function verifyPassword(password: string, stored: string): boolean {
  const [salt, hashHex] = stored.split(":");
  if (!salt || !hashHex) return false;
  const derived = crypto.scryptSync(password, salt, 64);
  const storedBuf = Buffer.from(hashHex, "hex");
  if (derived.length !== storedBuf.length) return false;
  return crypto.timingSafeEqual(derived, storedBuf);
}

export function sha256Hex(value: string): string {
  return crypto.createHash("sha256").update(value).digest("hex");
}

export function generateSessionToken(): string {
  return crypto.randomBytes(32).toString("base64url");
}

export function generateRestApiKey(): {
  rawKey: string;
  keyPrefix: string;
  keyHash: string;
} {
  const token = crypto.randomBytes(24).toString("base64url");
  const rawKey = `ey_${token}`;
  return {
    rawKey,
    keyPrefix: rawKey.slice(0, 10),
    keyHash: sha256Hex(rawKey),
  };
}
