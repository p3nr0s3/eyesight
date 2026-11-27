import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  decryptSecret,
  encryptSecret,
  generateRestApiKey,
  hashPassword,
  maskSecret,
  verifyPassword,
} from "@/lib/crypto";

describe("crypto helpers", () => {
  it("encrypts and decrypts secrets symmetrically", () => {
    const secret = "vt-secret-api-key-12345";
    const encrypted = encryptSecret(secret);
    assert.equal(encrypted.includes(secret), false);
    assert.equal(decryptSecret(encrypted), secret);
    assert.equal(maskSecret(secret), "vt-s••••2345");
  });

  it("hashes and verifies passwords via scrypt", () => {
    const hash = hashPassword("correct-horse-battery-staple");
    assert.equal(verifyPassword("correct-horse-battery-staple", hash), true);
    assert.equal(verifyPassword("wrong-password", hash), false);
  });

  it("generates prefixed REST API keys with SHA-256 hash", () => {
    const key = generateRestApiKey();
    assert.equal(key.rawKey.startsWith("ey_"), true);
    assert.equal(key.keyPrefix, key.rawKey.slice(0, 10));
    assert.equal(key.keyHash.length, 64);
  });
});
