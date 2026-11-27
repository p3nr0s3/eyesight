import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { isAuthRequired } from "@/lib/auth";

describe("auth portal defaults", () => {
  const origAuthRequired = process.env.AUTH_REQUIRED;

  afterEach(() => {
    if (origAuthRequired === undefined) {
      delete process.env.AUTH_REQUIRED;
    } else {
      process.env.AUTH_REQUIRED = origAuthRequired;
    }
  });

  it("requires login portal authentication by default", () => {
    delete process.env.AUTH_REQUIRED;
    assert.equal(isAuthRequired(), true);
  });

  it("allows disabling login portal only when AUTH_REQUIRED=false", () => {
    process.env.AUTH_REQUIRED = "false";
    assert.equal(isAuthRequired(), false);
    process.env.AUTH_REQUIRED = "true";
    assert.equal(isAuthRequired(), true);
  });
});
