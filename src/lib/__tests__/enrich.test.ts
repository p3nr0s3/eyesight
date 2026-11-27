import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { enrichIoc } from "@/lib/enrich";

describe("enrichIoc orchestration", () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    process.env.VITEST = "true";
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("skips external queries for private/RFC1918 IPs", async () => {
    let called = 0;
    globalThis.fetch = (async () => {
      called++;
      return new Response("{}", { status: 200 });
    }) as unknown as typeof fetch;

    const report = await enrichIoc({ rawIoc: "192.168.1.50", recordHistory: false });
    assert.equal(report.isPrivateIp, true);
    assert.equal(report.verdict, "unknown");
    assert.equal(called, 0);
  });

  it("fans out, caches valid responses, and respects forceRefresh", async () => {
    let callCount = 0;
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      callCount++;
      const url = String(input);
      if (url.includes("threatfox-api")) {
        return new Response(
          JSON.stringify({
            query_status: "ok",
            data: [
              {
                malware_printable: "Cobalt Strike",
                threat_type: "botnet_cc",
                confidence_level: 90,
              },
            ],
          }),
          { status: 200 },
        );
      }
      if (url.includes("urlhaus-api")) {
        return new Response(JSON.stringify({ query_status: "no_results" }), {
          status: 200,
        });
      }
      if (url.includes("greynoise.io")) {
        return new Response(JSON.stringify({ message: "IP not observed" }), {
          status: 404,
        });
      }
      if (url.includes("ipwho.is")) {
        return new Response(
          JSON.stringify({
            success: true,
            country: "United States",
            country_code: "US",
            connection: { asn: 64512, org: "ExampleNet" },
          }),
          { status: 200 },
        );
      }
      if (url.includes("rdap.org")) {
        return new Response(JSON.stringify({ name: "TEST-NET" }), { status: 200 });
      }
      return new Response("{}", { status: 404 });
    }) as unknown as typeof fetch;

    const first = await enrichIoc({ rawIoc: "203.0.113.10", recordHistory: true });
    assert.equal(first.ioc, "203.0.113.10");
    assert.equal(first.fromCacheCount, 0);
    assert.equal(
      first.results.find((r) => r.providerId === "threatfox")?.verdict,
      "malicious",
    );

    const callsAfterFirst = callCount;
    assert.ok(callsAfterFirst > 0);

    // Second call should hit PGlite cache for ok/not_found providers
    const second = await enrichIoc({ rawIoc: "203.0.113.10", recordHistory: false });
    assert.ok(second.fromCacheCount >= 4);

    // Force refresh bypasses cache and re-fetches
    const third = await enrichIoc({
      rawIoc: "203.0.113.10",
      forceRefresh: true,
      recordHistory: false,
    });
    assert.equal(third.fromCacheCount, 0);
    assert.ok(callCount > callsAfterFirst);
  });
});
