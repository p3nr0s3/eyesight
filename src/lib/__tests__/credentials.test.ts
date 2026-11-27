import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import {
  detectCredentialQueryKind,
  parseCombLine,
  searchCredentialLeaks,
} from "@/lib/credentials";

describe("credential leak monitoring", () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("classifies email, domain, and username queries accurately", () => {
    assert.equal(detectCredentialQueryKind("alice@example.com"), "email");
    assert.equal(detectCredentialQueryKind("dropbox.com"), "domain");
    assert.equal(detectCredentialQueryKind("jdoe_admin"), "username");
  });

  it("parses raw COMB lines uncensored including secrets containing colons", () => {
    const rec = parseCombLine("alice@example.com:P@ss:word123!", 1);
    assert.equal(rec.identifier, "alice@example.com");
    assert.equal(rec.domain, "example.com");
    assert.equal(rec.secret, "P@ss:word123!");
    assert.equal(rec.rawLine, "alice@example.com:P@ss:word123!");
  });

  it("aggregates ProxyNova COMB, Hudson Rock, LeakCheck, XposedOrNot 2026 catalog, and leak evidence dates", async () => {
    (
      globalThis as unknown as {
        __eyesightDarkwebCache?: unknown;
        __eyesightXonGlobalCache?: unknown;
      }
    ).__eyesightDarkwebCache = undefined;
    (
      globalThis as unknown as {
        __eyesightXonGlobalCache?: unknown;
      }
    ).__eyesightXonGlobalCache = undefined;

    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("api.proxynova.com/comb")) {
        return new Response(
          JSON.stringify({
            count: 250,
            lines: ["alice@example.com:hunter2", "bob@example.com:secret99"],
          }),
          { status: 200 },
        );
      }
      if (url.includes("search-by-domain")) {
        return new Response(
          JSON.stringify({
            total: 420,
            employees: 12,
            users: 400,
            third_parties: 8,
            last_employee_compromised: "2026-11-25T00:00:00Z",
            last_user_compromised: "2026-11-26T00:00:00Z",
            stealerFamilies: { total: 420, RedLine: 200, Vidar: 100 },
            antiviruses: {
              total: 50,
              found: 40,
              not_found: 60,
              list: [{ name: "Windows Defender", count: 20 }],
            },
            applications: [{ keyword: "vpn", count: 7 }],
            employeePasswords: {
              totalPass: 10,
              too_weak: { perc: 30 },
              weak: { perc: 50 },
              medium: { perc: 10 },
              strong: { perc: 10 },
            },
            data: {
              employees_urls: [{ url: "https://sso.example.com", occurrence: 5 }],
              clients_urls: [{ url: "https://example.com/login", occurrence: 25 }],
            },
          }),
          { status: 200 },
        );
      }
      if (url.includes("search-by-email")) {
        return new Response(
          JSON.stringify({
            message: "Infected host detected",
            total_corporate_services: 3,
            total_user_services: 42,
            stealers: [
              {
                date_compromised: "2026-11-24T00:00:00Z",
                computer_name: "DESKTOP-TEST01",
                operating_system: "Windows 11 Pro",
                malware_path: "C:\\Temp\\stealer.exe",
                antiviruses: ["Windows Defender"],
                ip: "203.0.113.5",
                total_corporate_services: 3,
                total_user_services: 42,
                top_logins: ["alice@example.com"],
                top_passwords: ["h*****2"],
              },
            ],
          }),
          { status: 200 },
        );
      }
      if (url.includes("xposedornot.com/v1/breach-analytics")) {
        return new Response(
          JSON.stringify({
            BreachMetrics: {
              risk: [{ risk_label: "High", risk_score: 85 }],
              passwords_strength: [
                { EasyToCrack: 2, PlainText: 1, StrongHash: 1, Unknown: 0 },
              ],
            },
            ExposedBreaches: {
              breaches_details: [
                {
                  breach: "SampleBreach",
                  domain: "example.com",
                  xposed_date: "2026",
                  added: "2026-11-01T00:00:00Z",
                  xposed_records: 50000,
                  password_risk: "plaintext",
                  verified: "Yes",
                  xposed_data: "Email addresses;Passwords",
                  details: "Exposed sample dump",
                },
              ],
            },
          }),
          { status: 200 },
        );
      }
      if (url.includes("/api/leaks/leaks")) {
        return new Response(
          JSON.stringify([{ id: 3, name: "example.com" }]),
          { status: 200 },
        );
      }
      if (url.includes("/leak/3")) {
        return new Response(
          JSON.stringify({
            id: 3,
            name: "example.com",
            group: {
              columns: ["email", "password"],
              indexed: "2018-04-12",
              records: "120,000",
              size: "150 M",
            },
          }),
          { status: 200 },
        );
      }
      if (url.includes("haveibeenpwned.com/api/v3/breaches")) {
        return new Response(
          JSON.stringify([
            {
              Name: "ExampleBreach",
              Title: "Example Corp",
              Domain: "example.com",
              BreachDate: "2018-03-01",
              AddedDate: "2018-04-15T00:00:00Z",
              PwnCount: 120000,
              Description: "Credentials dump",
              DataClasses: ["Email addresses", "Passwords"],
              IsVerified: true,
              IsStealerLog: false,
            },
          ]),
          { status: 200 },
        );
      }
      if (url.includes("leakcheck.io/api/public")) {
        return new Response(
          JSON.stringify({
            success: true,
            found: 120,
            fields: ["username", "password", "ip"],
            sources: [
              { name: "Stealer Logs", date: "" },
              { name: "RecentBreach.com", date: "2026-08" },
            ],
          }),
          { status: 200 },
        );
      }
      if (url.includes("api.xposedornot.com/v1/breaches")) {
        return new Response(
          JSON.stringify({
            exposedBreaches: [
              {
                breachID: "Example2026",
                domain: "example.com",
                breachedDate: "2026-09-01T00:00:00+00:00",
                addedDate: "2026-10-05T00:00:00+00:00",
                exposedRecords: 250000,
                passwordRisk: "unknown",
                verified: true,
                exposedData: ["Email addresses", "Passwords"],
                exposureDescription: "2026 live breach",
              },
            ],
          }),
          { status: 200 },
        );
      }
      return new Response("[]", { status: 200 });
    }) as unknown as typeof fetch;

    const report = await searchCredentialLeaks("alice@example.com", {
      start: 0,
      limit: 50,
    });
    assert.equal(report.queryKind, "email");
    assert.equal(report.comb.totalCount, 250);
    assert.equal(report.comb.records[0].secret, "hunter2");
    assert.equal(report.comb.records[0].leakDate, "2018-03-01");
    assert.equal(report.leakCheck?.found, 120);
    assert.equal(report.leakCheck?.sources[0].date, "2026-08");
    assert.equal(report.evidence.xonCatalogMatches[0].breachId, "Example2026");
    assert.equal(report.evidence.ransomLookDumps[0].indexedDate, "2018-04-12");
    assert.equal(report.evidence.hibpMatches[0].breachDate, "2018-03-01");
    assert.equal(report.evidence.timelineSummary.earliestDate, "2018-03-01");
    assert.equal(report.evidence.timelineSummary.latestDate, "2026-11-26");
    assert.equal(report.hudsonRockDomain?.employees, 12);
    assert.equal(report.hudsonRockDomain?.exposedApplications[0].keyword, "vpn");
    assert.equal(report.hudsonRockEmail?.hosts[0].computerName, "DESKTOP-TEST01");
    assert.equal(report.xposedOrNot?.riskScore, 85);
    assert.equal(report.xposedOrNot?.breaches[0].breach, "SampleBreach");
  });
});
