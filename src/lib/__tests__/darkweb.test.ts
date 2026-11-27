import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import {
  evaluateTargetAgainstSnapshot,
  extractDomainFromText,
  getDarkwebIntelSnapshot,
  inferVictimCountry,
  inferVictimSector,
  searchDarkwebIntel,
  sortVictimsLatestFirst,
  type DarkwebIntelSnapshot,
} from "@/lib/darkweb";

describe("darkweb monitoring intelligence", () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("extracts domains and infers country and sector from victim metadata", () => {
    const domain = extractDomainFromText(
      "Hospital in Bremen Germany https://www.sternklinik.net/about",
    );
    assert.equal(domain, "sternklinik.net");

    const deCountry = inferVictimCountry(
      "SternKlinik (medi-z Bremen GmbH)",
      "Medical centre in Germany",
      "sternklinik.net",
    );
    assert.equal(deCountry.code, "DE");

    const idCountry = inferVictimCountry(
      "PT Example Indonesia",
      "Retail",
      "example.co.id",
    );
    assert.equal(idCountry.code, "ID");

    assert.equal(
      inferVictimSector("City General Hospital", "Medical records"),
      "HEALTHCARE",
    );
  });

  it("sorts ransomware victims latest-first", () => {
    const sorted = sortVictimsLatestFirst([
      {
        victim: "Older Corp",
        group: "lockbit",
        discovered: "2026-01-01 00:00:00",
        description: "",
        countryCode: "US",
        countryName: "UNITED STATES",
        sector: "OTHER",
        extractedDomain: null,
        mispUuid: null,
        onionLink: null,
        hasMagnet: false,
        screenshotUrl: null,
        sourceUrl: null,
      },
      {
        victim: "Newest Corp",
        group: "ransomhub",
        discovered: "2026-11-27 06:00:00",
        description: "",
        countryCode: "DE",
        countryName: "GERMANY",
        sector: "TECHNOLOGY",
        extractedDomain: null,
        mispUuid: null,
        onionLink: null,
        hasMagnet: false,
        screenshotUrl: null,
        sourceUrl: null,
      },
    ]);
    assert.equal(sorted[0].victim, "Newest Corp");
  });

  it("evaluates monitored domains and brands across victims, breaches, and leaked DBs", () => {
    const snapshot: DarkwebIntelSnapshot = {
      victims: [
        {
          victim: "Acme Logistics",
          group: "qilin",
          discovered: "2026-11-26 10:00:00",
          description: "Transportation",
          countryCode: "US",
          countryName: "UNITED STATES",
          sector: "LOGISTICS",
          extractedDomain: "acmelogistics.com",
          mispUuid: "uuid-1",
          onionLink: null,
          hasMagnet: false,
          screenshotUrl: null,
          sourceUrl: null,
        },
      ],
      groups: ["qilin", "lockbit"],
      markets: ["darkzone"],
      breaches: [
        {
          name: "AcmeLeak",
          title: "Acme",
          domain: "acmelogistics.com",
          breachDate: "2025-06-01",
          addedDate: "2025-07-01T00:00:00Z",
          pwnCount: 50000,
          description: "Stealer logs",
          dataClasses: ["Email addresses", "Passwords"],
          isVerified: true,
          isStealerLog: true,
        },
      ],
      leakedDomains: [{ id: 1, domain: "acmelogistics.com" }],
      infraStats: null,
      topGroups: [{ name: "qilin", count: 1 }],
      topSectors: [{ name: "LOGISTICS", count: 1 }],
      topCountries: [{ code: "US", name: "UNITED STATES", count: 1 }],
      stats: {
        recentVictimsCount: 1,
        groupsCount: 2,
        marketsCount: 1,
        breachesCount: 1,
        stealerBreachesCount: 1,
        leakedDomainsCount: 1,
        latestVictimDate: "2026-11-26 10:00:00",
        latestBreachDate: "2025-07-01T00:00:00Z",
      },
      fetchedAt: new Date().toISOString(),
    };

    const hits = evaluateTargetAgainstSnapshot("acmelogistics.com", snapshot);
    assert.equal(hits.matchCount, 3);
    assert.equal(hits.victimHits.length, 1);
    assert.equal(hits.breachHits.length, 1);
    assert.equal(hits.leakedDomainHits.length, 1);
  });

  it("aggregates snapshot and searches across mocked darkweb APIs", async () => {
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("/api/recent")) {
        return new Response(
          JSON.stringify([
            {
              post_title: "Example Hospital",
              group_name: "medusa",
              discovered: "2026-11-27 05:00:00",
              description: "Healthcare in Germany https://examplehospital.de",
              link: "/site/blog?uuid=3789ad26",
              misp_uuid: "misp-123",
            },
          ]),
          { status: 200 },
        );
      }
      if (url.includes("/api/groups")) {
        return new Response(JSON.stringify(["medusa", "blackbasta"]), {
          status: 200,
        });
      }
      if (url.includes("/api/markets")) {
        return new Response(JSON.stringify(["alphabay"]), { status: 200 });
      }
      if (url.includes("/api/leaks/leaks")) {
        return new Response(
          JSON.stringify([{ id: 1, name: "examplehospital.de" }]),
          { status: 200 },
        );
      }
      if (url.includes("/api/stats")) {
        return new Response(
          JSON.stringify({ groups: 657, groups_locations: 3662, groups_dls: 900, groups_fs: 2413, groups_chat: 327 }),
          { status: 200 },
        );
      }
      if (url.includes("haveibeenpwned.com/api/v3/breaches")) {
        return new Response(
          JSON.stringify([
            {
              Name: "ExampleStealer",
              Title: "Example Stealer Logs",
              Domain: "examplehospital.de",
              BreachDate: "2026-10-01",
              AddedDate: "2026-10-05T00:00:00Z",
              PwnCount: 12000,
              Description: "Infostealer dump",
              DataClasses: ["Email addresses", "Passwords"],
              IsVerified: true,
              IsStealerLog: true,
            },
          ]),
          { status: 200 },
        );
      }
      return new Response("[]", { status: 200 });
    }) as unknown as typeof fetch;

    const snap = await getDarkwebIntelSnapshot(true);
    assert.equal(snap.victims.length, 1);
    assert.equal(snap.victims[0].countryCode, "DE");
    assert.equal(snap.victims[0].sector, "HEALTHCARE");
    assert.equal(
      snap.victims[0].sourceUrl,
      "https://www.ransomlook.io/group/medusa",
    );
    assert.equal(snap.victims[0].onionLink, "/site/blog?uuid=3789ad26");
    assert.equal(snap.infraStats?.dlsSites, 900);

    const search = await searchDarkwebIntel("examplehospital.de");
    assert.equal(search.breaches.length, 1);
    assert.equal(search.leakedDomains.length, 1);
  });
});
