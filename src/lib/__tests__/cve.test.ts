import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import {
  getCveDashboardData,
  scoreToSeverity,
  searchCves,
  sortCvesLatestFirst,
  sortKevLatestFirst,
  type CveRecord,
  type KevEntry,
} from "@/lib/cve";

describe("CVE intelligence service", () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("maps CVSS scores to severity labels accurately", () => {
    assert.equal(scoreToSeverity(9.8), "CRITICAL");
    assert.equal(scoreToSeverity(7.5), "HIGH");
    assert.equal(scoreToSeverity(5.3), "MEDIUM");
    assert.equal(scoreToSeverity(2.1), "LOW");
    assert.equal(scoreToSeverity(null), "UNKNOWN");
  });

  it("sorts CVEs and KEV entries latest-first", () => {
    const cves: CveRecord[] = [
      {
        id: "CVE-2024-0001",
        published: "2024-01-01T00:00:00Z",
        lastModified: "2024-01-01T00:00:00Z",
        description: "Old",
        cvssScore: 5.0,
        cvssVector: null,
        severity: "MEDIUM",
        cwes: [],
        references: [],
        affectedProducts: [],
        activeExploit: null,
        source: "nvd",
      },
      {
        id: "CVE-2026-9999",
        published: "2026-11-26T00:00:00Z",
        lastModified: "2026-11-26T00:00:00Z",
        description: "Latest",
        cvssScore: 9.8,
        cvssVector: null,
        severity: "CRITICAL",
        cwes: [],
        references: [],
        affectedProducts: [],
        activeExploit: null,
        source: "nvd",
      },
    ];
    const sorted = sortCvesLatestFirst(cves);
    assert.equal(sorted[0].id, "CVE-2026-9999");

    const kevs: KevEntry[] = [
      {
        cveID: "CVE-2023-1000",
        vendorProject: "A",
        product: "P1",
        vulnerabilityName: "V1",
        dateAdded: "2023-05-01",
        shortDescription: "D1",
        requiredAction: "Patch",
        dueDate: "2023-05-21",
        knownRansomwareCampaignUse: "Unknown",
      },
      {
        cveID: "CVE-2026-5000",
        vendorProject: "B",
        product: "P2",
        vulnerabilityName: "V2",
        dateAdded: "2026-11-20",
        shortDescription: "D2",
        requiredAction: "Patch",
        dueDate: "2026-12-10",
        knownRansomwareCampaignUse: "Known",
      },
    ];
    assert.equal(sortKevLatestFirst(kevs)[0].cveID, "CVE-2026-5000");
  });

  it("aggregates dashboard and searches CVEs sorted latest-first with KEV matching", async () => {
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("known_exploited_vulnerabilities.json")) {
        return new Response(
          JSON.stringify({
            vulnerabilities: [
              {
                cveID: "CVE-2026-1111",
                vendorProject: "Acme",
                product: "Gateway",
                vulnerabilityName: "Acme RCE",
                dateAdded: "2026-11-25",
                shortDescription: "Remote code execution",
                requiredAction: "Apply vendor update",
                dueDate: "2026-12-15",
                knownRansomwareCampaignUse: "Known",
              },
            ],
          }),
          { status: 200 },
        );
      }
      if (url.includes("services.nvd.nist.gov")) {
        return new Response(
          JSON.stringify({
            vulnerabilities: [
              {
                cve: {
                  id: "CVE-2025-2222",
                  published: "2025-02-10T10:00:00.000",
                  lastModified: "2025-02-10T10:00:00.000",
                  descriptions: [{ lang: "en", value: "Older CVE" }],
                  metrics: {
                    cvssMetricV31: [
                      {
                        cvssData: {
                          baseScore: 7.5,
                          baseSeverity: "HIGH",
                          vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        },
                      },
                    ],
                  },
                },
              },
              {
                cve: {
                  id: "CVE-2026-1111",
                  published: "2026-11-24T12:00:00.000",
                  lastModified: "2026-11-25T12:00:00.000",
                  descriptions: [{ lang: "en", value: "Critical Acme RCE" }],
                  metrics: {
                    cvssMetricV31: [
                      {
                        cvssData: {
                          baseScore: 9.8,
                          baseSeverity: "CRITICAL",
                          vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        },
                      },
                    ],
                  },
                },
              },
            ],
          }),
          { status: 200 },
        );
      }
      return new Response("[]", { status: 200 });
    }) as unknown as typeof fetch;

    const dash = await getCveDashboardData();
    assert.equal(dash.top10Latest[0].id, "CVE-2026-1111");
    assert.equal(dash.top10Latest[0].activeExploit?.knownRansomwareCampaignUse, "Known");
    assert.equal(dash.stats.criticalInLatestCount, 1);
    assert.equal(dash.stats.ransomwareKevCount, 1);

    const searchRes = await searchCves({ query: "acme", kevOnly: true });
    assert.equal(searchRes.length, 1);
    assert.equal(searchRes[0].id, "CVE-2026-1111");
  });
});
