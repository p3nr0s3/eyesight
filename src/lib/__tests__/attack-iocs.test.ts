import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import {
  getLiveAttackIocsSnapshot,
  inferPhishingTargetBrand,
  parseCsvFeedLines,
} from "@/lib/attack-iocs";

describe("live attack IOC intelligence", () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("parses CSV C2 feed lines skipping comments and blank rows", () => {
    const parsed = parseCsvFeedLines(
      "#ip,ioc\n1.2.3.4,Cobalt Strike C2\n\n5.6.7.8,Sliver C2\n",
    );
    assert.equal(parsed.length, 2);
    assert.equal(parsed[0].indicator, "1.2.3.4");
    assert.equal(parsed[0].description, "Cobalt Strike C2");
  });

  it("infers targeted brand from phishing URLs", () => {
    assert.equal(
      inferPhishingTargetBrand("https://evil.example/microsoft-login"),
      "MICROSOFT Lure Phishing",
    );
    assert.equal(
      inferPhishingTargetBrand("https://unknown-portal.example/login"),
      "Credential Harvesting Phishing",
    );
  });

  it("aggregates and enriches live attack IOCs across mocked CTI feeds", async () => {
    (
      globalThis as unknown as { __eyesightAttackCache?: unknown }
    ).__eyesightAttackCache = undefined;

    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("isc.sans.edu/api/sources/attacks")) {
        return new Response(
          JSON.stringify([
            {
              ip: "91.191.209.198",
              attacks: 8153,
              count: 157503,
              firstseen: "2025-01-01",
              lastseen: "2026-11-27",
            },
          ]),
          { status: 200 },
        );
      }
      if (url.includes("internetdb.shodan.io/91.191.209.198")) {
        return new Response(
          JSON.stringify({
            ip: "91.191.209.198",
            ports: [22, 443],
            hostnames: ["scanner.badhost.example"],
            cpes: ["cpe:/a:openbsd:openssh:7.4"],
            vulns: ["CVE-2025-26465"],
            tags: ["scanner"],
          }),
          { status: 200 },
        );
      }
      if (url.includes("isc.sans.edu/api/ip/91.191.209.198")) {
        return new Response(
          JSON.stringify({
            ip: {
              number: "91.191.209.198",
              as: 57509,
              asname: "TEST-ASN",
              ascountry: "BG",
              asabusecontact: "abuse@example.net",
              network: "91.191.209.0/24",
            },
          }),
          { status: 200 },
        );
      }
      if (url.includes("feodotracker.abuse.ch/downloads/ipblocklist.json")) {
        return new Response(
          JSON.stringify([
            {
              ip_address: "50.16.16.211",
              port: 443,
              status: "online",
              hostname: "ec2-50-16-16-211.compute-1.amazonaws.com",
              as_number: 14618,
              as_name: "AMAZON-AES",
              country: "US",
              first_seen: "2026-11-20",
              last_online: "2026-11-27",
              malware: "QakBot",
            },
          ]),
          { status: 200 },
        );
      }
      if (url.includes("IPC2s-30day.csv")) {
        return new Response("1.14.219.84,Possible Cobaltstrike C2 IP\n", {
          status: 200,
        });
      }
      if (url.includes("domainC2s-30day.csv")) {
        return new Response("bad-c2.example.com,Cobalt Strike C2 Domain\n", {
          status: 200,
        });
      }
      if (url.includes("openphish.com/feed.txt")) {
        return new Response("https://paypal-verify.example.com/auth\n", {
          status: 200,
        });
      }
      if (url.includes("Experimental-IOC-Tweets.txt")) {
        return new Response(
          "010d16abdf45a544ae192a4eae1c5d11cfa690a827d7e6ba39e457cc774ee26d\n",
          { status: 200 },
        );
      }
      return new Response("[]", { status: 200 });
    }) as unknown as typeof fetch;

    const snap = await getLiveAttackIocsSnapshot(true);
    assert.equal(snap.items.length, 6);
    assert.equal(snap.stats.c2Count, 3);
    assert.equal(snap.stats.scannerCount, 1);
    assert.equal(snap.stats.phishingCount, 1);
    assert.equal(snap.stats.malwareHashCount, 1);
    assert.equal(snap.stats.enrichedWithCveCount, 1);

    const dshield = snap.items.find((i) => i.ioc === "91.191.209.198");
    assert.ok(dshield);
    assert.deepEqual(dshield.ports, [22, 443]);
    assert.deepEqual(dshield.cves, ["CVE-2025-26465"]);
    assert.equal(dshield.asn, "AS57509");
    assert.equal(dshield.country, "BG");

    const feodo = snap.items.find((i) => i.ioc === "50.16.16.211");
    assert.ok(feodo);
    assert.equal(feodo.malwareFamily, "QakBot");
    assert.equal(feodo.status, "ONLINE");
  });
});
