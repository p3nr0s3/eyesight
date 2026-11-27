import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { resolveToolProfile } from "@/lib/providers/tool-profiles";

describe("tool classification profiles", () => {
  it("scopes individual tools to their exact provider and accepted IOC types", () => {
    const abuse = resolveToolProfile("reputation", "abuseipdb");
    assert.deepEqual(abuse.providerIds, ["abuseipdb"]);
    assert.deepEqual(abuse.acceptedTypes, ["ip"]);

    const bazaar = resolveToolProfile("malware_feeds", "malwarebazaar");
    assert.deepEqual(bazaar.providerIds, ["malwarebazaar"]);
    assert.deepEqual(bazaar.acceptedTypes, ["hash"]);

    const net = resolveToolProfile("network_osint", "network_rdap");
    assert.deepEqual(net.providerIds, ["network_rdap"]);
    assert.equal(net.defaultTab, "network");
  });

  it("scopes category views to their category providers and unified lookup to all", () => {
    const repAll = resolveToolProfile("reputation", null);
    assert.deepEqual(repAll.providerIds, ["virustotal", "abuseipdb"]);

    const unified = resolveToolProfile("all", null);
    assert.equal(unified.providerIds, undefined);
    assert.equal(unified.acceptedTypes.length, 4);
  });
});
