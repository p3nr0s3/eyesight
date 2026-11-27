import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  analyzeEmailHeaders,
  decodeCyberPayload,
  defangValue,
  extractSocArtifacts,
  generateDetectionRules,
  inspectSubnetCidr,
  refangText,
} from "@/lib/soc-tools";

describe("SOC analyst workbench tools", () => {
  it("extracts, refangs, and defangs mixed IOC artifacts cleanly", () => {
    const raw =
      "Callback hxxps://bad[.]example/a.bin from 45.155.205[.]11 hash 010d16abdf45a544ae192a4eae1c5d11cfa690a827d7e6ba39e457cc774ee26d CVE-2026-103406 user@bad[.]example";
    const res = extractSocArtifacts(raw);
    assert.deepEqual(res.ips, ["45.155.205.11"]);
    assert.ok(res.domains.includes("bad.example"));
    assert.ok(res.urls.includes("https://bad.example/a.bin"));
    assert.equal(res.hashes[0].algorithm, "SHA-256");
    assert.deepEqual(res.cves, ["CVE-2026-103406"]);
    assert.deepEqual(res.emails, ["user@bad.example"]);
    assert.equal(defangValue("https://bad.example"), "hxxps://bad[.]example");
    assert.equal(refangText("hxxp[:]//evil[.]org"), "http://evil.org");
  });

  it("analyzes email headers for SPF/DKIM/DMARC, spoofing mismatches, and hops", () => {
    const headers = [
      "From: IT <alert@legit.example>",
      "Return-Path: <bounce@phish.example>",
      "Authentication-Results: mx.org; spf=fail; dkim=none; dmarc=fail",
      "Received: from edge.phish.example (185.220.101.4) by mx.org; Fri, 27 Nov 2026 06:10:05 +0000",
    ].join("\n");
    const analysis = analyzeEmailHeaders(headers);
    assert.equal(analysis.authVerdicts[0].status, "FAIL");
    assert.equal(analysis.authVerdicts[2].status, "FAIL");
    assert.ok(analysis.anomalies.some((a) => a.includes("RETURN-PATH MISMATCH")));
    assert.equal(analysis.hops.length, 1);
    assert.ok(analysis.extractedIps.includes("185.220.101.4"));
  });

  it("inspects IPv4 CIDR ranges and classifies private vs public space", () => {
    const pub = inspectSubnetCidr("45.155.205.11/24");
    assert.ok(pub);
    assert.equal(pub.networkAddress, "45.155.205.0");
    assert.equal(pub.broadcastAddress, "45.155.205.255");
    assert.equal(pub.wildcardMask, "0.0.0.255");
    assert.equal(pub.usableHosts, 254);
    assert.equal(pub.classification, "PUBLIC ROUTABLE");

    const priv = inspectSubnetCidr("10.20.1.5/16");
    assert.equal(priv?.classification, "PRIVATE (RFC 1918)");
  });

  it("decodes PowerShell UTF-16LE Base64 and generates SIEM/Sigma queries", () => {
    const ps = decodeCyberPayload(
      "powershell.exe -EncodedCommand SQBFAFgAIAB0AGUAcwB0AA==",
      "auto",
    );
    assert.equal(ps.detectedMode, "POWERSHELL UTF-16LE BASE64");
    assert.equal(ps.decodedText, "IEX test");

    const sigma = generateDetectionRules("45.155.205.11 evil.example", "sigma");
    assert.ok(sigma.includes("45.155.205.11"));
    assert.ok(sigma.includes("evil.example"));
  });
});
