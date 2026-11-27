import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  defangIoc,
  isPrivateOrReservedIp,
  parseBulkIocs,
  parseIoc,
  refangIoc,
} from "@/lib/ioc";

describe("IOC parsing, refanging, and safety", () => {
  it("refangs defanged URLs, domains, and IPs", () => {
    assert.equal(
      refangIoc("hxxps[:]//evil[.]example[.]com/dropper.exe"),
      "https://evil.example.com/dropper.exe",
    );
    assert.equal(refangIoc("1[.]1[.]1[.]1"), "1.1.1.1");
    assert.equal(
      defangIoc("https://evil.com/a.exe", "url"),
      "hxxps://evil[.]com/a[.]exe",
    );
  });

  it("detects IPv4, IPv6, domain, URL, and MD5/SHA1/SHA256 hashes", () => {
    assert.deepEqual(
      {
        normalized: parseIoc("1.1.1.1")?.normalized,
        type: parseIoc("1.1.1.1")?.type,
        isPrivateIp: parseIoc("1.1.1.1")?.isPrivateIp,
      },
      { normalized: "1.1.1.1", type: "ip", isPrivateIp: false },
    );

    const ipv6 = parseIoc("2606:4700:4700::1111");
    assert.equal(ipv6?.type, "ip");
    assert.equal(ipv6?.isPrivateIp, false);

    const dom = parseIoc("EXAMPLE.COM.");
    assert.equal(dom?.normalized, "example.com");
    assert.equal(dom?.type, "domain");

    const url = parseIoc("hxxps[:]//malicious[.]test/login");
    assert.equal(url?.normalized, "https://malicious.test/login");
    assert.equal(url?.type, "url");

    const md5 = parseIoc("44D88612FEA8A8F36DE82E1278ABB02F");
    assert.equal(md5?.type, "hash");
    assert.equal(md5?.hashAlgorithm, "md5");

    assert.equal(parseIoc("a".repeat(40))?.hashAlgorithm, "sha1");
    assert.equal(parseIoc("b".repeat(64))?.hashAlgorithm, "sha256");
  });

  it("flags private, loopback, and metadata IPs", () => {
    assert.equal(isPrivateOrReservedIp("127.0.0.1"), true);
    assert.equal(isPrivateOrReservedIp("10.10.1.5"), true);
    assert.equal(isPrivateOrReservedIp("172.16.0.1"), true);
    assert.equal(isPrivateOrReservedIp("192.168.1.10"), true);
    assert.equal(isPrivateOrReservedIp("169.254.169.254"), true);
    assert.equal(isPrivateOrReservedIp("::1"), true);
    assert.equal(isPrivateOrReservedIp("8.8.8.8"), false);
  });

  it("parses and deduplicates bulk IOC inputs", () => {
    const res = parseBulkIocs(`
      1.1.1.1, 1[.]1[.]1[.]1
      example.com; not-an-ioc
      44d88612fea8a8f36de82e1278abb02f
    `);
    assert.equal(res.iocs.length, 3);
    assert.equal(res.duplicatesRemoved, 1);
    assert.deepEqual(res.invalidTokens, ["not-an-ioc"]);
  });
});
