import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import {
  fetchAggregatedRssNews,
  invalidateNewsCache,
  isSafeExternalFeedUrl,
  parseRssOrAtomXml,
} from "@/lib/rss";
import { POPULAR_RSS_FEEDS } from "@/lib/popular-rss";

describe("RSS feed parser and news aggregation", () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
    invalidateNewsCache();
  });

  it("validates public feed URLs and blocks private/localhost SSRF targets", () => {
    assert.equal(isSafeExternalFeedUrl("https://www.bleepingcomputer.com/feed/"), true);
    assert.equal(isSafeExternalFeedUrl("http://127.0.0.1/feed.xml"), false);
    assert.equal(isSafeExternalFeedUrl("http://localhost:3000/rss"), false);
    assert.equal(isSafeExternalFeedUrl("http://169.254.169.254/latest/meta-data"), false);
    assert.equal(isSafeExternalFeedUrl("ftp://example.com/feed.xml"), false);

    assert.ok(POPULAR_RSS_FEEDS.length >= 10);
    for (const preset of POPULAR_RSS_FEEDS) {
      assert.equal(isSafeExternalFeedUrl(preset.url), true, `Preset invalid: ${preset.url}`);
    }
  });

  it("parses RSS 2.0 and Atom feeds with CDATA and categories", () => {
    const rssXml = `
      <rss version="2.0">
        <channel>
          <item>
            <title><![CDATA[Critical Zero-Day Patched]]></title>
            <link>https://news.example.com/zero-day</link>
            <pubDate>Thu, 26 Nov 2026 10:00:00 GMT</pubDate>
            <category>Zero-Day</category>
            <description><![CDATA[<p>Details about &amp; fix.</p>]]></description>
          </item>
        </channel>
      </rss>
    `;
    const rssItems = parseRssOrAtomXml(rssXml, "TestFeed", "THREAT NEWS");
    assert.equal(rssItems.length, 1);
    assert.equal(rssItems[0].title, "Critical Zero-Day Patched");
    assert.equal(rssItems[0].summary, "Details about & fix.");
    assert.deepEqual(rssItems[0].tags, ["Zero-Day"]);

    const atomXml = `
      <feed xmlns="http://www.w3.org/2005/Atom">
        <entry>
          <title>CISA Advisory AA26-300A</title>
          <link rel="alternate" href="https://cisa.gov/advisory/1" />
          <published>2026-11-27T08:00:00Z</published>
          <summary>Advisory summary</summary>
        </entry>
      </feed>
    `;
    const atomItems = parseRssOrAtomXml(atomXml, "CISA", "ADVISORY");
    assert.equal(atomItems.length, 1);
    assert.equal(atomItems[0].link, "https://cisa.gov/advisory/1");
  });

  it("aggregates multiple feeds and sorts articles latest-first", async () => {
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("feed1")) {
        return new Response(
          `<rss><channel><item><title>Older Story</title><link>https://a.test/1</link><pubDate>Mon, 01 Nov 2026 10:00:00 GMT</pubDate></item></channel></rss>`,
          { status: 200 },
        );
      }
      return new Response(
        `<rss><channel><item><title>Latest Story</title><link>https://b.test/2</link><pubDate>Fri, 27 Nov 2026 09:00:00 GMT</pubDate></item></channel></rss>`,
        { status: 200 },
      );
    }) as unknown as typeof fetch;

    const agg = await fetchAggregatedRssNews(
      [
        { id: "1", name: "Feed1", url: "https://feed1.example.com/rss", category: "NEWS", enabled: true },
        { id: "2", name: "Feed2", url: "https://feed2.example.com/rss", category: "NEWS", enabled: true },
        { id: "3", name: "Disabled", url: "https://feed3.example.com/rss", category: "NEWS", enabled: false },
      ],
      true,
    );

    assert.equal(agg.articles.length, 2);
    assert.equal(agg.articles[0].title, "Latest Story");
    assert.equal(agg.feedStatuses.length, 2);
  });
});
