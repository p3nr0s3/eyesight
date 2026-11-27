import net from "node:net";
import { isPrivateOrReservedIp } from "@/lib/ioc";

export interface NewsArticle {
  id: string;
  title: string;
  link: string;
  summary: string;
  publishedAt: string;
  sourceName: string;
  sourceCategory: string;
  tags: string[];
}

export interface RssFeedSource {
  id: string;
  name: string;
  url: string;
  category: string;
  enabled: boolean;
}

export interface NewsAggregationResult {
  articles: NewsArticle[];
  feedStatuses: Array<{
    id: string;
    name: string;
    category: string;
    ok: boolean;
    articleCount: number;
    error?: string;
  }>;
  fetchedAt: string;
}

const globalForNews = globalThis as unknown as {
  __eyesightNewsCache?: {
    feedsKey: string;
    data: NewsAggregationResult;
    expiresAt: number;
  };
};

const NEWS_CACHE_TTL_MS = 5 * 60 * 1000;

export function invalidateNewsCache(): void {
  globalForNews.__eyesightNewsCache = undefined;
}

/** Validates that a user-configured RSS feed URL is public HTTP/HTTPS and not localhost/private IP. */
export function isSafeExternalFeedUrl(rawUrl: string): boolean {
  try {
    const parsed = new URL(rawUrl.trim());
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
      return false;
    }
    const host = parsed.hostname.toLowerCase();
    if (
      host === "localhost" ||
      host.endsWith(".local") ||
      host.endsWith(".internal")
    ) {
      return false;
    }
    if (net.isIP(host) && isPrivateOrReservedIp(host)) {
      return false;
    }
    return Boolean(host.includes("."));
  } catch {
    return false;
  }
}

function decodeXmlEntities(str: string): string {
  return str
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'")
    .replace(/&#(\d+);/g, (_, num) => String.fromCharCode(Number(num)))
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function extractTag(block: string, tagName: string): string {
  const re = new RegExp(
    `<${tagName}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${tagName}>`,
    "i",
  );
  const match = block.match(re);
  return match ? decodeXmlEntities(match[1]) : "";
}

function extractAtomLink(block: string): string {
  const altMatch = block.match(
    /<link[^>]*rel=["']alternate["'][^>]*href=["']([^"']+)["'][^>]*\/?>/i,
  );
  if (altMatch?.[1]) return altMatch[1].trim();
  const hrefMatch = block.match(/<link[^>]*href=["']([^"']+)["'][^>]*\/?>/i);
  if (hrefMatch?.[1]) return hrefMatch[1].trim();
  return extractTag(block, "link");
}

function extractCategories(block: string): string[] {
  const tags: string[] = [];
  const catRe = /<category(?:\s+term=["']([^"']+)["'])?[^>]*>([\s\S]*?)<\/category>|<category[^>]*term=["']([^"']+)["'][^>]*\/?>/gi;
  let match: RegExpExecArray | null;
  while ((match = catRe.exec(block)) !== null) {
    const val = decodeXmlEntities(match[1] || match[2] || match[3] || "");
    if (val) tags.push(val);
    if (tags.length >= 4) break;
  }
  return Array.from(new Set(tags));
}

function normalizeDate(raw: string): string {
  if (!raw) return new Date(0).toISOString();
  const parsed = Date.parse(raw);
  if (Number.isNaN(parsed)) return new Date(0).toISOString();
  return new Date(parsed).toISOString();
}

export function parseRssOrAtomXml(
  xml: string,
  sourceName: string,
  sourceCategory: string,
): NewsArticle[] {
  const articles: NewsArticle[] = [];

  // RSS 2.0 <item> blocks
  const itemMatches = xml.match(/<item\b[\s\S]*?<\/item>/gi) || [];
  for (const block of itemMatches.slice(0, 100)) {
    const title = extractTag(block, "title");
    const link = extractTag(block, "link") || extractTag(block, "guid");
    const summary =
      extractTag(block, "description") ||
      extractTag(block, "content:encoded");
    const rawDate =
      extractTag(block, "pubDate") ||
      extractTag(block, "dc:date") ||
      extractTag(block, "published");
    if (!title || !link) continue;

    articles.push({
      id: `${sourceName}:${link}`,
      title,
      link,
      summary: summary.slice(0, 320),
      publishedAt: normalizeDate(rawDate),
      sourceName,
      sourceCategory,
      tags: extractCategories(block),
    });
  }

  if (articles.length > 0) {
    return articles;
  }

  // Atom <entry> blocks
  const entryMatches = xml.match(/<entry\b[\s\S]*?<\/entry>/gi) || [];
  for (const block of entryMatches.slice(0, 100)) {
    const title = extractTag(block, "title");
    const link = extractAtomLink(block);
    const summary =
      extractTag(block, "summary") || extractTag(block, "content");
    const rawDate =
      extractTag(block, "published") || extractTag(block, "updated");
    if (!title || !link) continue;

    articles.push({
      id: `${sourceName}:${link}`,
      title,
      link,
      summary: summary.slice(0, 320),
      publishedAt: normalizeDate(rawDate),
      sourceName,
      sourceCategory,
      tags: extractCategories(block),
    });
  }

  return articles;
}

export async function fetchAggregatedRssNews(
  feeds: RssFeedSource[],
  forceRefresh = false,
): Promise<NewsAggregationResult> {
  const enabledFeeds = feeds.filter(
    (f) => f.enabled && isSafeExternalFeedUrl(f.url),
  );
  const feedsKey = enabledFeeds
    .map((f) => `${f.id}:${f.url}`)
    .sort()
    .join("|");

  if (
    !forceRefresh &&
    globalForNews.__eyesightNewsCache &&
    globalForNews.__eyesightNewsCache.feedsKey === feedsKey &&
    globalForNews.__eyesightNewsCache.expiresAt > Date.now()
  ) {
    return globalForNews.__eyesightNewsCache.data;
  }

  const settled = await Promise.all(
    enabledFeeds.map(async (feed) => {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 12000);
      try {
        const res = await fetch(feed.url, {
          signal: controller.signal,
          headers: {
            "User-Agent": "Mozilla/5.0 (compatible; eyesight-rss/1.0)",
            Accept:
              "application/rss+xml, application/atom+xml, application/xml, text/xml, */*",
          },
        });
        if (!res.ok) {
          return {
            status: {
              id: feed.id,
              name: feed.name,
              category: feed.category,
              ok: false,
              articleCount: 0,
              error: `HTTP ${res.status}`,
            },
            articles: [] as NewsArticle[],
          };
        }
        const xml = await res.text();
        const parsed = parseRssOrAtomXml(xml, feed.name, feed.category);
        return {
          status: {
            id: feed.id,
            name: feed.name,
            category: feed.category,
            ok: true,
            articleCount: parsed.length,
          },
          articles: parsed,
        };
      } catch (err) {
        return {
          status: {
            id: feed.id,
            name: feed.name,
            category: feed.category,
            ok: false,
            articleCount: 0,
            error: err instanceof Error ? err.message : "Fetch error",
          },
          articles: [] as NewsArticle[],
        };
      } finally {
        clearTimeout(timer);
      }
    }),
  );

  const allArticles = settled
    .flatMap((s) => s.articles)
    .sort((a, b) => Date.parse(b.publishedAt) - Date.parse(a.publishedAt));

  const result: NewsAggregationResult = {
    articles: allArticles,
    feedStatuses: settled.map((s) => s.status),
    fetchedAt: new Date().toISOString(),
  };

  if (settled.some((s) => s.status.ok)) {
    globalForNews.__eyesightNewsCache = {
      feedsKey,
      data: result,
      expiresAt: Date.now() + NEWS_CACHE_TTL_MS,
    };
  }

  return result;
}
