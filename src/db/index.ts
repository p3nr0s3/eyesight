import fs from "node:fs";
import path from "node:path";
import { sql } from "drizzle-orm";
import { drizzle as drizzlePg } from "drizzle-orm/node-postgres";
import { drizzle as drizzlePglite } from "drizzle-orm/pglite";
import { PGlite } from "@electric-sql/pglite";
import { Pool } from "pg";
import * as schema from "./schema";
import { PROVIDER_CATALOG } from "@/lib/providers/catalog";

type DbInstance =
  | ReturnType<typeof drizzlePg<typeof schema>>
  | ReturnType<typeof drizzlePglite<typeof schema>>;

const SCHEMA_VERSION = "2026-11-27-v3";

const globalForDb = globalThis as unknown as {
  __eyesightDb?: DbInstance;
  __eyesightInitPromise?: Promise<DbInstance>;
  __eyesightSchemaVersion?: string;
  __eyesightMigrationPromise?: Promise<void>;
  __eyesightMode?: "postgres" | "pglite";
};

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'analyst',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS users_email_idx ON users (email);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS sessions_token_hash_idx ON sessions (token_hash);

CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  key_prefix TEXT NOT NULL,
  key_hash TEXT NOT NULL,
  last_used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS api_keys_hash_idx ON api_keys (key_hash);

CREATE TABLE IF NOT EXISTS provider_configs (
  provider_id TEXT PRIMARY KEY,
  weight INTEGER NOT NULL DEFAULT 15,
  ttl_seconds INTEGER NOT NULL DEFAULT 3600,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  encrypted_api_key TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS user_provider_keys (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider_id TEXT NOT NULL,
  encrypted_api_key TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS user_provider_keys_user_provider_idx ON user_provider_keys (user_id, provider_id);

CREATE TABLE IF NOT EXISTS scoring_settings (
  id TEXT PRIMARY KEY,
  malicious_threshold INTEGER NOT NULL DEFAULT 70,
  suspicious_threshold INTEGER NOT NULL DEFAULT 30,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS provider_cache (
  id TEXT PRIMARY KEY,
  ioc_value TEXT NOT NULL,
  ioc_type TEXT NOT NULL,
  provider_id TEXT NOT NULL,
  status TEXT NOT NULL,
  risk_score INTEGER,
  verdict TEXT NOT NULL,
  summary TEXT NOT NULL,
  details JSONB NOT NULL,
  pivots JSONB NOT NULL,
  raw JSONB,
  fetched_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS provider_cache_lookup_idx ON provider_cache (ioc_value, ioc_type, provider_id);
CREATE INDEX IF NOT EXISTS provider_cache_expires_idx ON provider_cache (expires_at);

CREATE TABLE IF NOT EXISTS lookup_history (
  id TEXT PRIMARY KEY,
  user_id TEXT,
  ioc_value TEXT NOT NULL,
  ioc_type TEXT NOT NULL,
  composite_score INTEGER,
  verdict TEXT NOT NULL,
  coverage_count INTEGER NOT NULL,
  total_applicable INTEGER NOT NULL,
  summary_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS lookup_history_created_idx ON lookup_history (created_at);
CREATE INDEX IF NOT EXISTS lookup_history_ioc_idx ON lookup_history (ioc_value);

CREATE TABLE IF NOT EXISTS rss_feeds (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  url TEXT NOT NULL,
  category TEXT NOT NULL DEFAULT 'NEWS',
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS rss_feeds_url_idx ON rss_feeds (url);

CREATE TABLE IF NOT EXISTS tool_watchlist (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  category TEXT NOT NULL DEFAULT 'THREAT INTEL',
  status TEXT NOT NULL DEFAULT 'MONITORING',
  url TEXT,
  notes TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS darkweb_monitors (
  id TEXT PRIMARY KEY,
  target TEXT NOT NULL,
  target_type TEXT NOT NULL DEFAULT 'DOMAIN',
  notes TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
`;

async function seedDefaults(db: DbInstance) {
  await db
    .insert(schema.scoringSettings)
    .values({
      id: "default",
      maliciousThreshold: 70,
      suspiciousThreshold: 30,
    })
    .onConflictDoNothing();

  for (const p of PROVIDER_CATALOG) {
    await db
      .insert(schema.providerConfigs)
      .values({
        providerId: p.id,
        weight: p.defaultWeight,
        ttlSeconds: p.defaultTtlSeconds,
        enabled: true,
      })
      .onConflictDoNothing();
  }

  const defaultFeeds = [
    {
      id: "feed-bleeping",
      name: "BleepingComputer",
      url: "https://www.bleepingcomputer.com/feed/",
      category: "THREAT NEWS",
      enabled: true,
    },
    {
      id: "feed-thn",
      name: "The Hacker News",
      url: "https://feeds.feedburner.com/TheHackersNews",
      category: "CYBER NEWS",
      enabled: true,
    },
    {
      id: "feed-cisa",
      name: "CISA Advisories",
      url: "https://www.cisa.gov/cybersecurity-advisories/all.xml",
      category: "ADVISORY",
      enabled: true,
    },
    {
      id: "feed-krebs",
      name: "Krebs on Security",
      url: "https://krebsonsecurity.com/feed/",
      category: "INVESTIGATIONS",
      enabled: true,
    },
    {
      id: "feed-sans",
      name: "SANS ISC Diary",
      url: "https://isc.sans.edu/rssfeed.xml",
      category: "THREAT INTEL",
      enabled: true,
    },
  ];

  for (const feed of defaultFeeds) {
    await db
      .insert(schema.rssFeeds)
      .values(feed)
      .onConflictDoNothing();
  }

  const existingWatchlist = await db
    .select({ id: schema.toolWatchlist.id })
    .from(schema.toolWatchlist)
    .limit(1);

  if (existingWatchlist.length === 0) {
    const defaultWatchlist = [
      {
        id: "watch-misp",
        name: "MISP Threat Sharing",
        category: "THREAT INTEL",
        status: "PLANNED",
        url: "https://www.misp-project.org",
        notes: "Open-source threat intelligence sharing & STIX/TAXII correlation.",
      },
      {
        id: "watch-opencti",
        name: "OpenCTI",
        category: "THREAT INTEL",
        status: "MONITORING",
        url: "https://www.opencti.io",
        notes: "Knowledge graph for threat actors, campaigns, and TTPs.",
      },
      {
        id: "watch-nuclei",
        name: "ProjectDiscovery Nuclei",
        category: "SCANNER",
        status: "MONITORING",
        url: "https://github.com/projectdiscovery/nuclei",
        notes: "Template-driven CVE & misconfiguration scanner.",
      },
      {
        id: "watch-yara",
        name: "YARA-X",
        category: "MALWARE ANALYSIS",
        status: "PLANNED",
        url: "https://virustotal.github.io/yara-x/",
        notes: "Next-gen Rust YARA rule matching for malware samples.",
      },
    ];
    for (const item of defaultWatchlist) {
      await db.insert(schema.toolWatchlist).values(item).onConflictDoNothing();
    }
  }

  const existingMonitors = await db
    .select({ id: schema.darkwebMonitors.id })
    .from(schema.darkwebMonitors)
    .limit(1);

  if (existingMonitors.length === 0) {
    const defaultMonitors = [
      {
        id: "dw-mon-1",
        target: "dropbox.com",
        targetType: "DOMAIN",
        notes: "Sample SaaS domain exposure & breach monitor",
      },
      {
        id: "dw-mon-2",
        target: "university",
        targetType: "KEYWORD",
        notes: "Education sector ransomware leak keyword monitor",
      },
    ];
    for (const mon of defaultMonitors) {
      await db.insert(schema.darkwebMonitors).values(mon).onConflictDoNothing();
    }
  }
}

async function applySchemaAndSeed(db: DbInstance): Promise<void> {
  const statements = SCHEMA_SQL.split(";")
    .map((s) => s.trim())
    .filter(Boolean);
  for (const stmt of statements) {
    await db.execute(sql.raw(stmt));
  }
  await seedDefaults(db);
  globalForDb.__eyesightSchemaVersion = SCHEMA_VERSION;
}

async function ensureSchemaUpToDate(db: DbInstance): Promise<void> {
  if (globalForDb.__eyesightSchemaVersion === SCHEMA_VERSION) {
    return;
  }
  if (!globalForDb.__eyesightMigrationPromise) {
    globalForDb.__eyesightMigrationPromise = applySchemaAndSeed(db).finally(
      () => {
        globalForDb.__eyesightMigrationPromise = undefined;
      },
    );
  }
  await globalForDb.__eyesightMigrationPromise;
}

async function initDb(): Promise<DbInstance> {
  const databaseUrl = process.env.DATABASE_URL?.trim();

  if (databaseUrl) {
    const pool = new Pool({
      connectionString: databaseUrl,
      max: 5,
      ssl:
        databaseUrl.includes("localhost") || databaseUrl.includes("127.0.0.1")
          ? undefined
          : { rejectUnauthorized: false },
    });
    const db = drizzlePg(pool, { schema });
    await ensureSchemaUpToDate(db);
    globalForDb.__eyesightMode = "postgres";
    globalForDb.__eyesightDb = db;
    return db;
  }

  // Local zero-install embedded PostgreSQL via PGlite
  const isTest = process.env.NODE_ENV === "test" || process.env.VITEST === "true";
  let client: PGlite;
  if (isTest) {
    client = new PGlite();
  } else {
    const dataDir = path.resolve(process.cwd(), ".eyesight-data", "pglite");
    fs.mkdirSync(dataDir, { recursive: true });
    client = new PGlite(dataDir);
  }
  await client.waitReady;
  const db = drizzlePglite(client, { schema });
  await ensureSchemaUpToDate(db);
  globalForDb.__eyesightMode = "pglite";
  globalForDb.__eyesightDb = db;
  return db;
}

export async function getDb(): Promise<DbInstance> {
  if (globalForDb.__eyesightDb) {
    await ensureSchemaUpToDate(globalForDb.__eyesightDb);
    return globalForDb.__eyesightDb;
  }
  if (!globalForDb.__eyesightInitPromise) {
    globalForDb.__eyesightInitPromise = initDb().catch((err) => {
      globalForDb.__eyesightInitPromise = undefined;
      throw err;
    });
  }
  return globalForDb.__eyesightInitPromise;
}

export function getDbMode(): "postgres" | "pglite" {
  if (globalForDb.__eyesightMode) return globalForDb.__eyesightMode;
  return process.env.DATABASE_URL?.trim() ? "postgres" : "pglite";
}

export { schema };
