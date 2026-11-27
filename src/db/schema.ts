import {
  pgTable,
  text,
  integer,
  boolean,
  timestamp,
  jsonb,
  uniqueIndex,
  index,
} from "drizzle-orm/pg-core";

export const users = pgTable(
  "users",
  {
    id: text("id").primaryKey(),
    email: text("email").notNull(),
    name: text("name").notNull(),
    passwordHash: text("password_hash").notNull(),
    role: text("role").notNull().default("analyst"), // 'admin' | 'analyst'
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [uniqueIndex("users_email_idx").on(table.email)],
);

export const sessions = pgTable(
  "sessions",
  {
    id: text("id").primaryKey(),
    userId: text("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    tokenHash: text("token_hash").notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [uniqueIndex("sessions_token_hash_idx").on(table.tokenHash)],
);

export const apiKeys = pgTable(
  "api_keys",
  {
    id: text("id").primaryKey(),
    userId: text("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    keyPrefix: text("key_prefix").notNull(),
    keyHash: text("key_hash").notNull(),
    lastUsedAt: timestamp("last_used_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [uniqueIndex("api_keys_hash_idx").on(table.keyHash)],
);

export const providerConfigs = pgTable("provider_configs", {
  providerId: text("provider_id").primaryKey(),
  weight: integer("weight").notNull().default(15),
  ttlSeconds: integer("ttl_seconds").notNull().default(3600),
  enabled: boolean("enabled").notNull().default(true),
  encryptedApiKey: text("encrypted_api_key"),
  updatedAt: timestamp("updated_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
});

export const userProviderKeys = pgTable(
  "user_provider_keys",
  {
    id: text("id").primaryKey(),
    userId: text("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    providerId: text("provider_id").notNull(),
    encryptedApiKey: text("encrypted_api_key").notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    uniqueIndex("user_provider_keys_user_provider_idx").on(
      table.userId,
      table.providerId,
    ),
  ],
);

export const scoringSettings = pgTable("scoring_settings", {
  id: text("id").primaryKey(), // 'default'
  maliciousThreshold: integer("malicious_threshold").notNull().default(70),
  suspiciousThreshold: integer("suspicious_threshold").notNull().default(30),
  updatedAt: timestamp("updated_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
});

export const providerCache = pgTable(
  "provider_cache",
  {
    id: text("id").primaryKey(),
    iocValue: text("ioc_value").notNull(),
    iocType: text("ioc_type").notNull(),
    providerId: text("provider_id").notNull(),
    status: text("status").notNull(),
    riskScore: integer("risk_score"),
    verdict: text("verdict").notNull(),
    summary: text("summary").notNull(),
    details: jsonb("details").$type<Record<string, unknown>>().notNull(),
    pivots: jsonb("pivots")
      .$type<Array<{ type: string; value: string; label?: string }>>()
      .notNull(),
    raw: jsonb("raw").$type<unknown>(),
    fetchedAt: timestamp("fetched_at", { withTimezone: true }).notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  },
  (table) => [
    uniqueIndex("provider_cache_lookup_idx").on(
      table.iocValue,
      table.iocType,
      table.providerId,
    ),
    index("provider_cache_expires_idx").on(table.expiresAt),
  ],
);

export const lookupHistory = pgTable(
  "lookup_history",
  {
    id: text("id").primaryKey(),
    userId: text("user_id"),
    iocValue: text("ioc_value").notNull(),
    iocType: text("ioc_type").notNull(),
    compositeScore: integer("composite_score"),
    verdict: text("verdict").notNull(),
    coverageCount: integer("coverage_count").notNull(),
    totalApplicable: integer("total_applicable").notNull(),
    summaryJson: jsonb("summary_json").$type<Record<string, unknown>>().notNull(),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    index("lookup_history_created_idx").on(table.createdAt),
    index("lookup_history_ioc_idx").on(table.iocValue),
  ],
);

export const rssFeeds = pgTable(
  "rss_feeds",
  {
    id: text("id").primaryKey(),
    name: text("name").notNull(),
    url: text("url").notNull(),
    category: text("category").notNull().default("NEWS"),
    enabled: boolean("enabled").notNull().default(true),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [uniqueIndex("rss_feeds_url_idx").on(table.url)],
);

export const toolWatchlist = pgTable("tool_watchlist", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  category: text("category").notNull().default("THREAT INTEL"),
  status: text("status").notNull().default("MONITORING"), // 'MONITORING' | 'PLANNED' | 'INTEGRATED'
  url: text("url"),
  notes: text("notes"),
  createdAt: timestamp("created_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
});

export const darkwebMonitors = pgTable("darkweb_monitors", {
  id: text("id").primaryKey(),
  target: text("target").notNull(),
  targetType: text("target_type").notNull().default("DOMAIN"), // 'DOMAIN' | 'BRAND' | 'EMAIL' | 'KEYWORD'
  notes: text("notes"),
  createdAt: timestamp("created_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
});
