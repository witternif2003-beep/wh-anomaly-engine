// persistencePg.js — Neon Postgres adapter, same contract as persistence.js (async).
// Selected automatically by api/index.js when DATABASE_URL is set; SQLite stays the
// default fallback. The HTTP-based driver (@neondatabase/serverless) is safe for
// serverless: no TCP connection pooling, no connection-count exhaustion.
// Engine-side note: the while(true) stream consumer cannot run on Vercel (stateless,
// short-lived functions) — it belongs on a persistent host, which can write to the
// same Neon database by setting the same DATABASE_URL there.
const { neon } = require('@neondatabase/serverless');

let sql = null;

// Returns true when a database URL was provided (wired), false otherwise (unwired).
function initDB(databaseUrl) {
  const url = databaseUrl || process.env.DATABASE_URL;
  if (!url) return false;
  sql = neon(url);
  return true;
}

// Idempotent schema bootstrap; safe to run on every cold start.
async function init() {
  if (!sql) return false;
  await sql`CREATE TABLE IF NOT EXISTS anomalies (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    rule_id     text        NOT NULL,
    severity    text        NOT NULL,
    description text,
    details     jsonb       NOT NULL DEFAULT '{}'::jsonb,
    timestamp   timestamptz NOT NULL
  )`;
  await sql`CREATE INDEX IF NOT EXISTS idx_anomalies_ts ON anomalies (timestamp DESC)`;
  return true;
}

async function saveAnomaly(anomaly) {
  await sql`INSERT INTO anomalies (rule_id, severity, description, details, timestamp)
            VALUES (${anomaly.ruleId}, ${anomaly.severity}, ${anomaly.description || null},
                    ${JSON.stringify(anomaly.details || {})}::jsonb, ${anomaly.timestamp})`;
}

async function getAnomalies(limit = 100) {
  const rows = await sql`SELECT id, rule_id, severity, description, details, timestamp
                         FROM anomalies ORDER BY id DESC LIMIT ${limit}`;
  return rows.map(r => ({
    id: r.id,
    rule_id: r.rule_id,
    severity: r.severity,
    description: r.description,
    details: r.details || {},
    timestamp: r.timestamp instanceof Date ? r.timestamp.toISOString() : r.timestamp
  }));
}

async function getTotalCount() {
  const rows = await sql`SELECT count(*)::int AS c FROM anomalies`;
  return rows[0].c;
}

module.exports = { initDB, init, saveAnomaly, getAnomalies, getTotalCount };
