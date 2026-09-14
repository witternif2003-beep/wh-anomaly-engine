// api/index.js — Vercel serverless entry (HTTP API surface of WH Anomaly Tracker)
// NOTE: the long-running subsystems (WebSocket broadcast, Redis stream consumer,
// scheduled self-checks) need a persistent host. This function serves the
// health/read API; point REDIS_URL at a reachable instance (e.g. Upstash) and
// deploy main.js on a VM/container for the full pipeline.
const express = require('express');
const helmet = require('helmet');
const path = require('path');
const fs = require('fs');
const yaml = require('js-yaml');
const promClient = require('prom-client');
const sqlite = require('../persistence');
const pg = require('../persistencePg');

const app = express();
app.use(helmet());        // security headers (CSP, HSTS, nosniff, frameguard, hides x-powered-by)
app.use(express.json());

// Backend selection: Neon Postgres when DATABASE_URL is set (durable, serverless-safe
// HTTP driver); SQLite fallback otherwise. On Vercel the SQLite file lives on ephemeral
// /tmp — per-instance and wiped on cold start — so DATABASE_URL is required for durable
// persistence in production. No secret is hardcoded anywhere; the value arrives via env.
const usePg = pg.initDB();            // false when DATABASE_URL is unset
const pgReady = usePg ? pg.init() : Promise.resolve(false); // idempotent DDL
if (!usePg) {
  sqlite.initDB(process.env.VERCEL
    ? '/tmp/anomalies.db'
    : path.join(__dirname, '..', 'data', 'anomalies.db'));
}
const store = {
  async getAnomalies(limit) { return usePg ? pg.getAnomalies(limit) : sqlite.getAnomalies(limit); },
  async getTotalCount() { return usePg ? pg.getTotalCount() : sqlite.getTotalCount(); }
};

const promRegister = new promClient.Registry();
promClient.collectDefaultMetrics({ register: promRegister });
const anomalyCounter = new promClient.Counter({
  name: 'wh_anomalies_total',
  help: 'Total anomalies detected',
  labelNames: ['severity', 'rule_id'],
  registers: [promRegister]
});

let rules = [];
function findRuleFile(name) {
  // Serverless bundles may place included files at the lambda root or alongside
  // the entrypoint; local runs use the project root. Try all candidates.
  return [
    path.join(__dirname, name),
    path.join(__dirname, '..', name),
    path.join(process.cwd(), name)
  ].find(p => fs.existsSync(p));
}
for (const f of ['rules.yaml', 'p1-rules.yaml']) {
  const fp = findRuleFile(f);
  if (fp) {
    try { rules = rules.concat((yaml.load(fs.readFileSync(fp, 'utf8')) || {}).rules || []); } catch (_) {}
  }
}

app.get('/', (req, res) => {
  // No static frontend exists in this repo (no public/ or dist/), so /
  // serves a JSON service index instead of Cannot GET /
  res.json({
    service: 'wh-anomaly-tracker',
    status: 'ok',
    env: process.env.VERCEL ? 'serverless' : 'node',
    storage: usePg ? 'postgres' : 'sqlite-ephemeral',
    rules: rules.length,
    endpoints: ['/health/siem', '/api/stats', '/api/anomalies', '/metrics']
  });
});

app.get('/health/siem', async (req, res) => {
  let dbReady = true;
  if (usePg) { try { await pgReady; } catch (_) { dbReady = false; } }
  res.json({
    status: dbReady ? 'ok' : 'degraded',
    env: process.env.VERCEL ? 'serverless' : 'node',
    storage: usePg ? 'postgres' : 'sqlite-ephemeral',
    redis: process.env.REDIS_URL ? 'configured' : 'not_configured',
    rules: rules.length,
    uptime: process.uptime()
  });
});

app.get('/metrics', async (req, res) => {
  res.set('Content-Type', promRegister.contentType);
  res.end(await promRegister.metrics());
});

app.get('/api/anomalies', async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 100, 500); // clamp to protect storage
  res.json(await store.getAnomalies(limit));
});

app.get('/api/stats', async (req, res) => {
  res.json({ total: await store.getTotalCount(), uptime: process.uptime(), rules: rules.length });
});

// JSON 404 fallback — replaces Express's text/html "Cannot GET <path>" default
app.use((req, res) => {
  res.status(404).json({
    error: 'not_found',
    path: req.path,
    endpoints: ['/health/siem', '/api/stats', '/api/anomalies', '/metrics']
  });
});

module.exports = app;
