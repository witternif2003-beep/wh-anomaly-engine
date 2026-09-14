// main.js — WH Anomaly Tracker (Complete Integration)
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const redis = require('redis');
const yaml = require('js-yaml');
const fs = require('fs');
const path = require('path');
const promClient = require('prom-client');

// ─── Local Modules ───
const AdvancedCircuitBreaker = require('./circuitBreaker');
const DiagnosticsManager = require('./diagnostics');
const HiddenErrorFinder = require('./hiddenErrorFinder');
const ScoutBot = require('./scoutBot');
const VirusTotalClient = require('./virustotalClient');
const AlertState = require('./alertState');
const AlertRouter = require('./alertRouter');
const MemgraphClient = require('./memgraphClient');
const sqlite = require('./persistence');
const pg = require('./persistencePg');
const ReportGenerator = require('./reportGenerator');

// ─── Config ───
const PORT = process.env.PORT || 3000;
const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6379';
const WORKER_COUNT = parseInt(process.env.WORKER_COUNT || '4', 10);
const DISABLE_AUTH = process.env.DISABLE_AUTH === 'true';
const STREAM_KEY = process.env.STREAM_KEY || 'network:firewall';
const GROUP_NAME = 'wh_anomaly_group';

// ─── Express & WebSocket ───
const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
app.use(express.json());
app.use(express.static('public'));

// ─── Prometheus ───
const collectDefaultMetrics = promClient.collectDefaultMetrics;
collectDefaultMetrics();
const anomalyCounter = new promClient.Counter({
  name: 'wh_anomalies_total',
  help: 'Total anomalies detected',
  labelNames: ['severity', 'rule_id']
});
const eventCounter = new promClient.Counter({
  name: 'wh_events_processed_total',
  help: 'Total events processed from Redis streams'
});

// ─── Worker Pool (in-process, consistent-hash) ───
class InProcessWorkerPool {
  constructor(ruleCount, evaluatorFactory) {
    this.evaluatorFactory = evaluatorFactory;
    this.evaluators = [];
    this.eventBuffer = [];
    this.bufferSize = 100;
    this.flushIntervalMs = 100;
    this.listeners = new Set();
    this.startFlushLoop();
  }

  loadRules(rules) {
    this.evaluators = rules.map(r => this.evaluatorFactory(r));
    console.log(`📋 Loaded ${this.evaluators.length} evaluators`);
  }

  on(event, listener) { this.listeners.add(listener); }

  // node-redis v4 returns stream fields as an object ({k: v}); raw replies may be
  // alternating arrays. Normalize both to an alternating array before parsing.
  static normalizeFields(fields) {
    if (Array.isArray(fields)) return fields;
    const out = [];
    for (const [k, v] of Object.entries(fields || {})) out.push(k, v);
    return out;
  }

  dispatch(redisMsg) {
    try {
      if (!redisMsg || typeof redisMsg !== 'object') return;
      const fields = InProcessWorkerPool.normalizeFields(redisMsg);
      const data = {};
      // Parse Redis stream fields: alternating key/value pairs
      for (let i = 0; i < fields.length; i += 2) {
        if (fields[i] === 'data') {
          try { data.data = JSON.parse(fields[i + 1]); } catch (_) { data.data = fields[i + 1]; }
        } else {
          data[fields[i]] = fields[i + 1];
        }
      }
      if (Object.keys(data).length === 0) return; // drop unparseable/empty events
      this.eventBuffer.push(data);
      if (this.eventBuffer.length >= this.bufferSize) {
        this.flush();
      }
    } catch (err) {
      console.error('Dispatch error:', err.message);
    }
  }

  flush() {
    if (this.eventBuffer.length === 0) return;
    const batch = this.eventBuffer.splice(0);
    for (const evaluator of this.evaluators) {
      try {
        const result = evaluator.evaluate(batch);
        if (result && result.triggered) {
          const anomaly = {
            ruleId: evaluator.rule.id,
            severity: evaluator.rule.severity || 'MEDIUM',
            description: evaluator.rule.description || evaluator.rule.name,
            details: result.details || {},
            timestamp: new Date().toISOString()
          };
          for (const listener of this.listeners) listener(anomaly);
        }
      } catch (err) {
        console.error(`Evaluator ${evaluator.rule?.id} error:`, err.message);
      }
    }
  }

  startFlushLoop() {
    setInterval(() => this.flush(), this.flushIntervalMs);
  }
}

// ─── Evaluator Factory ───
function createEvaluator(rule) {
  const type = rule.detection?.type || rule.type || 'threshold';

  switch (type) {
    case 'threshold':
      return createThresholdEvaluator(rule);
    case 'pattern':
      return createPatternEvaluator(rule);
    case 'signature':
      return createSignatureEvaluator(rule);
    case 'correlation':
      return createCorrelationEvaluator(rule);
    case 'statistical':
      return createStatisticalEvaluator(rule);
    case 'custom-frequency':
      return createFrequencyEvaluator(rule);
    default:
      return createThresholdEvaluator(rule);
  }
}

function createThresholdEvaluator(rule) {
  const params = rule.detection?.parameters || rule.parameters || {};
  const source = rule.detection?.source || rule.source;
  const field = params.field;
  const threshold = params.threshold || params.count_threshold || 100;
  const windowMs = (params.window_seconds || 60) * 1000;
  const values = [];

  return {
    rule,
    evaluate(events) {
      const now = Date.now();
      for (const ev of events) {
        if (source && ev.source !== source) continue;
        if (field && ev.data?.[field] !== undefined) {
          values.push({ ts: now, val: ev.data[field] });
        }
      }
      while (values.length > 0 && (now - values[0].ts) >= windowMs) values.shift();
      if (values.length >= threshold) {
        return { triggered: true, details: { count: values.length, threshold, window: params.window_seconds } };
      }
      return { triggered: false };
    }
  };
}

function createPatternEvaluator(rule) {
  const params = rule.detection?.parameters || rule.parameters || {};
  const source = rule.detection?.source || rule.source;
  const pattern = new RegExp(params.pattern || params.regex || '.*', 'i');
  const field = params.field || 'raw';

  return {
    rule,
    evaluate(events) {
      for (const ev of events) {
        if (source && ev.source !== source) continue;
        const value = String(ev.data?.[field] || ev[field] || '');
        if (pattern.test(value)) {
          return { triggered: true, details: { matched: value.slice(0, 200) } };
        }
      }
      return { triggered: false };
    }
  };
}

function createSignatureEvaluator(rule) {
  const params = rule.detection?.parameters || rule.parameters || {};
  const source = rule.detection?.source || rule.source;
  const iocType = params.ioc_type || 'ip';
  const iocList = params.iocs || [];

  return {
    rule,
    evaluate(events) {
      for (const ev of events) {
        if (source && ev.source !== source) continue;
        const value = ev.data?.[iocType] || ev.data?.src_ip || ev.data?.dst_ip;
        if (value && iocList.includes(value)) {
          return { triggered: true, details: { ioc_type: iocType, value } };
        }
      }
      return { triggered: false };
    }
  };
}

function createCorrelationEvaluator(rule) {
  const params = rule.detection?.parameters || rule.parameters || {};
  const sources = params.sources || [];
  const conditions = params.conditions || [];
  const matches = new Map();

  return {
    rule,
    evaluate(events) {
      for (const ev of events) {
        if (sources.length > 0 && !sources.includes(ev.source)) continue;
        const key = ev.data?.src_ip || ev.data?.user || 'default';
        if (!matches.has(key)) matches.set(key, new Set());
        matches.get(key).add(ev.source);
      }
      for (const [key, matchedSources] of matches) {
        if (matchedSources.size >= conditions.length) {
          return { triggered: true, details: { correlated_key: key, sources: [...matchedSources] } };
        }
      }
      return { triggered: false };
    }
  };
}

function createStatisticalEvaluator(rule) {
  const params = rule.detection?.parameters || rule.parameters || {};
  const field = params.field;
  const stdDevs = params.std_deviations || 3;
  const windowMs = (params.window_seconds || 300) * 1000;
  const values = [];

  return {
    rule,
    evaluate(events) {
      const now = Date.now();
      for (const ev of events) {
        const val = parseFloat(ev.data?.[field]);
        if (!isNaN(val)) values.push({ ts: now, val });
      }
      while (values.length > 0 && (now - values[0].ts) >= windowMs) values.shift();
      if (values.length < 30) return { triggered: false };
      const nums = values.map(v => v.val);
      const mean = nums.reduce((a, b) => a + b, 0) / nums.length;
      const stdDev = Math.sqrt(nums.reduce((s, n) => s + (n - mean) ** 2, 0) / nums.length);
      const latest = nums[nums.length - 1];
      if (Math.abs(latest - mean) > stdDevs * stdDev) {
        return { triggered: true, details: { value: latest, mean, stdDev, zScore: (latest - mean) / stdDev } };
      }
      return { triggered: false };
    }
  };
}

function createFrequencyEvaluator(rule) {
  const params = rule.detection?.parameters || rule.parameters || {};
  const source = rule.detection?.source || rule.source;
  const field = params.field || 'src_ip';
  const threshold = params.count_threshold || 50;
  const windowMs = (params.window_seconds || 60) * 1000;
  const eventsByKey = new Map();

  return {
    rule,
    evaluate(events) {
      const now = Date.now();
      for (const ev of events) {
        if (source && ev.source !== source) continue;
        const key = ev.data?.[field];
        if (!key) continue;
        if (!eventsByKey.has(key)) eventsByKey.set(key, []);
        const bucket = eventsByKey.get(key);
        while (bucket.length > 0 && (now - bucket[0]) >= windowMs) bucket.shift();
        bucket.push(now);
      }
      const suspicious = [];
      for (const [key, bucket] of eventsByKey) {
        if (bucket.length >= threshold) suspicious.push({ key, count: bucket.length });
      }
      if (suspicious.length > 0) return { triggered: true, details: { suspicious_keys: suspicious } };
      return { triggered: false };
    }
  };
}

// ─── Main Start ───
async function start() {
  // 1. Redis
  const redisClient = redis.createClient({ url: REDIS_URL });
  let diagnosticsRef = null; // avoids TDZ ReferenceError if Redis errors during connect()
  redisClient.on('error', err => {
    console.error('Redis error:', err.message);
    if (diagnosticsRef) diagnosticsRef.report({ source: 'redis', message: err.message, severity: 'CRITICAL' });
  });
  await redisClient.connect();
  console.log('✅ Redis connected');

  // 2. Persistence — Neon Postgres when DATABASE_URL is set, SQLite (WAL) fallback.
  // Architecture note: this engine process runs the while(true) stream consumer and
  // owns the WRITE path, so it must live on a persistent host (VM/container) — Vercel
  // functions are stateless and short-lived and must never run this loop. Vercel hosts
  // only the read API (api/index.js) against the same database.
  const usePg = pg.initDB(); // false when DATABASE_URL is unset
  if (usePg) {
    await pg.init().catch(err => console.error('⚠️  Postgres schema init failed:', err.message));
    console.log('✅ Persistence: Neon Postgres (DATABASE_URL)');
  } else {
    sqlite.initDB();
    console.log('✅ SQLite initialized (WAL mode)');
  }
  const store = {
    async saveAnomaly(a) { return usePg ? pg.saveAnomaly(a) : sqlite.saveAnomaly(a); },
    async getAnomalies(l) { return usePg ? pg.getAnomalies(l) : sqlite.getAnomalies(l); },
    async getTotalCount() { return usePg ? pg.getTotalCount() : sqlite.getTotalCount(); }
  };

  // 3. Circuit Breaker
  const circuitBreaker = new AdvancedCircuitBreaker(redisClient);

  // 4. Diagnostics
  const diagnostics = new DiagnosticsManager(redisClient);
  diagnosticsRef = diagnostics;
  const hiddenFinder = new HiddenErrorFinder(redisClient, diagnostics);
  const scout = new ScoutBot(redisClient, diagnostics);
  hiddenFinder.start(60000);

  // 5. Threat Intel
  const vtClient = new VirusTotalClient(process.env.VIRUSTOTAL_API_KEY, redisClient);

  // 6. Alerting
  const alertState = new AlertState(redisClient);
  let suppressionList = [];
  try {
    suppressionList = JSON.parse(fs.readFileSync(path.join(__dirname, 'suppression.json'), 'utf8'));
  } catch (e) { suppressionList = []; }
  setInterval(() => {
    try { suppressionList = JSON.parse(fs.readFileSync(path.join(__dirname, 'suppression.json'), 'utf8')); } catch (e) {}
  }, 300000);

  // 7. Graph
  let graphClient = null;
  try {
    graphClient = new MemgraphClient(process.env.MEMGRAPH_URI);
    await graphClient.connect();
  } catch (err) {
    console.warn('⚠️  Memgraph unavailable, graph features disabled');
  }

  // 8. Worker Pool & Rules
  const workerPool = new InProcessWorkerPool(WORKER_COUNT, createEvaluator);
  let rules = [];
  try {
    const ruleFiles = ['rules.yaml', 'p1-rules.yaml'];
    for (const f of ruleFiles) {
      const fp = path.join(__dirname, f);
      if (fs.existsSync(fp)) {
        const data = yaml.load(fs.readFileSync(fp, 'utf8'));
        rules = rules.concat(data.rules || []);
      }
    }
  } catch (err) {
    console.warn('⚠️  No rule files found, detection disabled');
  }
  workerPool.loadRules(rules);

  // 9. Broadcast
  function broadcast(type, data) {
    const msg = JSON.stringify({ type, data });
    wss.clients.forEach(c => { if (c.readyState === WebSocket.OPEN) c.send(msg); });
  }

  diagnostics.subscribe(event => broadcast('diagnostic', event));

  // 10. Anomaly Pipeline
  workerPool.on('anomaly', async (anomaly) => {
    try {
      if (isSuppressed(anomaly)) return;
      if (await alertState.isDuplicate(anomaly)) return;
      if (await alertState.isCooldownActive(anomaly.ruleId)) return;

      anomalyCounter.inc({ severity: anomaly.severity, rule_id: anomaly.ruleId });
      store.saveAnomaly(anomaly).catch(err => scout.captureError(err, { context: 'db_write' }));
      broadcast('anomaly', anomaly);

      if (graphClient) {
        graphClient.recordAnomaly(anomaly).catch(() => {});
      }

      // Route to all configured channels
      if (process.env.SLACK_WEBHOOK_URL) sendSlack(anomaly).catch(() => {});
      if (process.env.PAGERDUTY_ROUTING_KEY) sendPagerDuty(anomaly).catch(() => {});
      if (process.env.SIEM_URL) sendSIEM(anomaly).catch(() => {});

    } catch (err) {
      scout.captureError(err, { context: 'anomaly_pipeline' });
    }
  });

  function isSuppressed(anomaly) {
    return suppressionList.some(s =>
      (!s.ruleId || s.ruleId === anomaly.ruleId) &&
      (!s.src_ip || anomaly.details?.src_ip === s.src_ip)
    );
  }

  // 11. External Callers (wrapped in circuit breaker)
  async function sendSIEM(anomaly) {
    return circuitBreaker.execute('siem', async () => {
      const axios = require('axios');
      return axios.post(process.env.SIEM_URL, {
        event: anomaly.description,
        severity: anomaly.severity,
        rule: anomaly.ruleId,
        details: anomaly.details,
        timestamp: anomaly.timestamp
      }, {
        headers: { Authorization: `Splunk ${process.env.SIEM_TOKEN}` },
        timeout: 5000
      });
    });
  }

  async function sendSlack(anomaly) {
    return circuitBreaker.execute('slack', async () => {
      const axios = require('axios');
      const emoji = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🟢' };
      return axios.post(process.env.SLACK_WEBHOOK_URL, {
        text: `${emoji[anomaly.severity] || '⚪'} *${anomaly.severity}* — ${anomaly.ruleId}\n${anomaly.description}\n_${anomaly.timestamp}_`
      }, { timeout: 5000 });
    });
  }

  async function sendPagerDuty(anomaly) {
    if (anomaly.severity !== 'P1' && anomaly.severity !== 'CRITICAL') return;
    return circuitBreaker.execute('pagerduty', async () => {
      const axios = require('axios');
      return axios.post('https://events.pagerduty.com/v2/enqueue', {
        routing_key: process.env.PAGERDUTY_ROUTING_KEY,
        event_action: 'trigger',
        payload: {
          summary: `${anomaly.ruleId}: ${anomaly.description}`,
          severity: 'critical',
          source: 'wh-anomaly-tracker',
          timestamp: anomaly.timestamp
        }
      }, { timeout: 5000 });
    });
  }

  // 12. Redis Stream Consumer
  const consumerName = `consumer_${process.pid}`;
  try {
    await redisClient.xGroupCreate(STREAM_KEY, GROUP_NAME, '0', { MKSTREAM: true });
  } catch (e) { /* group exists */ }

  async function consume() {
    while (true) {
      try {
        const response = await redisClient.xReadGroup(
          redis.commandOptions({ isolated: true }),
          GROUP_NAME, consumerName,
          [{ key: STREAM_KEY, id: '>' }],
          { COUNT: 100, BLOCK: 5000 }
        );
        if (response) {
          for (const stream of response) {
            for (const msg of stream.messages) {
              workerPool.dispatch(msg.message); // redis v4: reply is { id, message: {k: v} }
              eventCounter.inc(); // count actual events, not poll iterations
              await redisClient.xAck(STREAM_KEY, GROUP_NAME, msg.id);
            }
          }
        }
      } catch (err) {
        scout.captureError(err, { context: 'redis_consumer' });
        await new Promise(r => setTimeout(r, 5000));
      }
    }
  }

  // 13. API Routes
  app.get('/health/siem', (req, res) => res.json({ status: 'ok', uptime: process.uptime() }));
  app.get('/metrics', async (req, res) => {
    res.set('Content-Type', promClient.register.contentType);
    res.end(await promClient.register.metrics());
  });
  app.get('/api/anomalies', async (req, res) => {
    const limit = parseInt(req.query.limit) || 100;
    res.json(await store.getAnomalies(limit));
  });
  app.get('/api/stats', async (req, res) => {
    res.json({ total: await store.getTotalCount(), uptime: process.uptime(), rules: rules.length });
  });
  app.get('/api/circuit-breakers', async (req, res) => {
    res.json(await circuitBreaker.getStatus());
  });
  app.get('/api/diagnostics', async (req, res) => {
    const events = await diagnostics.getRecentEvents(50);
    res.json({ events, commonCauses: [] });
  });

  // 14. Start
  server.listen(PORT, () => {
    console.log(`🚀 WH Anomaly Tracker — ${rules.length} rules loaded`);
    console.log(`📡 Dashboard: http://localhost:${PORT}`);
    console.log(`📊 Prometheus: http://localhost:${PORT}/metrics`);
    consume(); // Start consumer (non-blocking)
  });

  process.on('uncaughtException', err => scout.captureError(err, { fatal: true }));
  process.on('unhandledRejection', reason => scout.captureError(reason, { fatal: false }));
}

start().catch(err => { console.error('Fatal:', err); process.exit(1); });
