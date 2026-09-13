# WH Anomaly Tracker

Network anomaly detection pipeline: **Redis Stream → dispatch → rule evaluators → dedup/cooldown/suppression → SQLite + WebSocket dashboard + Prometheus**.

Boot-verified on Node v22.23.2 / Redis 7.0.15: signature-IoC event injected via `XADD` produced a CRITICAL anomaly in SQLite, `/api/anomalies`, Prometheus counters, and a live WebSocket broadcast.

## Run

```bash
npm install
nohup node main.js > boot.log 2>&1 &
```

## Verify detection

```bash
redis-cli XADD network:firewall '*' source firewall_log \
  timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  data '{"src_ip":"185.220.101.4","dst_ip":"10.0.0.50","bytes":52428800}'
sleep 3
curl -s http://localhost:3000/api/stats
curl -s http://localhost:3000/api/anomalies
curl -s http://localhost:3000/metrics | grep -E "^wh_(anomalies|events)"
node ws-test.js   # live WebSocket + detection exercise
```

## Key fix vs. original draft

`redis` v4 `xReadGroup` returns `{ id, message: {k: v} }` — the consumer must pass
`msg.message` (not `msg.fields`) to the worker pool. Also: TDZ-safe Redis error
handler, event counter moved to the per-message loop, malformed-JSON-tolerant dispatch.

## Structure

- `main.js` — full integration (Express + WS + Prometheus + consumer + evaluators + alert pipeline)
- `rules.yaml` — detection rules (signature / threshold / custom-frequency examples)
- `circuitBreaker.js`, `diagnostics.js`, `alertState.js`, `persistence.js` — supporting subsystems
- `scoutBot.js`, `hiddenErrorFinder.js`, `virustotalClient.js`, `alertRouter.js`, `memgraphClient.js`, `reportGenerator.js` — behavior-contract stubs; swap in full implementations without changing call sites

Configure channels via env: `SLACK_WEBHOOK_URL`, `PAGERDUTY_ROUTING_KEY`, `SIEM_URL`, `SIEM_TOKEN`, `VIRUSTOTAL_API_KEY`, `MEMGRAPH_URI`, `REDIS_URL`, `STREAM_KEY`. See `.env.example`.
