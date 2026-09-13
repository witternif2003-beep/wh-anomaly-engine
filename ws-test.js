// ws-test.js — verifies WebSocket broadcast + detection path end-to-end
const WebSocket = require('ws');
const { execSync } = require('child_process');

const ws = new WebSocket('ws://localhost:3000');
let gotAnomaly = false;

ws.on('open', () => {
  console.log('[WS] connected to ws://localhost:3000');
  const id = execSync(
    `redis-cli XADD network:firewall '*' source firewall_log timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" data '{"src_ip":"185.220.101.4","dst_ip":"10.0.0.50","bytes":52428800}'`
  ).toString().trim();
  console.log(`[INJECT] XADD ok, stream id=${id}`);
});

ws.on('message', (m) => {
  const msg = m.toString();
  console.log('[WS MSG]', msg);
  try {
    const parsed = JSON.parse(msg);
    if (parsed.type === 'anomaly') {
      gotAnomaly = true;
      console.log('[RESULT] WebSocket anomaly broadcast received ✓');
      setTimeout(() => process.exit(0), 500);
    }
  } catch (_) {}
});

ws.on('error', (e) => { console.error('[WS ERROR]', e.message); process.exit(1); });

setTimeout(() => {
  if (!gotAnomaly) { console.error('[RESULT] FAIL: no anomaly broadcast within 15s'); process.exit(1); }
}, 15000);
