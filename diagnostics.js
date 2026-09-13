// diagnostics.js — minimal working stub (ring buffer + subscribe)
class DiagnosticsManager {
  constructor(redisClient) {
    this.redis = redisClient;
    this.events = [];
    this.maxEvents = 500;
    this.listeners = new Set();
  }
  report(event) {
    const e = { ...event, ts: new Date().toISOString() };
    this.events.push(e);
    if (this.events.length > this.maxEvents) this.events.shift();
    for (const l of this.listeners) { try { l(e); } catch (_) {} }
  }
  subscribe(listener) { this.listeners.add(listener); }
  async getRecentEvents(n = 50) { return this.events.slice(-n); }
}
module.exports = DiagnosticsManager;
