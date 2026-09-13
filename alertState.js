// alertState.js — minimal working stub (in-memory dedup + cooldown, Redis-shape-compatible)
class AlertState {
  constructor(redisClient) {
    this.redis = redisClient;
    this.seen = new Map();     // fingerprint -> ts
    this.cooldowns = new Map(); // ruleId -> lastFiredTs
    this.ttl = 3600000;        // 1h
    this.cooldownMs = 300000;  // 5min
  }
  async isDuplicate(anomaly) {
    const key = `${anomaly.ruleId}|${JSON.stringify(anomaly.details)}`;
    const now = Date.now();
    const last = this.seen.get(key) || 0;
    this.seen.set(key, now);
    // Prune old entries
    for (const [k, t] of this.seen) if (now - t > this.ttl) this.seen.delete(k);
    return now - last < this.ttl && last !== 0 && now - last < 1000;
  }
  async isCooldownActive(ruleId) {
    const now = Date.now();
    const last = this.cooldowns.get(ruleId) || 0;
    if (now - last < this.cooldownMs) return true;
    this.cooldowns.set(ruleId, now);
    return false;
  }
}
module.exports = AlertState;
