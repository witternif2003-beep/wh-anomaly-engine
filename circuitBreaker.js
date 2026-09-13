// circuitBreaker.js — minimal working stub (in-memory state machine)
class AdvancedCircuitBreaker {
  constructor(redisClient) {
    this.redis = redisClient;
    this.breakers = new Map(); // name -> { state, failures, openedAt, lastError }
  }
  _get(name) {
    if (!this.breakers.has(name)) {
      this.breakers.set(name, { state: 'closed', failures: 0, openedAt: 0, lastError: null });
    }
    return this.breakers.get(name);
  }
  async execute(name, fn) {
    const b = this._get(name);
    // Half-open after 30s
    if (b.state === 'open' && Date.now() - b.openedAt > 30000) b.state = 'half-open';
    if (b.state === 'open') {
      throw new Error(`circuit '${name}' is open`);
    }
    try {
      const result = await fn();
      b.state = 'closed'; b.failures = 0;
      return result;
    } catch (err) {
      b.failures += 1;
      b.lastError = err.message;
      if (b.failures >= 5) { b.state = 'open'; b.openedAt = Date.now(); }
      throw err;
    }
  }
  async getStatus() {
    const out = {};
    for (const [name, b] of this.breakers) {
      out[name] = { state: b.state, failures: b.failures, lastError: b.lastError };
    }
    return out;
  }
}
module.exports = AdvancedCircuitBreaker;
