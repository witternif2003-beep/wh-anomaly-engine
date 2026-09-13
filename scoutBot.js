// scoutBot.js — minimal working stub (error capture, no crash on fatal)
class ScoutBot {
  constructor(redisClient, diagnostics) {
    this.redis = redisClient;
    this.diagnostics = diagnostics;
  }
  captureError(err, meta = {}) {
    const msg = err && err.message ? err.message : String(err);
    try { this.diagnostics.report({ source: 'scoutBot', message: msg, severity: meta.fatal ? 'CRITICAL' : 'MEDIUM', meta }); } catch (_) {}
    console.error('[scout]', msg);
  }
}
module.exports = ScoutBot;
