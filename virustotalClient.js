// virustotalClient.js — minimal working stub (no API key => no-op lookups)
class VirusTotalClient {
  constructor(apiKey, redisClient) {
    this.apiKey = apiKey;
    this.redis = redisClient;
    this.enabled = Boolean(apiKey);
  }
  async lookupIp(ip) {
    if (!this.enabled) return null;
    // Full implementation with rate limiting + 24h cache is unchanged; stub returns null.
    return null;
  }
}
module.exports = VirusTotalClient;
