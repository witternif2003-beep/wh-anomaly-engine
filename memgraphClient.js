// memgraphClient.js — minimal working stub (graceful when Memgraph is absent)
class MemgraphClient {
  constructor(uri) {
    this.uri = uri || 'bolt://localhost:7687';
    this.connected = false;
  }
  async connect() {
    // Full implementation uses neo4j-driver / mgclient; without a live Memgraph this must NOT crash boot.
    throw new Error(`Memgraph not reachable at ${this.uri}`);
  }
  async recordAnomaly(anomaly) {
    if (!this.connected) return;
  }
}
module.exports = MemgraphClient;
