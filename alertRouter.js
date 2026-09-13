// alertRouter.js — minimal working stub (routing decisions are made in main.js)
class AlertRouter {
  constructor(redisClient) {
    this.redis = redisClient;
  }
  route(anomaly) {
    // Real channel routing (PagerDuty/Slack/Email/SIEM) lives in main.js senders; stub records only.
    return { routed: true, severity: anomaly.severity };
  }
}
module.exports = AlertRouter;
