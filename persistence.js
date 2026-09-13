// persistence.js — SQLite (WAL mode), better-sqlite3
const Database = require('better-sqlite3');
const path = require('path');

let db = null;

function initDB(dbPath = path.join(__dirname, 'data', 'anomalies.db')) {
  const fs = require('fs');
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  db.exec(`
    CREATE TABLE IF NOT EXISTS anomalies (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      rule_id TEXT NOT NULL,
      severity TEXT NOT NULL,
      description TEXT,
      details TEXT,
      timestamp TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_anomalies_ts ON anomalies(timestamp);
  `);
}

function saveAnomaly(anomaly) {
  db.prepare(`INSERT INTO anomalies (rule_id, severity, description, details, timestamp)
              VALUES (?, ?, ?, ?, ?)`)
    .run(
      anomaly.ruleId,
      anomaly.severity,
      anomaly.description || null,
      JSON.stringify(anomaly.details || {}),
      anomaly.timestamp
    );
}

function getAnomalies(limit = 100) {
  return db.prepare('SELECT * FROM anomalies ORDER BY id DESC LIMIT ?').all(limit)
    .map(row => ({ ...row, details: JSON.parse(row.details || '{}') }));
}

function getTotalCount() {
  return db.prepare('SELECT COUNT(*) AS c FROM anomalies').get().c;
}

module.exports = { initDB, saveAnomaly, getAnomalies, getTotalCount };
