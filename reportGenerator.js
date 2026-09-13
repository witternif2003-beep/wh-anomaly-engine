// reportGenerator.js — CSV/JSON/HTML report export from persistence
const fs = require('fs');
const path = require('path');
const { getAnomalies } = require('./persistence');

class ReportGenerator {
  constructor(outputDir = path.join(__dirname, 'reports')) {
    this.outputDir = outputDir;
    fs.mkdirSync(outputDir, { recursive: true });
  }
  toCSV(rows) {
    if (rows.length === 0) return 'id,rule_id,severity,description,timestamp\n';
    const esc = v => `"${String(v).replace(/"/g, '""')}"`;
    const header = 'id,rule_id,severity,description,timestamp';
    return header + '\n' + rows.map(r =>
      [r.id, r.rule_id, r.severity, r.description, r.timestamp].map(esc).join(',')
    ).join('\n') + '\n';
  }
  generate(format = 'csv', limit = 1000) {
    const rows = getAnomalies(limit);
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    if (format === 'csv') {
      const file = path.join(this.outputDir, `anomalies-${stamp}.csv`);
      fs.writeFileSync(file, this.toCSV(rows));
      return file;
    }
    if (format === 'json') {
      const file = path.join(this.outputDir, `anomalies-${stamp}.json`);
      fs.writeFileSync(file, JSON.stringify(rows, null, 2));
      return file;
    }
    const file = path.join(this.outputDir, `anomalies-${stamp}.html`);
    fs.writeFileSync(file, `<!DOCTYPE html><html><body><h1>WH Anomaly Report</h1><pre>${JSON.stringify(rows, null, 2)}</pre></body></html>`);
    return file;
  }
}
module.exports = ReportGenerator;
