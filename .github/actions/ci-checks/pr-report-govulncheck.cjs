'use strict';
// Aggregate data-only module receipts. A missing receipt is never success.
const fs = require('node:fs');
const path = require('node:path');
const { utf8 } = require('./pr-report.cjs');
const MODULES = new Set(['examples', 'otdfctl', 'sdk', 'service', 'lib/ocrypto', 'lib/fixtures',
  'lib/flattening', 'lib/identifier', 'tests-bdd']);
function aggregate(directory, env = process.env) {
  const results = new Map();
  const files = fs.existsSync(directory) ? fs.readdirSync(directory).filter(name => name.endsWith('.json')) : [];
  for (const name of files) {
    const file = path.join(directory, name);
    if (fs.statSync(file).size > 98304) throw new Error('Oversized govulncheck receipt');
    const data = JSON.parse(utf8(fs.readFileSync(file)), (key, value, context) => {
      // Node 24's source context preserves integer receipt spellings without a
      // producer dependency install; 7.0/7e0 must not coerce into run 7.
      if (['run', 'attempt'].includes(key) && typeof value === 'number' &&
          (!Number.isSafeInteger(value) || !/^-?(0|[1-9][0-9]*)$/.test(context.source))) throw new Error('Invalid receipt integer');
      return value;
    });
    if (!data || typeof data !== 'object' || Array.isArray(data) ||
        Object.keys(data).sort().join(',') !== 'attempt,module,outcome,run') throw new Error('Invalid govulncheck receipt');
    if (!MODULES.has(data.module) || results.has(data.module)) throw new Error('Unknown/duplicate module');
    if (String(data.run) !== env.GITHUB_RUN_ID || String(data.attempt) !== env.GITHUB_RUN_ATTEMPT) throw new Error('Stale receipt');
    if (!['success', 'failure', 'skipped', 'cancelled'].includes(data.outcome)) throw new Error('Invalid outcome');
    results.set(data.module, data.outcome);
  }
  const outcomes = [...results.values()];
  const status = outcomes.includes('failure') ? 'failed' :
    results.size === MODULES.size && outcomes.every(v => v === 'success') ? 'passed' :
    outcomes.includes('cancelled') ? 'cancelled' : 'unavailable';
  const details = [...MODULES].sort().map(module => `${module}: ${results.get(module) || 'unavailable'}`).join('\n');
  return { status, details };
}
function translate(env = process.env) {
  const { status, details } = aggregate('govulncheck-results', env);
  const summaries = { passed: 'All modules completed govulncheck without findings.',
    failed: 'Govulncheck reported findings or failed; inspect the run for diagnostics.',
    cancelled: 'Govulncheck was cancelled.', unavailable: 'Some modules have no completed govulncheck result.' };
  fs.writeFileSync('govulncheck-summary.txt', summaries[status]);
  fs.writeFileSync('govulncheck-details.txt', details);
  fs.appendFileSync(env.GITHUB_OUTPUT, `status=${status}\n`);
}
module.exports = { MODULES, aggregate, translate };
if (require.main === module) {
  try { translate(); } catch (error) { console.error(JSON.stringify(error.message)); process.exitCode = 1; }
}
