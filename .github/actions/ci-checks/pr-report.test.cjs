const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const yazl = require('yazl');
const { spawnSync } = require('node:child_process');
const MarkdownIt = require('markdown-it');
const report = require('./pr-report.cjs');
const gov = require('./pr-report-govulncheck.cjs');
const oracle = require('./pr-report-equivalence.json');
const REPO = 'opentdf/platform';
const SHA = 'a'.repeat(40);
const PR = { number: 12, state: 'open', head: { sha: SHA, ref: 'feature', repo: { id: 1, full_name: REPO, fork: false } }, base: { sha: 'b'.repeat(40) } };
const RUN = { id: 7, run_attempt: 2, head_sha: SHA, head_branch: 'feature', head_repository: { full_name: REPO },
  event: 'pull_request', path: '.github/workflows/checks.yaml', pull_requests: [{ number: 12 }], status: 'completed',
  conclusion: 'success', html_url: 'https://github.com/opentdf/platform/actions/runs/7' };
const IDENTITY = { repository: REPO, pr: 12, sha: SHA, run: 7, attempt: 2 };
const TEMPLATE = '# Pull request checks\n' + Object.keys(report.PRODUCERS).map(s => `<!-- section:${s} -->`).join('\n');
const data = (section = 'benchmarks', changes = {}) => ({ version: 1, section, title: 'Title', status: 'passed', summary: 'Done', details: '', ...IDENTITY, ...changes });
function archive(value, filename = 'section.json', extra = false) {
  const zip = new yazl.ZipFile();
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(typeof value === 'string' ? value : JSON.stringify(value));
  zip.addBuffer(bytes, filename);
  if (extra) zip.addBuffer(Buffer.from('{}'), 'other.json');
  return new Promise((resolve, reject) => {
    const chunks = [];
    zip.outputStream.on('data', c => chunks.push(c));
    zip.outputStream.on('error', reject);
    zip.outputStream.on('end', () => resolve(Buffer.concat(chunks)));
    zip.end();
  });
}
class FakeAPI {
  constructor(prs = [PR]) {
    this.prs = structuredClone(prs);
    this.runs = new Map(this.prs.map(p => [p.number, { ...structuredClone(RUN), id: p.number - 5, head_sha: p.head.sha,
      head_branch: p.head.ref, pull_requests: [{ number: p.number }] }]));
    this.jobs = Object.values(report.PRODUCERS).map(v => ({ name: v[1], conclusion: 'success' }));
    this.artifacts = [];
    this.payloads = new Map();
    this.comments = new Map(this.prs.map(p => [p.number, []]));
    this.writes = [];
    this.calls = [];
  }
  async pages(endpoint, key) {
    this.calls.push(endpoint);
    if (endpoint.startsWith('/pulls?')) return structuredClone(this.prs);
    if (key === 'workflow_runs') return structuredClone([...this.runs.values()].filter(r => endpoint.endsWith(r.head_sha)));
    if (key === 'jobs') return this.jobs;
    if (key === 'artifacts') return this.artifacts.filter(a => endpoint.includes(`/runs/${a.workflow_run.id}/`));
    if (endpoint.endsWith('/comments')) return this.comments.get(Number(endpoint.split('/')[2]));
    throw new Error(`Unexpected page ${endpoint}`);
  }
  async request(endpoint, method = 'GET', body) {
    this.calls.push(endpoint);
    if (endpoint.startsWith('/contents/')) return { content: Buffer.from(TEMPLATE).toString('base64') };
    if (endpoint.startsWith('/pulls/')) {
      const pr = this.prs.find(p => p.number === Number(endpoint.split('/')[2]));
      if (this.changeHead) pr.head.sha = 'c'.repeat(40);
      if (this.changeAttempt) this.runs.get(pr.number).run_attempt++;
      if (this.closePR) pr.state = 'closed';
      return structuredClone(pr);
    }
    if (endpoint.endsWith('/zip')) return this.payloads.get(Number(endpoint.split('/').at(-2)));
    if (method === 'POST') {
      this.writes.push({ endpoint, method, body });
      this.comments.get(Number(endpoint.split('/')[2])).push({ id: 20 + this.writes.length,
        user: { login: 'github-actions[bot]' }, body: body.body });
      return {};
    }
    if (method === 'PATCH') {
      this.writes.push({ endpoint, method, body });
      const comment = [...this.comments.values()].flat().find(c => c.id === Number(endpoint.split('/').at(-1)));
      comment.body = body.body;
      return {};
    }
    throw new Error(`Unexpected request ${endpoint}`);
  }
  async add(section, changes = {}, attempt = 2, number = 12) {
    const id = this.artifacts.length + 1;
    const run = this.runs.get(number);
    this.artifacts.push({ id, name: `pr-report-${section}-${run.id}-${attempt}`, expired: false, size_in_bytes: 1024,
      workflow_run: { id: run.id, head_sha: run.head_sha, head_repository_id: 1 } });
    this.payloads.set(id, await archive(data(section, { pr: number, run: run.id, sha: run.head_sha, ...changes })));
  }
}

test('schema identity, UTF-8 byte limits, titles and optional file inputs remain strict', () => {
  for (const value of [data(), data('benchmarks', { summary: '', details: 'Details only' }), data('benchmarks', { details: 'Both' })]) assert.equal(report.validate(value, 'benchmarks', IDENTITY), value);
  for (const changes of [{ summary: '' }, { extra: 'unknown' }, { section: 'other' }, { attempt: 1 }, { pr: 13 }, { sha: 'old' },
    { run: 8 }, { repository: 'fork/repo' }, { status: 'success' }, { version: true }, { run: '7' }, { run: true },
    { details: 'x'.repeat(17000) }, { title: 'x'.repeat(257) }, { details: '\ud800' }, { details: '😀'.repeat(4097) }]) {
    assert.throws(() => report.validate(data('benchmarks', changes), 'benchmarks', IDENTITY));
  }
});
test('strict JSON detects duplicate and escaped aliases, nested duplicates and non-JSON syntax', () => {
  for (const raw of ['{"status":1,"status":2}', '{"a":1,"\\u0061":2}', '{"nested":{"x":1,"x":2}}', '{"a":1,}', '{/*comment*/"a":1}', 'NaN', 'null trailing']) assert.throws(() => report.strictJson(raw));
  assert.deepEqual(report.strictJson('{"items":[{"x":1},{"x":2}]}'), { items: [{ x: 1 }, { x: 2 }] });
});
test('maintained ZIP decoder rejects extra/path/encrypted/CRC/local-conflict/size/compression/UTF-8 attacks', async () => {
  const valid = await archive(data());
  assert.deepEqual(await report.decodeArchive(valid), data());
  const central = valid.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]));
  const mutated = (offset, value, width = 1) => { const bytes = Buffer.from(valid); bytes.writeUIntLE(value, offset, width); return bytes; };
  const large = await archive(Buffer.from('x'.repeat(report.MAX_SECTION + 1)));
  const lied = Buffer.from(large);
  lied.writeUInt32LE(10, lied.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02])) + 24);
  const traversal = await archive(data(), 'safe-dir/section.json');
  const safeName = Buffer.from('safe-dir/section.json');
  for (const offset of [traversal.indexOf(safeName), traversal.lastIndexOf(safeName)]) Buffer.from('../pathx/section.json').copy(traversal, offset);
  for (const raw of [Buffer.from('broken'), await archive(data(), 'nested/section.json'), await archive(data(), 'section.json', true),
    Buffer.alloc(report.MAX_ARCHIVE + 1), large, lied, traversal, await archive(Buffer.from([0xff])), await archive('\ufeff{}'), await archive('{"a":1,"a":2}'),
    mutated(central + 8, valid.readUInt16LE(central + 8) | 1, 2), mutated(central + 16, 0, 4), mutated(30, 'X'.charCodeAt(0)), mutated(central + 10, 99, 2)]) {
    await assert.rejects(report.decodeArchive(raw));
  }
});
test('trusted template enforces fixed unique slots and ordering', () => {
  assert.deepEqual(report.templateOrder(TEMPLATE), Object.keys(report.PRODUCERS));
  for (const value of [TEMPLATE + '\n<!-- section:benchmarks -->', TEMPLATE.replace('xtest', 'unknown'), TEMPLATE + 'script']) assert.throws(() => report.templateOrder(value));
});
test('JS render is byte-for-byte equivalent to approved renderer fixtures, including Unicode truncation', () => {
  assert.equal(oracle.oracleHead, 'efb0c456be6ab7c690ca687bad73183d912516ce');
  for (const fixture of oracle.render) assert.equal(report.render(Object.keys(report.PRODUCERS), fixture.sections, SHA, null), fixture.expected);
});
test('Markdown summary/detail/both, escaping, marker identity and comment limits retained', () => {
  const summary = '**Passed** [run](https://github.com/opentdf/platform)';
  const details = '### Table\n\n> quote\n\n| Case | Time |\n| --- | --- |\n| A | **10 ms** |';
  for (const [s, d] of [[true, false], [false, true], [true, true]]) {
    const sections = Object.fromEntries(Object.keys(report.PRODUCERS).map(id => [id, data(id, { summary: s ? summary : '', details: d ? details : '' })]));
    const text = report.render(Object.keys(report.PRODUCERS), sections, SHA, RUN);
    assert.equal(text.includes(summary), s); assert.equal(text.includes(details), d);
    assert.equal(text.includes('<details>'), d); assert.ok(!text.includes('<pre>'));
  }
  const hostile = `${report.MARKER}\n</details><script>alert(1)</script>\n@someone @opentdf/maintainers\n**safe**`;
  const sections = Object.fromEntries(Object.keys(report.PRODUCERS).map(id => [id, data(id, { title: '**plain**', summary: hostile, details: hostile + '&'.repeat(16000) })]));
  const text = report.render(Object.keys(report.PRODUCERS), sections, SHA, RUN);
  assert.equal(text.split(report.MARKER).length - 1, 1);
  assert.equal(text.split('</details>').length - 1, 3);
  assert.ok(!text.includes('<script>')); assert.ok(!text.includes('@someone')); assert.ok(text.includes('**safe**'));
  assert.ok(text.includes('\\*\\*plain\\*\\*')); assert.ok(text.includes('truncated')); assert.ok(text.length < 60000);
  assert.throws(() => report.render(Array(30).fill('benchmarks'), sections, SHA, RUN), /Comment exceeds/);
});
test('actual GFM renderer retains tables, bold and links in summary and expandable details', () => {
  const table = '**Passed** [run](https://github.com/opentdf/platform)\n\n| Case | Time |\n| --- | --- |\n| Bulk | **10 ms** |';
  const sections = Object.fromEntries(Object.keys(report.PRODUCERS).map(id => [id, data(id, { summary: table, details: table })]));
  const html = new MarkdownIt({ html: true }).render(report.render(Object.keys(report.PRODUCERS), sections, SHA, RUN));
  assert.equal((html.match(/<table>/g) || []).length, 6);
  assert.match(html, /<strong>10 ms<\/strong>/);
  assert.match(html, /<a href="https:\/\/github.com\/opentdf\/platform">run<\/a>/);
});
test('latest run rejects stale SHA/repo/branch/PR/workflow and chooses current run/attempt', () => {
  assert.equal(report.latestRun([RUN], PR, REPO), RUN);
  for (const changes of [{ head_sha: 'old' }, { head_branch: 'other' }, { event: 'push' }, { path: 'other.yml' },
    { pull_requests: [{ number: 13 }] }, { head_repository: { full_name: 'fork/repo' } }]) assert.equal(report.latestRun([{ ...RUN, ...changes }], PR, REPO), null);
  assert.equal(report.latestRun([RUN, { ...RUN, id: 8 }], PR, REPO).id, 8);
});
test('missing, conflicting duplicate, expired, malformed and prior-attempt artifacts never pass', async () => {
  const prepare = [async () => {}, a => a.add('benchmarks', {}, 1), a => a.add('benchmarks', { attempt: 1 }),
    async a => { await a.add('benchmarks'); await a.add('benchmarks', { status: 'failed' }); }, a => a.add('benchmarks', { pr: 99 }),
    async a => { await a.add('benchmarks'); a.artifacts[0].expired = true; },
    async a => { await a.add('benchmarks'); a.artifacts[0].size_in_bytes = report.MAX_ARCHIVE + 1; },
    async a => { await a.add('benchmarks'); a.payloads.set(1, Buffer.from('not a zip')); },
    async a => { await a.add('benchmarks'); a.payloads.set(1, Buffer.alloc(report.MAX_ARCHIVE + 1)); },
    async a => { await a.add('benchmarks'); a.jobs.push({ ...a.jobs[0] }); },
    async a => { await a.add('benchmarks'); a.jobs[0].conclusion = null; }];
  for (const setup of prepare) {
    const api = new FakeAPI(); await setup(api);
    assert.equal((await report.collect(api, REPO, PR, RUN)).benchmarks.status, 'unavailable');
  }
});
test('producer failure/cancellation/pending and job/artifact provenance guarded', async () => {
  const api = new FakeAPI(); await api.add('benchmarks'); api.jobs[0].conclusion = 'failure';
  assert.equal((await report.collect(api, REPO, PR, RUN)).benchmarks.status, 'failed');
  api.payloads.set(1, await archive(data('benchmarks', { status: 'failed' })));
  assert.equal((await report.collect(api, REPO, PR, RUN)).benchmarks.status, 'failed');
  api.jobs[0].name = 'wrong-producer'; assert.equal((await report.collect(api, REPO, PR, RUN)).benchmarks.status, 'unavailable');
  assert.equal(report.fallback('benchmarks', { ...RUN, conclusion: 'cancelled' }, []).status, 'cancelled');
  assert.equal(report.fallback('benchmarks', { ...RUN, status: 'in_progress' }, []).status, 'pending');
  for (const key of ['id', 'head_sha', 'head_repository_id']) {
    const a = new FakeAPI(); await a.add('benchmarks'); a.artifacts[0].workflow_run[key] = 'wrong';
    assert.equal((await report.collect(a, REPO, PR, RUN)).benchmarks.status, 'unavailable');
  }
});
test('serialized arrivals, idempotent creation/retry and whole-section replacement retain every section', async () => {
  const api = new FakeAPI(); await report.reconcile(api, REPO, PR); await report.reconcile(api, REPO, PR);
  assert.deepEqual(api.writes.map(w => w.method), ['POST']);
  await api.add('benchmarks', { details: 'First details' }); await report.reconcile(api, REPO, PR);
  await api.add('govulncheck', { status: 'failed' }); await report.reconcile(api, REPO, PR);
  api.payloads.set(1, await archive(data('benchmarks', { summary: 'Replacement', details: '' })));
  await report.reconcile(api, REPO, PR);
  assert.equal(api.comments.get(12).length, 1);
  assert.ok(!api.comments.get(12)[0].body.includes('First details'));
  assert.ok(api.comments.get(12)[0].body.includes('Replacement'));
  assert.ok(api.comments.get(12)[0].body.includes('— failed'));
});
test('marker ownership, earliest reuse, fork/bot and write-time SHA/attempt/closed-PR rechecks', async () => {
  for (const attr of ['changeHead', 'changeAttempt', 'closePR']) {
    const api = new FakeAPI(); api[attr] = true; await report.reconcile(api, REPO, PR); assert.equal(api.writes.length, 0);
  }
  for (const changes of [p => p.head.repo.fork = true, p => p.user = { login: 'dependabot[bot]' }, p => p.head.repo = null]) {
    const pr = structuredClone(PR); changes(pr); const api = new FakeAPI(); await report.reconcile(api, REPO, pr); assert.equal(api.writes.length, 0);
  }
  const api = new FakeAPI(); api.comments.get(12).push({ id: 9, user: { login: 'human' }, body: report.MARKER + '\nforged' });
  await report.reconcile(api, REPO, PR); assert.equal(api.writes[0].method, 'POST');
  api.comments.get(12).push({ id: 100, user: { login: 'github-actions[bot]' }, body: report.MARKER + '\nnewer' });
  await api.add('benchmarks'); await report.reconcile(api, REPO, PR);
  assert.equal(api.writes.at(-1).endpoint, '/issues/comments/21');
});
test('surviving reconciliation recovers multiple PRs and pending attempts without losing auth-blocked peers', async () => {
  const second = structuredClone(PR); second.number = 13; second.head.sha = 'd'.repeat(40); second.head.ref = 'second';
  const api = new FakeAPI([PR, second]); await api.add('benchmarks'); await api.add('govulncheck', {}, 2, 13);
  await report.publish(api, REPO); assert.equal(api.writes.length, 2);
  assert.ok(api.comments.get(12)[0].body.includes('— passed')); assert.ok(api.comments.get(13)[0].body.includes('— passed'));
  api.runs.get(12).run_attempt = 3; api.runs.get(12).status = 'in_progress';
  await report.publish(api, REPO); assert.ok(!api.comments.get(12)[0].body.includes('— passed')); assert.ok(api.comments.get(12)[0].body.includes('— pending'));
  api.request = async function(endpoint, ...args) {
    if (endpoint === '/pulls/12') throw new Error('GitHub HTTP 403');
    return FakeAPI.prototype.request.call(this, endpoint, ...args);
  };
  api.runs.get(13).run_attempt = 3; api.runs.get(13).status = 'in_progress';
  await assert.rejects(report.publish(api, REPO), /Unreconciled PRs: 12/);
  assert.ok(api.comments.get(13)[0].body.includes('— pending'));
});
test('pagination traverses all pages and fails closed at limit', async () => {
  const api = new report.GitHub(REPO, 'fake'); const calls = [];
  api.request = async endpoint => { calls.push(endpoint); return { items: calls.length === 1 ? Array(100).fill(1) : [2] }; };
  assert.equal((await api.pages('/endpoint?state=open', 'items')).length, 101); assert.ok(calls[1].includes('&per_page=100&page=2'));
  api.request = async () => Array(100).fill(1); await assert.rejects(api.pages('/endpoint'), /Pagination limit/);
});
test('native HTTP redirect strips writer auth and streamed downloads enforce bounds and errors', async () => {
  const seen = [];
  const api = new report.GitHub(REPO, 'private', async (url, options) => {
    seen.push({ url: String(url), ...options });
    return seen.length === 1 ? new Response(null, { status: 302, headers: { location: 'https://storage.example/artifact' } }) : new Response(Buffer.from('bytes'));
  });
  assert.equal((await api.request('/artifact', 'GET', undefined, true)).toString(), 'bytes');
  assert.equal(seen[0].headers.Authorization, 'Bearer private'); assert.equal(seen[1].headers.Authorization, undefined);
  const large = new report.GitHub(REPO, 'private', async () => new Response(Buffer.alloc(report.MAX_ARCHIVE + 1)));
  const bounded = await large.request('/artifact', 'GET', undefined, true);
  assert.equal(bounded.length, report.MAX_ARCHIVE + 1);
  await assert.rejects(report.decodeArchive(bounded), /Oversized/);
  const forbidden = new report.GitHub(REPO, 'private', async () => new Response(null, { status: 403 }));
  await assert.rejects(forbidden.request('/artifact'), /HTTP 403/);
  const insecure = new report.GitHub(REPO, 'private', async () => new Response(null, { status: 302, headers: { location: 'http://storage.example' } }));
  await assert.rejects(insecure.request('/artifact'), /Unsafe/);
});
test('submit reads actual files with execution identity; built-in-only producer path', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pr-report-submit-'));
  try {
    fs.writeFileSync(path.join(dir, 'event.json'), JSON.stringify({ pull_request: PR }));
    fs.writeFileSync(path.join(dir, 'summary.txt'), 'Summary'); fs.writeFileSync(path.join(dir, 'details.txt'), 'Details');
    const env = { GITHUB_EVENT_PATH: path.join(dir, 'event.json'), GITHUB_REPOSITORY: REPO, GITHUB_SHA: 'merge',
      GITHUB_RUN_ID: '7', GITHUB_RUN_ATTEMPT: '2', REPORT_SECTION: 'benchmarks', REPORT_TITLE: 'Title', REPORT_STATUS: 'passed', REPORT_DIR: path.join(dir, 'out') };
    for (const [s, d] of [[true, false], [false, true], [true, true]]) {
      report.submit({ ...env, REPORT_SUMMARY: s ? path.join(dir, 'summary.txt') : '', REPORT_DETAILS: d ? path.join(dir, 'details.txt') : '' });
      const value = JSON.parse(fs.readFileSync(path.join(dir, 'out/section.json'), 'utf8'));
      report.validate(value, 'benchmarks', IDENTITY); assert.equal(Boolean(value.summary), s); assert.equal(Boolean(value.details), d);
    }
    for (const run of ['', '0x7', '7.0', '7e0']) {
      assert.throws(() => report.submit({ ...env, GITHUB_RUN_ID: run, REPORT_SUMMARY: path.join(dir, 'summary.txt') }), /Invalid execution/);
    }
    fs.writeFileSync(path.join(dir, 'summary.txt'), Buffer.from([0xff]));
    assert.throws(() => report.submit({ ...env, REPORT_SUMMARY: path.join(dir, 'summary.txt') }));
    fs.writeFileSync(path.join(dir, 'summary.txt'), 'x'.repeat(16385));
    assert.throws(() => report.submit({ ...env, REPORT_SUMMARY: path.join(dir, 'summary.txt') }), /Oversized input/);
    fs.writeFileSync(path.join(dir, 'summary.txt'), '\u0000'.repeat(16384));
    fs.writeFileSync(path.join(dir, 'details.txt'), '\u0000'.repeat(16384));
    assert.throws(() => report.submit({ ...env, REPORT_SUMMARY: path.join(dir, 'summary.txt'), REPORT_DETAILS: path.join(dir, 'details.txt') }), /Oversized serialized/);
  } finally { fs.rmSync(dir, { recursive: true }); }
});
test('govulncheck requires all nine current receipts, handles failed/cancelled/skipped and rejects duplicates/stale', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pr-report-gov-')); const env = { GITHUB_RUN_ID: '7', GITHUB_RUN_ATTEMPT: '2' };
  try {
    assert.equal(gov.aggregate(dir, env).status, 'unavailable');
    [...gov.MODULES].forEach((module, index) => fs.writeFileSync(path.join(dir, `${index}.json`), JSON.stringify({ module, outcome: 'success', run: 7, attempt: 2 })));
    assert.equal(gov.aggregate(dir, env).status, 'passed');
    const filename = path.join(dir, '0.json'); const receipt = JSON.parse(fs.readFileSync(filename));
    for (const [outcome, status] of [['failure', 'failed'], ['cancelled', 'cancelled'], ['skipped', 'unavailable']]) {
      fs.writeFileSync(filename, JSON.stringify({ ...receipt, outcome })); assert.equal(gov.aggregate(dir, env).status, status);
    }
    fs.writeFileSync(filename, JSON.stringify({ ...receipt, attempt: 1 })); assert.throws(() => gov.aggregate(dir, env), /Stale/);
    fs.writeFileSync(filename, JSON.stringify(receipt).replace('"run":7', '"run":7.0')); assert.throws(() => gov.aggregate(dir, env), /integer/);
    fs.writeFileSync(filename, JSON.stringify({ ...receipt, outcome: 'unknown' })); assert.throws(() => gov.aggregate(dir, env), /Invalid outcome/);
    fs.writeFileSync(filename, JSON.stringify({ ...receipt, module: 'unknown' })); assert.throws(() => gov.aggregate(dir, env), /Unknown/);
    fs.writeFileSync(filename, JSON.stringify({ ...receipt, extra: 'unknown' })); assert.throws(() => gov.aggregate(dir, env), /Invalid govulncheck/);
    fs.writeFileSync(filename, JSON.stringify(receipt)); fs.copyFileSync(filename, path.join(dir, 'duplicate.json')); assert.throws(() => gov.aggregate(dir, env), /duplicate/);
  } finally { fs.rmSync(dir, { recursive: true }); }
});

test('final head recheck prevents writing when only the last read changes head', async () => {
  const api = new FakeAPI(); let reads = 0;
  api.request = async function(endpoint, ...args) {
    if (endpoint === '/pulls/12' && ++reads === 2) this.prs[0].head.sha = 'c'.repeat(40);
    return FakeAPI.prototype.request.call(this, endpoint, ...args);
  };
  await report.reconcile(api, REPO, PR);
  assert.equal(reads, 2); assert.equal(api.writes.length, 0);
});
test('Node CLI submit and govulncheck translation work without any installed packages', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pr-report-cli-'));
  try {
    for (const file of ['pr-report.cjs', 'pr-report-govulncheck.cjs']) fs.copyFileSync(path.join(__dirname, file), path.join(dir, file));
    fs.writeFileSync(path.join(dir, 'event.json'), JSON.stringify({ pull_request: PR }));
    fs.writeFileSync(path.join(dir, 'summary.txt'), '\ufeffSummary');
    const env = { ...process.env, NODE_PATH: '', GITHUB_EVENT_PATH: path.join(dir, 'event.json'), GITHUB_REPOSITORY: REPO,
      GITHUB_SHA: 'merge', GITHUB_RUN_ID: '7', GITHUB_RUN_ATTEMPT: '2', REPORT_SECTION: 'benchmarks', REPORT_TITLE: 'Title',
      REPORT_STATUS: 'passed', REPORT_DIR: path.join(dir, 'out'), REPORT_SUMMARY: path.join(dir, 'summary.txt'), REPORT_DETAILS: '',
      GITHUB_OUTPUT: path.join(dir, 'outputs') };
    const submitted = spawnSync(process.execPath, [path.join(dir, 'pr-report.cjs'), 'submit'], { cwd: dir, env, encoding: 'utf8' });
    assert.equal(submitted.status, 0, submitted.stderr);
    assert.equal(JSON.parse(fs.readFileSync(path.join(dir, 'out/section.json'))).summary, '\ufeffSummary');
    fs.mkdirSync(path.join(dir, 'govulncheck-results'));
    [...gov.MODULES].forEach((module, index) => fs.writeFileSync(path.join(dir, `govulncheck-results/${index}.json`), JSON.stringify({ module, outcome: 'success', run: 7, attempt: 2 })));
    const translated = spawnSync(process.execPath, [path.join(dir, 'pr-report-govulncheck.cjs')], { cwd: dir, env, encoding: 'utf8' });
    assert.equal(translated.status, 0, translated.stderr);
    assert.equal(fs.readFileSync(path.join(dir, 'outputs'), 'utf8'), 'status=passed\n');
    assert.equal(fs.readFileSync(path.join(dir, 'govulncheck-summary.txt'), 'utf8'), 'All modules completed govulncheck without findings.');
    assert.equal(fs.readFileSync(path.join(dir, 'govulncheck-details.txt'), 'utf8').split('\n').length, 9);
  } finally { fs.rmSync(dir, { recursive: true }); }
});

test('JS section positive/negative and fallback fixtures match the approved pre-migration oracle', () => {
  for (const fixture of oracle.sectionInputs) {
    let accepted = false;
    try { report.validate(report.strictJson(fixture.raw), 'benchmarks', IDENTITY); accepted = true; } catch { /* Rejection is the expected negative seam. */ }
    assert.equal(accepted, fixture.accepted);
  }
  for (const fixture of oracle.fallback) assert.deepEqual(report.fallback('benchmarks', fixture.run, fixture.jobs), fixture.expected);
});
