'use strict';
// Sections are untrusted data. Only the default-branch publisher writes comments.
const fs = require('node:fs');
const path = require('node:path');
const { TextDecoder, isDeepStrictEqual } = require('node:util');
const MARKER = '<!-- opentdf-pr-report:v1 -->';
const PRODUCERS = Object.freeze({
  benchmarks: ['Benchmarks', 'benchmark tests'],
  govulncheck: ['Govulncheck', 'report-govulncheck'],
  xtest: ['X-Test', 'platform-xtest / export-pr-report'],
});
const STATES = new Set(['pending', 'passed', 'failed', 'cancelled', 'unavailable']);
const MAX_ARCHIVE = 131072;
const MAX_SECTION = 98304;
const FIELDS = ['version', 'section', 'title', 'status', 'summary', 'details', 'repository', 'pr', 'sha', 'run', 'attempt'].sort();
const utf8 = bytes => new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
const characterCount = text => Array.from(text).length;

function validate(data, section, identity) {
  if (!data || typeof data !== 'object' || Array.isArray(data) ||
      !isDeepStrictEqual(Object.keys(data).sort(), FIELDS)) throw new Error('Invalid section schema');
  if (data.version !== 1) throw new Error('Unsupported section version');
  if (data.section !== section || !Object.hasOwn(PRODUCERS, section)) throw new Error('Unknown section');
  if (!STATES.has(data.status)) throw new Error('Invalid status');
  for (const key of ['title', 'summary', 'details']) {
    if (typeof data[key] !== 'string' || !data[key].isWellFormed() || Buffer.byteLength(data[key]) > 16384) {
      throw new Error('Invalid or oversized text');
    }
  }
  if (Buffer.byteLength(data.title) > 256) throw new Error('Oversized title');
  if (!data.title || !(data.summary || data.details)) throw new Error('Empty section');
  for (const [key, value] of Object.entries(identity)) {
    if (typeof data[key] !== typeof value || data[key] !== value ||
        (typeof value === 'number' && !Number.isSafeInteger(data[key]))) {
      throw new Error(`Section identity mismatch: ${key}`);
    }
  }
  return data;
}

function submit(env = process.env) {
  const event = JSON.parse(utf8(fs.readFileSync(env.GITHUB_EVENT_PATH)));
  const pr = event.pull_request || {};
  const integer = name => {
    const value = env[name]?.trim();
    if (!value || !/^[+-]?[0-9]+$/.test(value)) throw new Error('Invalid execution identity');
    return Number(value);
  };
  const identity = { repository: env.GITHUB_REPOSITORY, pr: pr.number || 0,
    sha: pr.head?.sha || env.GITHUB_SHA, run: integer('GITHUB_RUN_ID'), attempt: integer('GITHUB_RUN_ATTEMPT') };
  const readFile = name => {
    if (!env[name]) return '';
    if (fs.statSync(env[name]).size > 16384) throw new Error('Oversized input');
    return utf8(fs.readFileSync(env[name]));
  };
  const data = { version: 1, section: env.REPORT_SECTION, title: env.REPORT_TITLE, status: env.REPORT_STATUS,
    summary: readFile('REPORT_SUMMARY'), details: readFile('REPORT_DETAILS'), ...identity };
  validate(data, data.section, identity);
  const serialized = JSON.stringify(data);
  if (Buffer.byteLength(serialized) > MAX_SECTION) throw new Error('Oversized serialized section');
  fs.mkdirSync(env.REPORT_DIR, { recursive: true });
  fs.writeFileSync(path.join(env.REPORT_DIR, 'section.json'), serialized);
  return data;
}

function strictJson(raw) {
  // Microsoft jsonc-parser provides decoded property names and syntax events;
  // JSON.parse alone silently accepts duplicate keys, including escaped aliases.
  const { visit } = require('jsonc-parser');
  const objects = [];
  let error;
  visit(raw, {
    onObjectBegin() { objects.push(new Set()); },
    onObjectEnd() { objects.pop(); },
    onObjectProperty(name) {
      if (objects.at(-1).has(name)) error = 'Duplicate JSON field';
      objects.at(-1).add(name);
    },
    onLiteralValue(value, offset, length) {
      // The schema's numeric fields are integers. Preserve rejection of float
      // spellings before JS number coercion erases their original JSON type.
      if (typeof value === 'number' && (!Number.isSafeInteger(value) || !/^-?(0|[1-9][0-9]*)$/.test(raw.slice(offset, offset + length)))) {
        error = 'Invalid integer JSON field';
      }
    },
    onError() { error = 'Invalid JSON'; },
  }, { disallowComments: true, allowTrailingComma: false });
  if (error) throw new Error(error);
  return JSON.parse(raw);
}

async function decodeArchive(raw) {
  if (!Buffer.isBuffer(raw) || raw.length > MAX_ARCHIVE) throw new Error('Oversized archive');
  // Maintained yauzl parses ZIP metadata/streams and verifies declared sizes.
  // Never extract members; cap actual decoded bytes and verify CRC as zipfile did.
  const yauzl = require('yauzl');
  const crc32 = require('buffer-crc32');
  return new Promise((resolve, reject) => {
    yauzl.fromBuffer(raw, { lazyEntries: true, autoClose: false, validateEntrySizes: true, strictFileNames: true }, (error, zip) => {
      if (error) return reject(error);
      let finished = false;
      let member;
      const finish = (failure, result) => {
        if (finished) return;
        finished = true;
        zip.close();
        if (failure) reject(failure); else resolve(result);
      };
      zip.on('error', failure => finish(failure));
      zip.on('entry', entry => {
        if (member || entry.fileName !== 'section.json') return finish(new Error('Unexpected archive members'));
        if (entry.uncompressedSize > MAX_SECTION || (entry.generalPurposeBitFlag & 1)) {
          return finish(new Error('Oversized/encrypted section'));
        }
        member = entry;
        zip.readEntry();
      });
      zip.on('end', async () => {
        if (finished) return;
        if (!member) return finish(new Error('Unexpected archive members'));
        try {
          const local = await zip.readLocalFileHeaderPromise(member);
          if (!local.fileName.equals(Buffer.from('section.json')) || (local.generalPurposeBitFlag & 1) ||
              local.compressionMethod !== member.compressionMethod) throw new Error('Conflicting ZIP local header');
        } catch (failure) { finish(failure); return; }
        zip.openReadStream(member, (failure, stream) => {
          if (failure) return finish(failure);
          const chunks = [];
          let size = 0;
          stream.on('error', failure => finish(failure));
          stream.on('data', chunk => {
            size += chunk.length;
            if (size > MAX_SECTION) { stream.destroy(new Error('Oversized section')); return; }
            chunks.push(chunk);
          });
          stream.on('end', () => {
            try {
              const bytes = Buffer.concat(chunks);
              if (size !== member.uncompressedSize || crc32.unsigned(bytes) !== member.crc32) throw new Error('Invalid ZIP size/CRC');
              finish(null, strictJson(utf8(bytes)));
            } catch (failure) { finish(failure); }
          });
        });
      });
      zip.readEntry();
    });
  });
}

function templateOrder(template) {
  const slots = [...template.matchAll(/<!-- section:([a-z0-9-]+) -->/g)].map(match => match[1]);
  if (slots.length !== new Set(slots).size || !isDeepStrictEqual([...slots].sort(), Object.keys(PRODUCERS).sort())) {
    throw new Error('Template must declare each known section exactly once');
  }
  if (template.replace(/<!-- section:[a-z0-9-]+ -->/g, '').trim() !== '# Pull request checks') {
    throw new Error('Template supports only heading and section slots');
  }
  return slots;
}

function isolateFences(text) {
  // Root-align up-to-three-space fence lines to eliminate container ambiguity.
  // Escape an unmatched opener AND fence-like tail lines, never append a huge
  // closing delimiter. Preserve matched fences and the reviewed Markdown UI.
  const lines = text.replace(/\r\n?/g, '\n').split('\n');
  const pattern = /^( {0,3})(`{3,}|~{3,})([^\n]*)$/;
  let opener;
  for (let index = 0; index < lines.length; index++) {
    const match = pattern.exec(lines[index]);
    if (!match) continue;
    const [, indent, fence, rest] = match;
    lines[index] = lines[index].slice(indent.length);
    if (!opener) {
      if (fence[0] === '`' && rest.includes('`')) continue;
      opener = { index, character: fence[0], length: fence.length };
    } else if (fence[0] === opener.character && fence.length >= opener.length && !rest.replace(/[ \t]/g, '')) opener = undefined;
  }
  if (opener) {
    for (let index = opener.index; index < lines.length; index++) {
      const match = pattern.exec(lines[index]);
      if (match) lines[index] = lines[index].slice(0, match[1].length) + '\\' + lines[index].slice(match[1].length);
    }
  }
  return lines.join('\n');
}

function safeText(text, limit, plain = false) {
  let escaped = text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/@/g, '@\u200b');
  if (!plain) escaped = escaped.replace(/&gt;/g, '>');
  if (plain) escaped = escaped.replace(/([\\`*_{}\[\]()#+.!|>-])/g, '\\$1');
  let displayed = Array.from(escaped).slice(0, limit).join('');
  if (!plain) displayed = isolateFences(displayed);
  return displayed + (characterCount(escaped) > limit ? '\n… (truncated; see workflow artifacts)' : '');
}

function render(order, sections, sha, run) {
  const body = [MARKER, '# Pull request checks', `Head: \`${sha}\``];
  if (run) body.push(`[Workflow run](${run.html_url}) · attempt ${run.run_attempt}`);
  for (const section of order) {
    const data = sections[section];
    body.push(`## ${safeText(data.title, 160, true)} — ${data.status}`);
    if (data.summary) body.push(safeText(data.summary, 1500));
    if (data.details) body.push('<details><summary>Details</summary>\n\n' + safeText(data.details, 9000) + '\n\n</details>');
  }
  const result = body.join('\n\n');
  if (result.length > 60000) throw new Error('Comment exceeds safe GitHub length');
  return result;
}

class GitHub {
  constructor(repository, token, fetchImpl = fetch) {
    this.root = `https://api.github.com/repos/${repository}`;
    this.token = token;
    this.fetch = fetchImpl;
  }
  async request(endpoint, method = 'GET', body, binary = false) {
    let url = new URL(this.root + endpoint);
    const headers = { Accept: 'application/vnd.github+json', Authorization: `Bearer ${this.token}`,
      'X-GitHub-Api-Version': '2022-11-28', 'Content-Type': 'application/json', 'User-Agent': 'opentdf-pr-report' };
    for (let redirects = 0; redirects <= 5; redirects++) {
      const response = await this.fetch(url, { method, headers: { ...headers },
        body: body === undefined ? undefined : JSON.stringify(body), redirect: 'manual', signal: AbortSignal.timeout(30000) });
      if ([301, 302, 303, 307, 308].includes(response.status)) {
        const next = new URL(response.headers.get('location'), url);
        await response.body?.cancel();
        if (next.protocol !== 'https:' || method !== 'GET') throw new Error('Unsafe API redirect');
        if (next.origin !== url.origin) delete headers.Authorization;
        url = next;
        continue;
      }
      if (!response.ok) { await response.body?.cancel(); throw new Error(`GitHub HTTP ${response.status}: ${endpoint}`); }
      if (!binary) return response.json();
      const chunks = [];
      let size = 0;
      for await (const chunk of response.body) {
        const bounded = chunk.subarray(0, MAX_ARCHIVE + 1 - size);
        size += bounded.length;
        chunks.push(bounded);
        // Keep one sentinel byte, then cancel the iterator. decodeArchive rejects
        // oversized DATA per section; HTTP/auth failures still abort this PR.
        if (size > MAX_ARCHIVE) break;
      }
      return Buffer.concat(chunks);
    }
    throw new Error('API redirect limit exceeded');
  }
  async pages(endpoint, key) {
    const values = [];
    for (let page = 1; page <= 1000; page++) {
      const data = await this.request(endpoint + (endpoint.includes('?') ? '&' : '?') + `per_page=100&page=${page}`);
      const rows = key ? data[key] : data;
      values.push(...rows);
      if (rows.length < 100) return values;
    }
    throw new Error('Pagination limit exceeded');
  }
}

function latestRun(runs, pr, repository) {
  return runs.filter(run => run.event === 'pull_request' && run.path === '.github/workflows/checks.yaml' &&
    run.head_sha === pr.head.sha && run.head_branch === pr.head.ref && run.head_repository?.full_name === repository &&
    (run.pull_requests || []).every(p => p.number === pr.number))
    .sort((a, b) => b.id - a.id || b.run_attempt - a.run_attempt)[0] || null;
}
function fallback(section, run, jobs) {
  const [title, producer] = PRODUCERS[section];
  const matching = jobs.filter(job => job.name === producer);
  let status, summary;
  if (!run || run.status !== 'completed') [status, summary] = ['pending', 'Waiting for structured results.'];
  else if (run.conclusion === 'cancelled') [status, summary] = ['cancelled', 'Workflow cancelled; results may be incomplete.'];
  else if (matching.some(job => ['failure', 'timed_out'].includes(job.conclusion))) [status, summary] = ['failed', 'Producer failed without a valid structured result.'];
  else [status, summary] = ['unavailable', 'No valid result for this attempt (missing, skipped, expired, or malformed).'];
  return { title, status, summary, details: '' };
}
async function collect(api, repository, pr, run) {
  if (!run) return Object.fromEntries(Object.keys(PRODUCERS).map(id => [id, fallback(id, null, [])]));
  const jobs = await api.pages(`/actions/runs/${run.id}/attempts/${run.run_attempt}/jobs`, 'jobs');
  const artifacts = await api.pages(`/actions/runs/${run.id}/artifacts`, 'artifacts');
  const sections = Object.fromEntries(Object.keys(PRODUCERS).map(id => [id, fallback(id, run, jobs)]));
  const identity = { repository, pr: pr.number, sha: pr.head.sha, run: run.id, attempt: run.run_attempt };
  for (const [section, [, producer]] of Object.entries(PRODUCERS)) {
    const name = `pr-report-${section}-${run.id}-${run.run_attempt}`;
    const candidates = artifacts.filter(a => a.name === name && !a.expired);
    const producers = jobs.filter(job => job.name === producer);
    if (candidates.length !== 1 || producers.length !== 1 || !['success', 'failure', 'cancelled', 'timed_out'].includes(producers[0].conclusion)) continue;
    const artifact = candidates[0];
    const provenance = artifact.workflow_run || {};
    if (artifact.size_in_bytes > MAX_ARCHIVE || provenance.id !== run.id || provenance.head_sha !== pr.head.sha ||
        provenance.head_repository_id !== pr.head.repo.id) continue;
    const raw = await api.request(`/actions/artifacts/${artifact.id}/zip`, 'GET', undefined, true);
    try {
      const data = validate(await decodeArchive(raw), section, identity);
      if (producers[0].conclusion !== 'success' && data.status === 'passed') throw new Error('Failed producer cannot report passed');
      sections[section] = data;
    } catch (error) { console.log(`Rejected ${section}: ${JSON.stringify(error.message)}`); }
  }
  return sections;
}
async function reconcile(api, repository, pr) {
  if (pr.user?.login === 'dependabot[bot]' || !pr.head.repo || pr.head.repo.fork || pr.head.repo.full_name !== repository) return;
  const sha = pr.head.sha;
  const runsPath = `/actions/workflows/checks.yaml/runs?event=pull_request&head_sha=${sha}`;
  const run = latestRun(await api.pages(runsPath, 'workflow_runs'), pr, repository);
  const templateData = await api.request(`/contents/.github/comment-template.md?ref=${pr.base.sha}`);
  const order = templateOrder(utf8(Buffer.from(templateData.content, 'base64')));
  const body = render(order, await collect(api, repository, pr, run), sha, run);
  const comments = await api.pages(`/issues/${pr.number}/comments`);
  const owned = comments.filter(c => c.user?.login === 'github-actions[bot]' && (c.body || '').startsWith(MARKER + '\n'));
  const current = await api.request(`/pulls/${pr.number}`);
  const latest = latestRun(await api.pages(runsPath, 'workflow_runs'), current, repository);
  if (current.state !== 'open' || current.head.sha !== sha || !isDeepStrictEqual(latest, run)) {
    console.log(`Skipped stale reconciliation for PR ${pr.number}`); return;
  }
  // No atomic comment CAS exists. The next surviving full reconciliation repairs
  // the unavoidable final-check/write race. Workflow concurrency serializes writers.
  const final = await api.request(`/pulls/${pr.number}`);
  if (final.state !== 'open' || final.head.sha !== sha) return;
  if (owned.length) {
    const first = owned.sort((a, b) => a.id - b.id)[0];
    if (first.body !== body) await api.request(`/issues/comments/${first.id}`, 'PATCH', { body });
  } else await api.request(`/issues/${pr.number}/comments`, 'POST', { body });
}
async function publish(api = new GitHub(process.env.GITHUB_REPOSITORY, process.env.GH_TOKEN), repository = process.env.GITHUB_REPOSITORY) {
  const errors = [];
  for (const pr of await api.pages('/pulls?state=open')) {
    try { await reconcile(api, repository, pr); }
    catch (error) { console.log(`PR ${pr.number}: ${JSON.stringify(error.message)}`); errors.push(pr.number); }
  }
  if (errors.length) throw new Error(`Unreconciled PRs: ${errors.join(', ')}`);
}
module.exports = { MARKER, PRODUCERS, STATES, MAX_ARCHIVE, MAX_SECTION, utf8, validate, submit, strictJson, decodeArchive,
  templateOrder, isolateFences, safeText, render, GitHub, latestRun, fallback, collect, reconcile, publish };
if (require.main === module) {
  Promise.resolve().then(() => {
    if (process.argv[2] === 'submit') return submit();
    if (process.argv[2] === 'publish') return publish();
    throw new Error('Expected submit or publish');
  }).catch(error => { console.error(JSON.stringify(error.message)); process.exitCode = 1; });
}
