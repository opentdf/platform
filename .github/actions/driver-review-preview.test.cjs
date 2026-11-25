const assert = require('node:assert/strict');
const fs = require('node:fs');
const { test } = require('node:test');
const { preview, readOnlyAdapter } = require('./driver-review-preview.cjs');

function fixture({ comments = [], prChanges = {}, heads = [] } = {}) {
  const reads = [];
  const author = { id: 1, type: 'User', login: 'author' };
  const pr = { number: 4137, state: 'open', user: author,
    head: { sha: 'current-sha', repo: { id: 10 } }, base: { repo: { id: 10 } }, ...prChanges };
  const deny = () => { throw new Error('A live write escaped interception'); };
  let fetches = 0;
  const listComments = async () => ({ data: comments });
  const github = {
    rest: {
      pulls: { get: async args => {
        reads.push({ method: 'pulls.get', args });
        const sha = heads[fetches++] ?? pr.head.sha;
        return { data: { ...pr, head: { ...pr.head, sha } } };
      } },
      issues: { listComments, createComment: deny, updateComment: deny, deleteComment: deny },
      repos: { createCommitStatus: deny, get: deny },
    },
    request: deny, graphql: deny,
    paginate: async (method, args) => {
      assert.equal(method, listComments);
      reads.push({ method: 'issues.listComments', args });
      return comments;
    },
  };
  const context = { repo: { owner: 'opentdf', repo: 'platform' }, eventName: 'pull_request',
    payload: { action: 'synchronize', pull_request: { number: 4137, head: { sha: 'current-sha' } } } };
  return { github, context, reads, author };
}

function command(overrides = {}) {
  return { id: 42, html_url: 'https://github.com/opentdf/platform/pull/4137#issuecomment-42',
    body: '/reviewed', user: { id: 1, type: 'User', login: 'author' },
    created_at: '2026-01-01T00:00:00Z', ...overrides };
}

const statuses = operations => operations.filter(op => op.method === 'repos.createCommitStatus');

test('preview adapter denies every non-allowlisted API and intercepts all helper writes', async () => {
  const { github: live } = fixture();
  const operations = [];
  const github = readOnlyAdapter(live, operations, 'https://example.test/pr');
  assert.equal(github.request, undefined);
  assert.equal(github.graphql, undefined);
  assert.equal(github.rest.issues.deleteComment, undefined);
  assert.equal(github.rest.repos.get, undefined);
  assert.throws(() => github.rest.issues.deleteComment({}), TypeError);
  assert.throws(() => github.paginate(live.rest.issues.listComments, {}), /denies/);
  assert.throws(() => github.paginate(live.rest.repos.get, {}), /denies/);
  for (const [method, fn] of [
    ['issues.createComment', github.rest.issues.createComment],
    ['issues.updateComment', github.rest.issues.updateComment],
    ['repos.createCommitStatus', github.rest.repos.createCommitStatus],
  ]) {
    const args = { body: 'original' };
    const response = await fn(args);
    args.body = 'changed';
    assert.equal(operations.at(-1).method, method);
    assert.equal(operations.at(-1).args.body, 'original');
    assert.match(response.data.html_url, /dry-run-no-comment-written/);
  }
});

test('allowlisted reads strip endpoint/method overrides before delegating to live client', async () => {
  const input = fixture();
  const github = readOnlyAdapter(input.github, [], 'https://example.test/pr');
  const args = { owner: 'opentdf', repo: 'platform', pull_number: 4137,
    issue_number: 4137, per_page: 100, method: 'POST', url: '/unexpected', request: {} };
  await github.rest.pulls.get(args);
  await github.paginate(github.rest.issues.listComments, args);
  assert.deepEqual(input.reads, [
    { method: 'pulls.get', args: { owner: 'opentdf', repo: 'platform', pull_number: 4137 } },
    { method: 'issues.listComments', args: { owner: 'opentdf', repo: 'platform', issue_number: 4137, per_page: 100 } },
  ]);
});

test('no live command means actual helper simulates pending reset only', async () => {
  const input = fixture();
  const report = await preview(input);
  assert.match(report.mode, /NO REAL STATUS OR COMMENT WRITTEN/);
  assert.equal(report.matchedCommand, null);
  assert.match(report.commandResult, /No eligible command/);
  assert.deepEqual(report.commandOperations, []);
  assert.equal(report.resetOperations[0].method, 'issues.createComment');
  assert.deepEqual(statuses(report.resetOperations)[0].args, {
    owner: 'opentdf', repo: 'platform', sha: 'current-sha', state: 'pending',
    context: 'driver-review', description: 'Awaiting PR author /reviewed',
    target_url: 'https://github.com/opentdf/platform/pull/4137#dry-run-no-comment-written',
  });
  for (const read of input.reads) {
    assert.equal(read.args.owner, 'opentdf');
    assert.equal(read.args.repo, 'platform');
    assert.equal(read.args.pull_number ?? read.args.issue_number, 4137);
  }
});

test('latest human-author exact command replays actual helper success with intercepted tracking update', async () => {
  const comments = [command({ id: 43, created_at: '2026-01-02T00:00:00Z' }),
    command(), command({ id: 44, body: '/REVIEWED' }),
    command({ id: 45, body: '/reviewed\n' }),
    command({ id: 46, user: { id: 2, type: 'User', login: 'other' } }),
    command({ id: 47, user: { id: 1, type: 'Bot', login: 'bot' } }),
    command({ id: 48, body: '<!-- driver-review-attestation -->',
      user: { id: 3, type: 'Bot', login: 'github-actions[bot]' } })];
  const report = await preview(fixture({ comments }));
  assert.equal(report.matchedCommand.id, 43);
  assert.equal(report.matchedCommand.permalink, comments[0].html_url);
  assert.deepEqual(report.commandDecisions.map(c => c.eligible), [true, true, false, false, false, false, false]);
  for (const operations of [report.resetOperations, report.commandOperations]) {
    assert.equal(operations[0].method, 'issues.updateComment');
    assert.equal(operations[0].args.comment_id, 48);
  }
  const status = statuses(report.commandOperations)[0].args;
  assert.equal(status.state, 'success');
  assert.equal(status.sha, 'current-sha');
  assert.equal(status.context, 'driver-review');
  assert.equal(status.description, 'PR author attested review of this head');
});

test('forks, closed PRs and bot authors mirror production command eligibility', async () => {
  for (const prChanges of [
    { head: { sha: 'current-sha', repo: { id: 11 } } },
    { head: { sha: 'current-sha', repo: null } },
    { state: 'closed' },
    { user: { id: 1, type: 'Bot', login: 'author' } },
  ]) {
    const report = await preview(fixture({ comments: [command()], prChanges }));
    assert.equal(report.matchedCommand, null);
    assert.deepEqual(report.commandOperations, []);
    if (prChanges.user) assert.equal(statuses(report.resetOperations)[0].args.state, 'pending');
    else assert.deepEqual(report.resetOperations, []);
  }
});

test('old bare commands remain eligible: preview does not invent head timing semantics', async () => {
  const report = await preview(fixture({ comments: [command({ created_at: '2000-01-01T00:00:00Z' })] }));
  assert.equal(statuses(report.commandOperations)[0].args.state, 'success');
  assert.match(report.limitations.join(' '), /No timestamp-to-head freshness check/);
});

test('actual helper suppresses status when live head moves during reset or command', async () => {
  const reset = await preview(fixture({ heads: ['current-sha', 'current-sha', 'new-sha'] }));
  assert.equal(reset.resetOperations.length, 1);
  assert.deepEqual(statuses(reset.resetOperations), []);
  const attestation = await preview(fixture({ comments: [command()],
    heads: ['current-sha', 'current-sha', 'current-sha', 'current-sha', 'new-sha'] }));
  assert.equal(attestation.commandOperations.length, 1);
  assert.deepEqual(statuses(attestation.commandOperations), []);
});

test('read/auth failures and mismatched queued head fail closed without fallback token', async () => {
  const input = fixture();
  input.github.rest.pulls.get = async () => { throw new Error('403 read denied'); };
  await assert.rejects(preview(input), /403 read denied/);
  await assert.rejects(preview(fixture({ heads: ['new-sha'] })), /use the latest-head preview run/);
});

test('temporary workflow is PR-only, read-only, pinned and leaves production workflow untouched', () => {
  const workflow = fs.readFileSync('.github/workflows/driver-review-preview.yaml', 'utf8');
  assert.match(workflow, /pull_request:\n    types: \[opened, reopened, synchronize\]/);
  assert.doesNotMatch(workflow, /pull_request_target:|issue_comment:|workflow_dispatch:|secrets\.|: write/);
  assert.match(workflow, /permissions: \{\}/);
  for (const permission of ['contents', 'issues', 'pull-requests']) {
    assert.match(workflow, new RegExp(`${permission}: read`));
  }
  assert.match(workflow, /persist-credentials: false/);
  assert.match(workflow, /actions\/checkout@[a-f0-9]{40}/);
  assert.match(workflow, /actions\/github-script@[a-f0-9]{40}/);
  assert.match(workflow, /number == 4137/);
  assert.match(workflow, /Comments do not trigger this workflow/);
});
