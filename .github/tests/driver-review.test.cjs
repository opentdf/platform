const assert = require('node:assert/strict');
const fs = require('node:fs');
const { run: runDriverReview } = require('../actions/driver-review.js');
const { test } = require('node:test');

async function run({ eventName = 'issue_comment', action, after, commentUser = { id: 1, type: 'User' },
  author = { id: 1, type: 'User' }, head = 'abc', currentHead = head, body = '/reviewed',
  headRepoId = 10, baseRepoId = 10, existingTracking = false } = {}) {
  const statuses = [];
  const writes = [];
  const pr = { user: author, head: { sha: head, repo: headRepoId === null ? null : { id: headRepoId } },
    base: { repo: { id: baseRepoId } }, state: 'open' };
  let fetches = 0;
  const github = {
    rest: {
      pulls: { get: async () => ({ data: { ...pr, head: { ...pr.head, sha: ++fetches === 1 ? head : currentHead } } }) },
      issues: {
        listComments: () => {},
        createComment: async args => { writes.push(args); return { data: { html_url: 'https://example.test/comment' } }; },
        updateComment: async args => { writes.push(args); return { data: { html_url: 'https://example.test/comment' } }; },
      },
      repos: { createCommitStatus: async args => { statuses.push(args); } },
    },
    paginate: async () => existingTracking ? [{ id: 42, user: { login: 'github-actions[bot]' },
      body: '<!-- driver-review-attestation -->' }] : [],
  };
  const context = {
    repo: { owner: 'opentdf', repo: 'platform' }, issue: { number: 5 }, eventName,
    payload: { action, after, comment: { body, user: commentUser } },
  };
  await runDriverReview({ github, context });
  return { statuses, writes };
}

test('privileged events execute only the checked-out default-branch helper, never PR code', () => {
  const workflow = fs.readFileSync('.github/workflows/driver-review.yaml', 'utf8');
  assert.match(workflow, /ref: \$\{\{ github\.event\.repository\.default_branch \}\}/);
  assert.match(workflow, /persist-credentials: false/);
  assert.match(workflow, /require\('\.\/\.github\/actions\/driver-review\.js'\)/);
  assert.doesNotMatch(workflow, /github\.event\.pull_request\.head|refs\/pull\/|eval\(/);
  assert.doesNotMatch(runDriverReview.toString(), /\beval\(|new Function\(/);
});

test('human PR author attests fetched head', async () => {
  const { statuses, writes } = await run();
  assert.equal(statuses[0].state, 'success');
  assert.equal(statuses[0].sha, 'abc');
  assert.match(writes[0].body, /attested for head `abc`/);
});

test('same-repo comment updates existing bot tracking comment', async () => {
  const { statuses, writes } = await run({ existingTracking: true });
  assert.equal(statuses[0].state, 'success');
  assert.equal(writes[0].comment_id, 42);
  assert.equal(writes[0].issue_number, undefined);
});

test('new push leaves pending status and author instructions', async () => {
  const { statuses, writes } = await run({ eventName: 'pull_request_target', action: 'synchronize', after: 'abc' });
  assert.equal(statuses[0].state, 'pending');
  assert.match(writes[0].body, /awaiting author review/);
  assert.match(writes[0].body, /two distinct maintainer approvals/);
});

test('fork and unavailable head repo never receive tracking comments or statuses', async () => {
  for (const eventName of ['issue_comment', 'pull_request_target']) {
    for (const headRepoId of [11, null]) {
      const { statuses, writes } = await run({ eventName, headRepoId });
      assert.equal(statuses.length, 0);
      assert.equal(writes.length, 0);
    }
  }
});

test('different user, bot author, and non-exact command cannot attest', async () => {
  for (const options of [{ commentUser: { id: 2, type: 'User' } },
    { author: { id: 1, type: 'Bot' } }, { commentUser: { id: 1, type: 'Bot' } },
    { body: '/reviewed now' }, { body: ' /reviewed' }]) {
    const { statuses, writes } = await run(options);
    assert.equal(statuses.length, 0);
    assert.equal(writes.length, 0);
  }
});

test('stale synchronize delivery does not reset status', async () => {
  const { statuses, writes } = await run({ eventName: 'pull_request_target', action: 'synchronize', after: 'old' });
  assert.equal(statuses.length, 0);
  assert.equal(writes.length, 0);
});

test('head moving during run does not write status', async () => {
  // The second PR fetch sees a newer head.
  const { statuses } = await run({ currentHead: 'new' });
  assert.equal(statuses.length, 0);
});
