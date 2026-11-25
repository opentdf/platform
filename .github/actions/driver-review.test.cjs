const assert = require('node:assert/strict');
const fs = require('node:fs');
const { run: runDriverReview } = require('./driver-review.js');
const { test } = require('node:test');

async function run({ eventName = 'issue_comment', action, after, commentUser = { id: 1, type: 'User' },
  author = { id: 1, type: 'User' }, head = 'abc', currentHead = head, body = '/reviewed',
  headRepoId = 10, baseRepoId = 10, existingTracking = false, comments, state = 'open',
  failAt } = {}) {
  const statuses = [];
  const writes = [];
  const reads = [];
  const pr = { user: author, head: { sha: head, repo: headRepoId === null ? null : { id: headRepoId } },
    base: { repo: { id: baseRepoId } }, state };
  let fetches = 0;
  const fail = step => { if (failAt === step) throw new Error(`${step} failed`); };
  const listComments = () => {};
  const github = {
    rest: {
      pulls: { get: async args => {
        reads.push({ step: 'get', args });
        fail(++fetches === 1 ? 'first get' : 'second get');
        return { data: { ...pr, head: { ...pr.head, sha: fetches === 1 ? head : currentHead } } };
      } },
      issues: {
        listComments,
        createComment: async args => {
          fail('create');
          writes.push({ step: 'create', args });
          return { data: { html_url: 'https://example.test/new-comment' } };
        },
        updateComment: async args => {
          fail('update');
          writes.push({ step: 'update', args });
          return { data: { html_url: 'https://example.test/updated-comment' } };
        },
      },
      repos: { createCommitStatus: async args => { statuses.push(args); fail('status'); } },
    },
    paginate: async (method, args) => {
      reads.push({ step: 'paginate', method, args });
      fail('paginate');
      return comments ?? (existingTracking ? [{ id: 42, user: { login: 'github-actions[bot]' },
        body: '<!-- driver-review-attestation -->' }] : []);
    },
  };
  const context = {
    repo: { owner: 'opentdf', repo: 'platform' }, issue: { number: 5 }, eventName,
    payload: { action, after, comment: { body, user: commentUser } },
  };
  const result = { statuses, writes, reads, listComments };
  try {
    await runDriverReview({ github, context });
  } catch (error) {
    error.calls = result;
    throw error;
  }
  return result;
}

test('unprivileged action tests run only when action files change', () => {
  const workflow = fs.readFileSync('.github/workflows/actions-unit-tests.yaml', 'utf8');
  assert.match(workflow, /on:\n  pull_request:\n    paths:\n      - '\.github\/actions\/\*\*'/);
  assert.doesNotMatch(workflow, /pull_request_target:|issue_comment:|push:/);
  assert.match(workflow, /permissions: \{\}/);
  assert.match(workflow, /contents: read/);
  assert.match(workflow, /node --test \.github\/actions\/\*\.test\.cjs/);
});

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
  assert.match(writes[0].args.body, /attested for head `abc`/);
});

test('same-repo comment updates existing bot tracking comment', async () => {
  const { statuses, writes } = await run({ existingTracking: true });
  assert.equal(statuses[0].state, 'success');
  assert.equal(writes[0].args.comment_id, 42);
  assert.equal(writes[0].args.issue_number, undefined);
});

test('new push leaves pending status and author instructions', async () => {
  const { statuses, writes } = await run({ eventName: 'pull_request_target', action: 'synchronize', after: 'abc' });
  assert.equal(statuses[0].state, 'pending');
  assert.match(writes[0].args.body, /awaiting author review/);
  assert.match(writes[0].args.body, /two distinct maintainer approvals/);
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

test('head moving during run may update comment but must not write status', async () => {
  // The second PR fetch sees a newer head after the comment write.
  const { statuses, writes, reads } = await run({ currentHead: 'new' });
  assert.equal(statuses.length, 0);
  assert.equal(writes.length, 1);
  assert.deepEqual(reads.map(({ step }) => step), ['get', 'paginate', 'get']);
});

test('opened and reopened PRs initialize pending status on the fetched head', async () => {
  for (const action of ['opened', 'reopened']) {
    const { statuses, writes, reads, listComments } = await run({ eventName: 'pull_request_target', action, head: 'new-head' });
    assert.deepEqual(reads.map(({ step }) => step), ['get', 'paginate', 'get']);
    assert.deepEqual(reads[0].args, { owner: 'opentdf', repo: 'platform', pull_number: 5 });
    assert.deepEqual(reads[1].args, { owner: 'opentdf', repo: 'platform', issue_number: 5, per_page: 100 });
    assert.equal(reads[1].method, listComments);
    assert.equal(writes.length, 1);
    assert.equal(writes[0].step, 'create');
    assert.match(writes[0].args.body, /awaiting author review for head `new-head`/);
    assert.deepEqual(statuses, [{ owner: 'opentdf', repo: 'platform', sha: 'new-head',
      state: 'pending', context: 'driver-review', description: 'Awaiting PR author /reviewed',
      target_url: 'https://example.test/new-comment' }]);
  }
});

test('closed PRs do not paginate, write comments, or set status', async () => {
  for (const eventName of ['issue_comment', 'pull_request_target']) {
    const { statuses, writes, reads } = await run({ eventName, state: 'closed' });
    assert.deepEqual(reads.map(({ step }) => step), ['get']);
    assert.deepEqual(writes, []);
    assert.deepEqual(statuses, []);
  }
});

test('only a bot comment with the tracking marker is updated across paginated results', async () => {
  const comments = [
    { id: 1, user: { login: 'human' }, body: '<!-- driver-review-attestation -->' },
    { id: 2, user: { login: 'github-actions[bot]' }, body: 'unrelated' },
    { id: 42, user: { login: 'github-actions[bot]' }, body: 'previous\n<!-- driver-review-attestation -->' },
  ];
  const { writes, statuses, reads, listComments } = await run({ comments });
  assert.equal(reads[1].method, listComments);
  assert.deepEqual(reads[1].args, { owner: 'opentdf', repo: 'platform', issue_number: 5, per_page: 100 });
  assert.equal(writes.length, 1);
  assert.equal(writes[0].step, 'update');
  assert.equal(writes[0].args.comment_id, 42);
  assert.equal(writes[0].args.issue_number, undefined);
  assert.equal(statuses[0].target_url, 'https://example.test/updated-comment');
});

test('non-bot marker and unrelated bot comment do not replace tracking comment', async () => {
  const { writes, statuses } = await run({ comments: [
    { id: 1, user: { login: 'human' }, body: '<!-- driver-review-attestation -->' },
    { id: 2, user: { login: 'github-actions[bot]' }, body: 'unrelated' },
  ] });
  assert.equal(writes.length, 1);
  assert.equal(writes[0].step, 'create');
  assert.deepEqual({ owner: writes[0].args.owner, repo: writes[0].args.repo,
    issue_number: writes[0].args.issue_number }, { owner: 'opentdf', repo: 'platform', issue_number: 5 });
  assert.match(writes[0].args.body, /^<!-- driver-review-attestation -->/);
  assert.equal(statuses[0].target_url, 'https://example.test/new-comment');
});

test('comment status references the fetched SHA and new tracking comment URL', async () => {
  const { statuses, writes } = await run({ head: 'attested-head' });
  assert.equal(writes[0].step, 'create');
  assert.deepEqual(statuses, [{ owner: 'opentdf', repo: 'platform', sha: 'attested-head',
    state: 'success', context: 'driver-review', description: 'PR author attested review of this head',
    target_url: 'https://example.test/new-comment' }]);
});

test('API failures propagate without issuing a success status', async () => {
  for (const failAt of ['first get', 'paginate', 'create', 'second get']) {
    await assert.rejects(run({ failAt }), error => {
      assert.equal(error.message, `${failAt} failed`);
      assert.deepEqual(error.calls.statuses, []);
      if (failAt === 'paginate') assert.deepEqual(error.calls.writes, []);
      return true;
    });
  }
  await assert.rejects(run({ existingTracking: true, failAt: 'update' }), error => {
    assert.equal(error.message, 'update failed');
    assert.deepEqual(error.calls.statuses, []);
    return true;
  });
});
