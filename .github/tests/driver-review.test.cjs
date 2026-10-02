const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { test } = require('node:test');

const workflow = fs.readFileSync('.github/workflows/driver-review.yaml', 'utf8');
const script = workflow.split('          script: |\n')[1]
  .split('\n').map(line => line.startsWith('            ') ? line.slice(12) : line).join('\n');
assert.ok(script.includes('createCommitStatus'), 'could not extract workflow script');

async function run({ eventName = 'issue_comment', action, after, commentUser = { id: 1, type: 'User' },
  author = { id: 1, type: 'User' }, head = 'abc', currentHead = head, body = '/reviewed',
  headRepoId = 10, baseRepoId = 10 } = {}) {
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
    paginate: async () => [],
  };
  const context = {
    repo: { owner: 'opentdf', repo: 'platform' }, issue: { number: 5 }, eventName,
    payload: { action, after, comment: { body, user: commentUser } },
  };
  await vm.runInNewContext(`(async () => {\n${script}\n})()`, { github, context });
  return { statuses, writes };
}

test('human PR author attests fetched head', async () => {
  const { statuses, writes } = await run();
  assert.equal(statuses[0].state, 'success');
  assert.equal(statuses[0].sha, 'abc');
  assert.match(writes[0].body, /attested for head `abc`/);
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
