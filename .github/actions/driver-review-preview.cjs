// TEMPORARY: remove with the preview workflow after the author's confirmation.
const { run } = require('./driver-review.js');

function readOnlyAdapter(live, operations, prUrl) {
  const commentArgs = ({ owner, repo, issue_number, per_page }) => ({ owner, repo, issue_number, per_page });
  const listComments = args => live.rest.issues.listComments(commentArgs(args));
  const record = (method, args) => {
    operations.push({ method, args: structuredClone(args) });
    // No invented live comment permalink: a create would return a new URL.
    return { data: { html_url: `${prUrl}#dry-run-no-comment-written` } };
  };
  // Only these two read endpoints can reach the live client. No request/graphql
  // escape hatch, generic pagination, or live write method reaches the helper.
  return Object.freeze({
    rest: Object.freeze({
      pulls: Object.freeze({ get: ({ owner, repo, pull_number }) =>
        live.rest.pulls.get({ owner, repo, pull_number }) }),
      issues: Object.freeze({
        listComments,
        createComment: async args => record('issues.createComment', args),
        updateComment: async args => record('issues.updateComment', args),
      }),
      repos: Object.freeze({
        createCommitStatus: async args => record('repos.createCommitStatus', args),
      }),
    }),
    paginate: (method, args) => {
      if (method !== listComments) throw new Error('Preview denies non-allowlisted pagination');
      return live.paginate(live.rest.issues.listComments, commentArgs(args));
    },
  });
}

async function preview({ github: live, context }) {
  const { owner, repo } = context.repo;
  const number = context.payload.pull_request.number;
  const operations = [];
  const github = readOnlyAdapter(live, operations, `https://github.com/${owner}/${repo}/pull/${number}`);
  const pr = (await github.rest.pulls.get({ owner, repo, pull_number: number })).data;
  // A rerun keeps its original event payload. Do not label a newer head's
  // behavior as evidence for that old run; use a run for the latest push.
  if (pr.head.sha !== context.payload.pull_request.head.sha) {
    throw new Error('Live head differs from this run; use the latest-head preview run');
  }
  const comments = await github.paginate(github.rest.issues.listComments, {
    owner, repo, issue_number: number, per_page: 100,
  });
  const decisions = comments.map(comment => ({
    id: comment.id,
    permalink: comment.html_url,
    author: comment.user.login,
    authorType: comment.user.type,
    exactBody: comment.body === '/reviewed',
    matchesAuthorId: comment.user.id === pr.user.id,
    eligible: pr.state === 'open' && pr.head.repo?.id === pr.base.repo.id &&
      pr.user.type === 'User' && comment.user.type === 'User' &&
      comment.user.id === pr.user.id && comment.body === '/reviewed',
  }));
  const eligible = comments.filter((_, index) => decisions[index].eligible)
    .sort((a, b) => new Date(a.created_at) - new Date(b.created_at) || a.id - b.id);
  const matched = eligible.at(-1);
  const base = { repo: { owner, repo }, issue: { number } };
  // Independent hypothetical deliveries, not a claim that a comment triggers
  // this PR workflow. These invoke the production helper unchanged.
  await run({ github, context: { ...base, eventName: 'pull_request_target', payload: {
    action: context.payload.action, after: context.payload.pull_request.head.sha,
  } } });
  const resetOperations = operations.splice(0);
  if (matched) {
    await run({ github, context: { ...base, eventName: 'issue_comment', payload: {
      action: 'created', comment: matched,
    } } });
  }
  return {
    mode: 'DRY RUN / NO REAL STATUS OR COMMENT WRITTEN',
    repository: `${owner}/${repo}`, number, head: pr.head.sha,
    prState: pr.state, prAuthor: pr.user.login, prAuthorType: pr.user.type,
    sameRepository: Boolean(pr.head.repo && pr.head.repo.id === pr.base.repo.id),
    commandDecisions: decisions,
    matchedCommand: matched ? { id: matched.id, permalink: matched.html_url,
      createdAt: matched.created_at } : null,
    commandResult: matched ? 'Replayed latest eligible human-author exact /reviewed' :
      'No eligible command: no success simulated',
    resetOperations, commandOperations: operations,
    limitations: [
      'Comments do NOT trigger this temporary workflow. Post /reviewed personally, then rerun the latest-head job to read current live comments.',
      'Comment/status API writes are intercepted; create/update responses use a synthetic target URL. This is not an end-to-end write test.',
      'Reset and command are separate hypothetical deliveries using current live comment bodies, not historical webhook evidence or persisted state. No timestamp-to-head freshness check is added: production accepts a bare command, including older comments. Shared-SHA and delivery-order risks remain unchanged.',
    ],
  };
}

module.exports = { preview, readOnlyAdapter };
