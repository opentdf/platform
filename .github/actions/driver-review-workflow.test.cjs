const assert = require('node:assert/strict');
const fs = require('node:fs');
const { test } = require('node:test');
const vm = require('node:vm');

const workflow = fs.readFileSync('.github/workflows/driver-review.yaml', 'utf8');
const group = workflow.match(/^  group: (.+)$/m)[1];
const jobCondition = workflow.match(/^    if: (.+)$/m)[1];
const eligibility = "github.event_name == 'pull_request_target' || (github.event.issue.pull_request && github.event.comment.body == '/reviewed')";

function event({ eventName = 'issue_comment', number = 5, body = '/reviewed', isPR = true,
  action = 'created' } = {}) {
  return { event_name: eventName, event: {
    action,
    issue: eventName === 'issue_comment' ? { number, pull_request: isPR ? {} : undefined } : {},
    comment: { body },
    pull_request: eventName === 'pull_request_target' ? { number } : {},
  } };
}

// Evaluate only the operator/property subset used by this workflow, not arbitrary
// Actions functions. GitHub string equality is case-insensitive, unlike JS ==.
function evaluate(expression, github) {
  const translated = expression.replace(/(github\.[\w.]+) == ('[^']*')/g, 'equal($1, $2)');
  return vm.runInNewContext(translated, {
    github,
    equal: (left, right) => typeof left === 'string' && typeof right === 'string'
      ? left.toLowerCase() === right.toLowerCase() : left === right,
  }, { timeout: 100 });
}

function groupFor(github) {
  return group.replace(/\$\{\{ (.*?) \}\}/g, (_, expression) => {
    const value = evaluate(expression, github);
    return value == null ? '' : String(value);
  });
}

function queue(pending, github) {
  // GitHub retains one pending run per group even with cancel-in-progress:false.
  pending.set(groupFor(github), github);
}

test('workflow concurrency gates exactly the attestation job without unsupported functions', () => {
  assert.equal(jobCondition, eligibility);
  assert.equal(group, `driver-review-\${{ github.event.issue.number || github.event.pull_request.number }}-\${{ ${eligibility} }}`);
  assert.match(workflow, /^  cancel-in-progress: false$/m);
  assert.doesNotMatch(workflow, /^    concurrency:/m);
});

test('unrelated comments cannot replace a pending author command', () => {
  const reviewed = event();
  const pending = new Map();
  queue(pending, reviewed);
  for (const body of ['thanks', '/reviewed now', ' /reviewed', '/reviewed\n', '']) {
    const unrelated = event({ body });
    assert.equal(Boolean(evaluate(jobCondition, unrelated)), false);
    assert.notEqual(groupFor(unrelated), groupFor(reviewed));
    queue(pending, unrelated);
    assert.equal(pending.get(groupFor(reviewed)), reviewed);
  }
  assert.equal(groupFor(reviewed), 'driver-review-5-true');
});

test('issue commands are isolated and different PRs have separate groups', () => {
  const reviewed = event();
  const issue = event({ isPR: false });
  assert.equal(Boolean(evaluate(jobCondition, issue)), false);
  assert.notEqual(groupFor(issue), groupFor(reviewed));
  assert.notEqual(groupFor(event({ number: 6 })), groupFor(reviewed));
});

test('opened, reopened and synchronize resets serialize with eligible comments', () => {
  const reviewed = event();
  for (const action of ['opened', 'reopened', 'synchronize']) {
    const reset = event({ eventName: 'pull_request_target', action });
    assert.equal(Boolean(evaluate(jobCondition, reset)), true);
    assert.equal(groupFor(reset), groupFor(reviewed));
    const pending = new Map();
    queue(pending, reset);
    queue(pending, event({ body: 'thanks' }));
    assert.equal(pending.get(groupFor(reset)), reset);
  }
});

test('case-insensitive Actions equality keeps the group gate aligned with the job', () => {
  // The helper independently enforces the case-sensitive bare command. This run
  // still passes the Actions job gate, so it must use that same concurrency gate.
  const uppercase = event({ body: '/REVIEWED' });
  assert.equal(Boolean(evaluate(jobCondition, uppercase)), true);
  assert.equal(groupFor(uppercase), groupFor(event()));
});
