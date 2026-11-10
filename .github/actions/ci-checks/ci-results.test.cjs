const { test } = require('node:test');
const assert = require('node:assert/strict');
const checkResults = require('./ci-results.js');
const { validateResults } = checkResults;
const gated = ['go', 'image', 'integration', 'benchmark', 'license',
  'platform-xtest', 'tests-bdd', 'otdfctl-test'];

function needsFor({ workflowOnly = false, proto = false, event = 'pull_request' } = {}) {
  return {
    changes: { result: 'success', outputs: { workflow_only: String(workflowOnly), proto: String(proto) } },
    buflint: { result: event === 'pull_request' && !proto ? 'skipped' : 'success' },
    ...Object.fromEntries(gated.map(job => [job, {
      result: workflowOnly || (event === 'merge_group' && !['go', 'image'].includes(job))
        ? 'skipped' : 'success',
    }])),
  };
}

test('ci-results accepts only deliberate skips and normal successes for each event', () => {
  for (const workflowOnly of [true, false]) {
    validateResults(needsFor({ workflowOnly }), 'pull_request');
  }
  validateResults(needsFor({ proto: true }), 'pull_request');
  for (const event of ['push', 'merge_group', 'workflow_call', 'workflow_dispatch', 'schedule']) {
    validateResults(needsFor({ event, proto: true }), event);
    assert.throws(() => validateResults(needsFor({ event, workflowOnly: true }), event), /Only/);
  }
});

test('ci-results fails closed on invalid classification and missing needs', () => {
  for (const result of ['failure', 'cancelled', 'skipped', undefined]) {
    const needs = needsFor({ workflowOnly: true });
    needs.changes.result = result;
    assert.throws(() => validateResults(needs, 'pull_request'), /classification/);
  }
  for (const output of ['workflow_only', 'proto']) {
    for (const value of ['', undefined, 'unknown', true, false]) {
      const needs = needsFor();
      needs.changes.outputs[output] = value;
      assert.throws(() => validateResults(needs, 'pull_request'), /classification/);
    }
  }
  for (const malformed of [null, {}, { changes: {} }, { changes: { result: 'success' } }]) {
    assert.throws(() => validateResults(malformed, 'pull_request'));
  }
});

test('ci-results rejects failed, cancelled, absent, or unexpectedly skipped QA', () => {
  for (const job of [...gated, 'buflint']) {
    for (const result of ['failure', 'cancelled', 'skipped', undefined]) {
      const needs = needsFor({ proto: true });
      needs[job].result = result;
      assert.throws(() => validateResults(needs, 'pull_request'), new RegExp(job));
    }
    const missing = needsFor({ proto: true });
    delete missing[job];
    assert.throws(() => validateResults(missing, 'pull_request'), new RegExp(job));
    for (const result of ['success', 'failure', 'cancelled']) {
      const needs = needsFor({ workflowOnly: true });
      needs[job].result = result;
      assert.throws(() => validateResults(needs, 'pull_request'), new RegExp(job));
    }
  }
  for (const job of gated.filter(job => !['go', 'image'].includes(job))) {
    const needs = needsFor({ event: 'merge_group' });
    needs[job].result = 'success';
    assert.throws(() => validateResults(needs, 'merge_group'), new RegExp(job));
  }
});

test('github-script entrypoint marks the required check failed for malformed JSON or invalid needs', () => {
  for (const NEEDS_JSON of ['', '{', 'null', '{}', JSON.stringify(needsFor({ workflowOnly: true }))]) {
    const failures = [];
    checkResults({ core: { setFailed: message => failures.push(message) } },
      { NEEDS_JSON, EVENT_NAME: 'push' });
    assert.equal(failures.length, 1);
    assert.equal(typeof failures[0], 'string');
  }
  checkResults({ core: { setFailed: assert.fail } },
    { NEEDS_JSON: JSON.stringify(needsFor()), EVENT_NAME: 'pull_request' });
});
