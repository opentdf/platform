const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync, spawnSync } = require('node:child_process');
const YAML = require('yaml');
const { workflowPolicyOnly, classify } = require('../actions/ci-changes.cjs');

const root = path.join(__dirname, '../..');
const workflow = YAML.parse(fs.readFileSync(path.join(root, '.github/workflows/checks.yaml'), 'utf8'));
const gated = ['go', 'image', 'integration', 'benchmark', 'license', 'platform-xtest', 'tests-bdd', 'otdfctl-test'];
const prEnv = { EVENT_NAME: 'pull_request', REPOSITORY: 'opentdf/platform',
  WORKFLOW_REF: 'opentdf/platform/.github/workflows/checks.yaml@refs/pull/4137/merge' };

test('allowlist covers only explicit workflow/policy support paths for this PR', () => {
  const allowed = ['AGENTS.md', '.policy.yml', '.github/workflows/checks.yaml',
    '.github/workflows/driver-review.yaml', '.github/workflows/actions-unit-tests.yaml',
    '.github/workflows/policy-review-unit-tests.yaml', '.github/actions/driver-review.js',
    '.github/actions/driver-review.test.cjs', '.github/actions/driver-review-workflow.test.cjs',
    '.github/actions/ci-changes.cjs', '.github/tests/ci-checks.test.cjs',
    '.github/tests/policy-review.test.cjs', '.github/tests/package.json', '.github/tests/package-lock.json'];
  assert.equal(workflowPolicyOnly(allowed), true);
  assert.equal(workflowPolicyOnly([]), false);
  for (const unknown of ['service/main.go', 'sdk/go.mod', 'go.work', 'go.work.sum', 'LICENSE',
    'CODEOWNERS', 'README.md', 'docs/example.md', 'Dockerfile', 'Makefile', 'buf.yaml',
    'protocol/test.proto', '.github/scripts/work-init.sh', '.github/dependabot.yml',
    '.github/workflows/unknown.yaml', '.github/actions/unknown.js', '.github/tests/unknown.cjs',
    '.github/tests/go.mod', '.github/tests/../../service/main.go', '.policy.yml\nservice/main.go',
    'AGENTS.md ', 'agents.md']) {
    assert.equal(workflowPolicyOnly([...allowed, unknown]), false, unknown);
  }
});

test('push, merge_group, workflow_call and PR-triggered reusable callers run full QA', () => {
  for (const EVENT_NAME of ['push', 'merge_group', 'workflow_call', 'workflow_dispatch', 'schedule']) {
    assert.equal(classify({ ...prEnv, EVENT_NAME }), false);
  }
  for (const WORKFLOW_REF of [undefined,
    'opentdf/platform/.github/workflows/nightly-checks.yaml@refs/heads/main',
    'other/repo/.github/workflows/checks.yaml@refs/heads/main']) {
    assert.equal(classify({ ...prEnv, WORKFLOW_REF }), false);
  }
  assert.throws(() => classify(prEnv), /invalid PR SHA/);
  assert.throws(() => classify({ ...prEnv, BASE_SHA: 'a'.repeat(40), HEAD_SHA: 'b'.repeat(40) }));
});

test('git classifier includes deleted files, both rename sides, and unusual filenames', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'ci-changes-'));
  const original = process.cwd();
  const git = (...args) => execFileSync('git', args, { cwd: directory, encoding: 'utf8' }).trim();
  function write(file) {
    fs.mkdirSync(path.dirname(path.join(directory, file)), { recursive: true });
    fs.writeFileSync(path.join(directory, file), 'test\n');
  }
  // Tree snapshots exercise git diff without creating commits or requiring CI
  // signing credentials. Production still validates the event's commit SHAs.
  function snapshot() {
    git('add', '-A');
    return git('write-tree');
  }
  try {
    git('init', '-q');
    write('service/main.go');
    write('AGENTS.md');
    const base = snapshot();
    process.chdir(directory);
    const check = head => classify({ ...prEnv, BASE_SHA: base, HEAD_SHA: head });
    assert.equal(check(base), false, 'empty diff is conservative');
    fs.unlinkSync(path.join(directory, 'AGENTS.md'));
    assert.equal(check(snapshot()), true, 'allowlisted deletion');
    git('read-tree', '--reset', '-u', base);
    git('mv', 'service/main.go', '.policy.yml');
    assert.equal(check(snapshot()), false, 'old code path prevents skip');
    git('read-tree', '--reset', '-u', base);
    git('mv', 'AGENTS.md', 'CODEOWNERS');
    assert.equal(check(snapshot()), false, 'new special path prevents skip');
    git('read-tree', '--reset', '-u', base);
    write('.github/workflows/checks.yaml\nservice.go');
    assert.equal(check(snapshot()), false, 'NUL delimiters preserve unusual paths');
    git('read-tree', '--reset', '-u', base);
    write('.policy.yml');
    assert.equal(check(snapshot()), true);
  } finally {
    process.chdir(original);
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

function needsFor({ workflowOnly = false, proto = false, event = 'pull_request' } = {}) {
  return {
    changes: { result: 'success', outputs: { workflow_only: String(workflowOnly), proto: String(proto) } },
    buflint: { result: event === 'pull_request' && !proto ? 'skipped' : 'success' },
    ...Object.fromEntries(gated.map(job => [job, { result: workflowOnly ? 'skipped' : 'success' }])),
  };
}

function aggregate(needs, event = 'pull_request') {
  // Execute the actual inline aggregator, not a copied model of its behavior.
  return spawnSync('bash', ['-e', '-c', workflow.jobs.ci.steps[0].run], {
    env: { ...process.env, NEEDS_JSON: JSON.stringify(needs), EVENT_NAME: event }, encoding: 'utf8',
  }).status;
}

test('required ci always reports and directly depends on the classifier and every QA job', () => {
  assert.equal(workflow.jobs.ci.if, '${{ always() }}');
  assert.deepEqual(new Set(workflow.jobs.ci.needs), new Set(['changes', 'buflint', ...gated]));
  for (const job of gated) {
    assert.equal(workflow.jobs[job].needs, 'changes');
    assert.equal(workflow.jobs[job].if, "needs.changes.outputs.workflow_only != 'true'");
  }
  assert.equal(workflow.jobs.buflint.if, "needs.changes.outputs.proto == 'true' || github.event_name != 'pull_request'");
  assert.match(workflow.jobs['comment-govulncheck'].if, /needs.go.result != 'skipped'/);
});

test('required ci accepts only deliberately skipped workflow-only QA and normal successes', () => {
  for (const workflowOnly of [true, false]) {
    assert.equal(aggregate(needsFor({ workflowOnly })), 0);
  }
  assert.equal(aggregate(needsFor({ proto: true })), 0);
  for (const event of ['push', 'merge_group', 'workflow_call']) {
    assert.equal(aggregate(needsFor({ event }), event), 0);
    assert.notEqual(aggregate(needsFor({ event, workflowOnly: true }), event), 0);
  }
});

test('required ci fails closed on failed gates, invalid outputs, cancelled and unexpected skipped QA', () => {
  for (const result of ['failure', 'cancelled', 'skipped']) {
    const needs = needsFor({ workflowOnly: true });
    needs.changes.result = result;
    assert.notEqual(aggregate(needs), 0, `changes ${result}`);
  }
  for (const output of ['workflow_only', 'proto']) {
    for (const value of ['', undefined, 'unknown']) {
      const needs = needsFor();
      needs.changes.outputs[output] = value;
      assert.notEqual(aggregate(needs), 0, `${output} ${value}`);
    }
  }
  for (const job of [...gated, 'buflint']) {
    for (const result of ['failure', 'cancelled', 'skipped']) {
      const needs = needsFor({ proto: true });
      needs[job].result = result;
      assert.notEqual(aggregate(needs), 0, `${job} ${result}`);
    }
    const needs = needsFor({ workflowOnly: true });
    needs[job].result = 'failure';
    assert.notEqual(aggregate(needs), 0, `workflow-only ${job} failure`);
  }
});

test('classifier and workflow regression tests are covered by the existing policy test workflow', () => {
  const policyTests = YAML.parse(fs.readFileSync(path.join(root, '.github/workflows/policy-review-unit-tests.yaml'), 'utf8'));
  for (const file of ['.github/actions/ci-changes.cjs', '.github/tests/ci-checks.test.cjs', '.github/workflows/checks.yaml']) {
    assert.ok(policyTests.on.pull_request.paths.includes(file), file);
  }
  assert.ok(policyTests.jobs.test.steps.some(step => step.run === 'node --test .github/tests/*.test.cjs'));
});
