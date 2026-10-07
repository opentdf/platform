const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const YAML = require('yaml');
const root = path.join(__dirname, '../../..');
const readWorkflow = file => YAML.parse(fs.readFileSync(path.join(root, '.github/workflows', file), 'utf8'));
const workflow = readWorkflow('checks.yaml');
const gated = ['go', 'image', 'integration', 'benchmark', 'license',
  'platform-xtest', 'tests-bdd', 'otdfctl-test'];

test('required ci always reports and depends on classifier and every required QA job', () => {
  assert.equal(workflow.jobs.ci.if, '${{ always() }}');
  assert.deepEqual(new Set(workflow.jobs.ci.needs), new Set(['changes', 'buflint', ...gated]));
  for (const job of [...gated, 'authorization-scale']) {
    assert.equal(workflow.jobs[job].needs, 'changes');
    const condition = ['go', 'image'].includes(job)
      ? "needs.changes.outputs.workflow_only != 'true'"
      : "github.event_name != 'merge_group' && needs.changes.outputs.workflow_only != 'true'";
    assert.equal(workflow.jobs[job].if, condition);
  }
  assert.equal(workflow.jobs.buflint.if, "needs.changes.outputs.proto == 'true' || github.event_name != 'pull_request'");
  assert.match(workflow.jobs['comment-govulncheck'].if, /needs.go.result != 'skipped'/);
  assert.equal(workflow.jobs.go.steps.find(step => step.name === 'govulncheck').if,
    "github.event_name != 'merge_group'");
  assert.ok(!workflow.jobs.ci.needs.includes('authorization-scale'), 'scale remains report only');
  assert.deepEqual(workflow.permissions, {});
});

test('ci-results uses pinned github-script v9 with read-only PR merge checkout and data-only needs', () => {
  const ci = workflow.jobs.ci;
  assert.deepEqual(ci.permissions, { contents: 'read' });
  const checkout = ci.steps[0];
  assert.match(checkout.uses, /^actions\/checkout@[a-f0-9]{40}$/);
  assert.deepEqual(checkout.with, { 'persist-credentials': false });
  const results = ci.steps[1];
  assert.equal(results.uses, 'actions/github-script@3a2844b7e9c422d3c10d287c895573f7108da1b3');
  assert.deepEqual(results.env, {
    NEEDS_JSON: '${{ toJSON(needs) }}', EVENT_NAME: '${{ github.event_name }}',
  });
  assert.equal(results.with.script,
    "const checkResults = require('./.github/actions/ci-checks/ci-results.js');\ncheckResults({ core });\n");
  assert.ok(!JSON.stringify(ci).includes('secrets.'));
  assert.ok(!results.with.script.includes('${{'));
});

test('classifier writes both outputs from the PR three-dot diff without expression interpolation in shell', () => {
  const changes = workflow.jobs.changes;
  assert.deepEqual(changes.permissions, { contents: 'read' });
  assert.deepEqual(changes.outputs, {
    proto: '${{ steps.scope.outputs.proto }}', workflow_only: '${{ steps.scope.outputs.workflow_only }}',
  });
  assert.equal(changes.steps[0].with['fetch-depth'], 0);
  const classifier = changes.steps.find(step => step.id === 'scope');
  assert.equal(classifier.run, 'node .github/actions/ci-checks/ci-changes.cjs');
  assert.equal(classifier.env.BASE_SHA, '${{ github.event.pull_request.base.sha }}');
  assert.equal(classifier.env.HEAD_SHA, '${{ github.event.pull_request.head.sha }}');
});

test('focused workflow covers all helper, test, manifest and checks edits independently of PR 4137', () => {
  const tests = readWorkflow('ci-unit-tests.yaml');
  for (const event of ['pull_request', 'push']) {
    assert.deepEqual(tests.on[event].paths, [
      '.github/actions/ci-checks/**', '.github/ignore-checks-workflow-policy-paths.json',
      '.github/workflows/checks.yaml', '.github/workflows/bdd.yaml', '.github/workflows/ci-unit-tests.yaml',
    ]);
  }
  for (const file of ['ci-changes.cjs', 'ci-changes.test.cjs', 'ci-results.js',
    'ci-results.test.cjs', 'ci-workflow.test.cjs', 'package.json', 'package-lock.json']) {
    assert.ok(fs.existsSync(path.join(__dirname, file)), file);
  }
  assert.deepEqual(tests.jobs.test.permissions, { contents: 'read' });
  for (const run of ['npm ci --ignore-scripts', 'npm test']) {
    assert.equal(tests.jobs.test.steps.find(step => step.run === run)['working-directory'],
      '.github/actions/ci-checks');
  }
});
