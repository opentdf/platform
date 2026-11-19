const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync, spawnSync } = require('node:child_process');
const { classify: classifyChanges, workflowPolicyOnly, validatePolicy } = require('./ci-changes.cjs');
const classify = env => classifyChanges(env).workflow_only;

const prEnv = { EVENT_NAME: 'pull_request', REPOSITORY: 'opentdf/platform',
  WORKFLOW_REF: 'opentdf/platform/.github/workflows/checks.yaml@refs/pull/123/merge' };

const config = require('../../ignore-checks-workflow-policy-paths.json');
const allowed = [...config.paths, ...fs.readdirSync(__dirname)
  .filter(file => file !== 'node_modules').map(file => `.github/actions/ci-checks/${file}`)];

test('review-owned JSON policy allows each exact path without allowing lookalikes', () => {
  assert.equal(validatePolicy(config), config);
  assert.ok(config.paths.includes('.github/ignore-checks-workflow-policy-paths.json'),
    'the policy config remains self-allowlisted');
  assert.ok(!config.paths.includes('.github/workflows/checks.yaml'),
    'the broad QA workflow must not be exempted');
  assert.deepEqual(config.prefixes, ['.github/actions/ci-checks/']);
  // Exercise the reviewed configuration, not a second copied allowlist that
  // would need to change whenever owners approve another exact support path.
  for (const file of config.paths) {
    assert.equal(workflowPolicyOnly([file]), true, file);
    for (const lookalike of [`${file}.unknown`, `${file}/unknown`, `${file} `, `${file}\nservice/main.go`]) {
      assert.equal(workflowPolicyOnly([lookalike]), false, lookalike);
      assert.equal(workflowPolicyOnly([...allowed, lookalike]), false, lookalike);
    }
  }
  assert.equal(workflowPolicyOnly(allowed), true);
});

test('canonicalization and unknown paths fail closed independently of reviewed support paths', () => {
  assert.equal(workflowPolicyOnly([]), false);
  for (const unknown of ['CODEOWNERS', 'LICENSE', 'README.md', 'docs/example.md',
    '.github/workflows/checks.yaml',
    '.github/actions/ci-changes.cjs', '.github/actions/ci-changes.test.cjs',
    '.github/actions/ci-results.js', '.github/actions/ci-results.test.cjs',
    '.github/actions/ci-workflow.test.cjs', '.github/actions/package.json', '.github/actions/package-lock.json',
    '.github/scripts/work-init.sh', '.github/dependabot.yml',
    '.github/workflows/unknown.yaml', '.github/actions/unknown.js', '.github/tests/unknown.cjs',
    '.github/tests/go.mod', '.github/tests/../../service/main.go',
    '.github/actions/ci-checks-elsewhere/helper.cjs', '.github/actions/ci-checks/../actions/unknown.js',
    '.github/actions/ci-checks//unknown.cjs', '.github/actions/ci-checks/../../service/main.go',
    '.github/actions/ci-checks/unknown.cjs\nservice/main.go', 'agents.md']) {
    assert.equal(workflowPolicyOnly([unknown]), false, unknown);
    assert.equal(workflowPolicyOnly([...allowed, unknown]), false, unknown);
  }
});

test('code and Go dependencies require full QA alone or mixed with all reviewed support paths', () => {
  for (const code of ['service/main.go', 'sdk/go.mod', 'go.work', 'go.work.sum',
    'Dockerfile', 'Makefile', 'buf.yaml', 'protocol/test.proto']) {
    assert.equal(workflowPolicyOnly([code]), false, code);
    assert.equal(workflowPolicyOnly([...allowed, code]), false, code);
  }
});

test('policy configuration rejects malformed paths and broad prefixes', () => {
  assert.throws(() => validatePolicy(null), /Invalid/);
  for (const paths of [null, ['service/**'], ['../service/main.go'], ['/service/main.go'],
    ['.github/actions/ci-checks/../main.go'], ['AGENTS.md\nservice/main.go']]) {
    assert.throws(() => validatePolicy({ paths, prefixes: [] }), /Invalid/);
  }
  for (const prefixes of [null, ['.github/'], ['.github/actions/'], ['.github/workflows/'],
    ['.github/ci-policy-filter/'], ['.github/actions/ci-checks'], ['.github/actions/ci-checks/**']]) {
    assert.throws(() => validatePolicy({ paths: [], prefixes }), /Invalid/);
  }
  assert.throws(() => validatePolicy({ paths: [], prefixes: [], glob: '**' }), /Invalid/);
});

test('push, merge_group, workflow_call and PR-triggered reusable callers run full QA', () => {
  for (const EVENT_NAME of ['push', 'merge_group', 'workflow_call', 'workflow_dispatch', 'schedule']) {
    assert.deepEqual(classifyChanges({ ...prEnv, EVENT_NAME }), { workflow_only: false, proto: true });
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
  // Synthetic fixture commits are never published. commit-tree requires no
  // working branch or changes to the user's signing configuration.
  function snapshot(parent) {
    git('add', '-A');
    const tree = git('write-tree');
    return git('-c', 'user.name=CI Test', '-c', 'user.email=ci@example.invalid',
      'commit-tree', tree, ...(parent ? ['-p', parent] : []), '-m', 'test fixture');
  }
  try {
    git('init', '-q');
    write('service/main.go');
    write('.github/workflows/checks.yaml');
    write('.github/workflows/ci-unit-tests.yaml');
    const base = snapshot();
    process.chdir(directory);
    const check = head => classify({ ...prEnv, BASE_SHA: base, HEAD_SHA: head });
    assert.equal(check(base), false, 'empty diff is conservative');
    write('.policy.yml');
    const unrelated = snapshot();
    assert.throws(() => check(unrelated), /no merge base/);
    git('read-tree', '--reset', '-u', base);
    const output = path.join(directory, '.git', 'classification-output');
    fs.writeFileSync(output, '');
    const failed = spawnSync(process.execPath, [path.join(__dirname, 'ci-changes.cjs')], {
      cwd: directory,
      env: { ...process.env, ...prEnv, BASE_SHA: base, HEAD_SHA: unrelated, GITHUB_OUTPUT: output },
      encoding: 'utf8',
    });
    assert.notEqual(failed.status, 0, 'classification failure fails the step');
    assert.equal(fs.readFileSync(output, 'utf8'), '', 'failure never emits skip-authorizing outputs');
    fs.unlinkSync(path.join(directory, '.github/workflows/ci-unit-tests.yaml'));
    assert.equal(check(snapshot(base)), true, 'allowlisted deletion');
    git('read-tree', '--reset', '-u', base);
    fs.appendFileSync(path.join(directory, '.github/workflows/checks.yaml'), 'changed\n');
    assert.equal(check(snapshot(base)), false, 'broad QA workflow modification runs full QA');
    git('read-tree', '--reset', '-u', base);
    fs.unlinkSync(path.join(directory, '.github/workflows/checks.yaml'));
    assert.equal(check(snapshot(base)), false, 'broad QA workflow deletion runs full QA');
    git('read-tree', '--reset', '-u', base);
    fs.mkdirSync(path.join(directory, '.github/actions/ci-checks'), { recursive: true });
    git('mv', 'service/main.go', '.github/actions/ci-checks/ci-changes.cjs');
    assert.equal(check(snapshot(base)), false, 'old code path prevents skip');
    git('read-tree', '--reset', '-u', base);
    git('mv', '.github/workflows/ci-unit-tests.yaml', 'CODEOWNERS');
    assert.equal(check(snapshot(base)), false, 'new special path prevents skip');
    git('read-tree', '--reset', '-u', base);
    write('.github/workflows/ci-unit-tests.yaml\nservice.go');
    assert.equal(check(snapshot(base)), false, 'NUL delimiters preserve unusual paths');
    git('read-tree', '--reset', '-u', base);
    write('.github/ignore-checks-workflow-policy-paths.json');
    write('.github/actions/ci-checks/ci-changes.cjs');
    const workflowHead = snapshot(base);
    assert.equal(check(workflowHead), true);
    assert.equal(classifyChanges({ ...prEnv, BASE_SHA: base, HEAD_SHA: workflowHead }).proto, false);
    const success = spawnSync(process.execPath, [path.join(__dirname, 'ci-changes.cjs')], {
      cwd: directory,
      env: { ...process.env, ...prEnv, BASE_SHA: base, HEAD_SHA: workflowHead, GITHUB_OUTPUT: output },
      encoding: 'utf8',
    });
    assert.equal(success.status, 0, success.stderr);
    assert.equal(fs.readFileSync(output, 'utf8'), 'workflow_only=true\nproto=false\n');
    git('read-tree', '--reset', '-u', base);
    write('sdk/go.mod');
    const advancedBase = snapshot(base);
    assert.equal(classify({ ...prEnv, BASE_SHA: advancedBase, HEAD_SHA: workflowHead }), true,
      'upstream-only code/dependency changes are not PR changes');
    git('read-tree', '--reset', '-u', base);
    write('service/policy.proto');
    assert.deepEqual(classifyChanges({ ...prEnv, BASE_SHA: base, HEAD_SHA: snapshot(base) }),
      { workflow_only: false, proto: true });
    git('read-tree', '--reset', '-u', workflowHead);
    write('sdk/go.mod');
    assert.equal(classify({ ...prEnv, BASE_SHA: advancedBase, HEAD_SHA: snapshot(workflowHead) }), false,
      'mixed-path PR still runs full QA even when base also changes dependencies');
  } finally {
    process.chdir(original);
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
