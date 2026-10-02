const { execFileSync } = require('node:child_process');
const fs = require('node:fs');

// Only this PR's workflow/policy support files qualify. In particular, do not
// expand this to all Markdown, .github, scripts, CODEOWNERS, or dependencies.
const workflowPolicyPaths = new Set([
  'AGENTS.md',
  '.policy.yml',
  '.github/workflows/checks.yaml',
  '.github/workflows/driver-review.yaml',
  '.github/workflows/actions-unit-tests.yaml',
  '.github/workflows/policy-review-unit-tests.yaml',
  '.github/actions/driver-review.js',
  '.github/actions/driver-review.test.cjs',
  '.github/actions/driver-review-workflow.test.cjs',
  '.github/actions/ci-changes.cjs',
  '.github/tests/ci-checks.test.cjs',
  '.github/tests/policy-review.test.cjs',
  // These dependencies are confined to the policy/workflow tests, not Go code.
  '.github/tests/package.json',
  '.github/tests/package-lock.json',
]);

function workflowPolicyOnly(paths) {
  return paths.length > 0 && paths.every(path => workflowPolicyPaths.has(path));
}

function classify(env) {
  // workflow_ref identifies the caller for reusable workflows. A PR-triggered
  // caller must still run the full suite, as do push/merge_group/other events.
  if (env.EVENT_NAME !== 'pull_request' ||
      !env.WORKFLOW_REF?.startsWith(`${env.REPOSITORY}/.github/workflows/checks.yaml@`)) {
    return false;
  }
  for (const sha of [env.BASE_SHA, env.HEAD_SHA]) {
    if (!/^[a-f0-9]{40}$/.test(sha ?? '')) throw new Error('Missing or invalid PR SHA');
  }
  // NUL delimiters preserve unusual filenames. Disabling rename detection
  // includes BOTH old and new paths, including moves out of a protected path.
  // Any git failure/truncation fails the changes job, never authorizes skipping.
  // Match GitHub's PR diff: upstream-only changes since the common ancestor
  // are not PR changes. Failure to find a merge base also fails closed.
  const diff = execFileSync('git', [
    'diff', '--name-only', '-z', '--no-renames', `${env.BASE_SHA}...${env.HEAD_SHA}`, '--',
  ], { maxBuffer: 64 * 1024 * 1024 }).toString('utf8');
  if (diff && !diff.endsWith('\0')) throw new Error('Incomplete changed-path list');
  return workflowPolicyOnly(diff ? diff.slice(0, -1).split('\0') : []);
}

if (require.main === module) {
  fs.appendFileSync(process.env.GITHUB_OUTPUT, `workflow_only=${classify(process.env)}\n`);
}

module.exports = { workflowPolicyOnly, classify };
