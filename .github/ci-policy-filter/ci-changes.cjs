const { execFileSync } = require('node:child_process');
const fs = require('node:fs');

// This is review-owned policy input, not an anti-tamper boundary: the PR also
// controls this helper and its workflow. CODEOWNERS review must approve changes
// to QA exemptions, including the config itself. JSON needs no runtime parser.
const policy = require('../ignore-checks-workflow-policy-paths.json');

function canonicalPath(path) {
  return typeof path === 'string' && path.length > 0 &&
    !/[\\\x00-\x20\x7f*?\[\]{}]/.test(path) &&
    path.split('/').every(part => part !== '' && part !== '.' && part !== '..');
}

function validatePolicy(config) {
  if (!config || Object.keys(config).sort().join(',') !== 'paths,prefixes' ||
      !Array.isArray(config.paths) || !Array.isArray(config.prefixes) ||
      !config.paths.every(canonicalPath) ||
      // No generic glob matcher or broad .github/workflows/actions exemption.
      !config.prefixes.every(prefix => prefix === '.github/ci-policy-filter/')) {
    throw new Error('Invalid workflow/policy path configuration');
  }
  return config;
}

validatePolicy(policy);
const workflowPolicyPaths = new Set(policy.paths);

function workflowPolicyOnly(paths) {
  return paths.length > 0 && paths.every(path => canonicalPath(path) &&
    (workflowPolicyPaths.has(path) || policy.prefixes.some(prefix => path.startsWith(prefix))));
}

function classify(env) {
  // workflow_ref identifies the caller for reusable workflows. A PR-triggered
  // caller must still run the full suite, as do push/merge_group/other events.
  if (env.EVENT_NAME !== 'pull_request' ||
      !env.WORKFLOW_REF?.startsWith(`${env.REPOSITORY}/.github/workflows/checks.yaml@`)) {
    return { workflow_only: false, proto: true };
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
  const paths = diff ? diff.slice(0, -1).split('\0') : [];
  return {
    workflow_only: workflowPolicyOnly(paths),
    proto: paths.some(path => /\.proto$|^Makefile$|^buf\.|^protocol\/codegen\/|^protocol\/go\/internal\/|^sdk\/codegen\//.test(path)),
  };
}

if (require.main === module) {
  const outputs = classify(process.env);
  fs.appendFileSync(process.env.GITHUB_OUTPUT,
    `workflow_only=${outputs.workflow_only}\nproto=${outputs.proto}\n`);
}

module.exports = { workflowPolicyOnly, classify, validatePolicy };
