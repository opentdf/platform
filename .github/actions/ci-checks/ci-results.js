const mergeGroupJobs = ['go', 'image'];
const nonMergeGroupJobs = ['integration', 'benchmark', 'license',
  'platform-xtest', 'tests-bdd', 'otdfctl-test'];

function validateResults(needs, eventName) {
  const outputs = needs.changes?.outputs;
  if (needs.changes?.result !== 'success' ||
      !['true', 'false'].includes(outputs?.workflow_only) ||
      !['true', 'false'].includes(outputs?.proto)) {
    throw new Error('Change classification failed or returned invalid outputs');
  }
  const isPR = eventName === 'pull_request';
  const workflowOnly = outputs.workflow_only === 'true';
  if (workflowOnly && !isPR) {
    throw new Error('Only workflow/policy-only PRs may skip Go QA');
  }
  function expect(job, result) {
    if (needs[job]?.result !== result) {
      throw new Error(`${job}: expected ${result}, got ${needs[job]?.result}`);
    }
  }
  for (const job of mergeGroupJobs) {
    expect(job, workflowOnly ? 'skipped' : 'success');
  }
  for (const job of nonMergeGroupJobs) {
    expect(job, workflowOnly || eventName === 'merge_group' ? 'skipped' : 'success');
  }
  expect('buflint', isPR && outputs.proto === 'false' ? 'skipped' : 'success');
}

// github-script supplies core; needs is passed as data, never interpolated code.
module.exports = function checkResults({ core }, env = process.env) {
  try {
    validateResults(JSON.parse(env.NEEDS_JSON), env.EVENT_NAME);
  } catch (error) {
    core.setFailed(error.message);
  }
};
module.exports.validateResults = validateResults;
