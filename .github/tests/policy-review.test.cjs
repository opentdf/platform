const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const YAML = require('yaml');

const policy = YAML.parse(fs.readFileSync(path.join(__dirname, '../../.policy.yml'), 'utf8'));
const rules = Object.fromEntries(policy.approval_rules.map(rule => [rule.name, rule]));
const approval = policy.policy.approval[0].or;
const defaultPaths = approval[0].and;

function defaultApproved({ branch, maintainers, attested }) {
  return defaultPaths[0].or.some(name => {
    const rule = rules[name];
    const pattern = rule.if?.from_branch?.pattern;
    if (pattern && !new RegExp(pattern).test(branch)) return false;
    const requirements = rule.requires;
    return new Set(maintainers).size >= requirements.count &&
      (!requirements.conditions?.has_status || attested);
  });
}

function policyApproved({ branch, maintainers, attested, activeRules = [], approvals = {}, exception }) {
  if (exception) return rules[exception].requires.count === 0;
  if (!defaultApproved({ branch, maintainers, attested })) return false;
  return defaultPaths.slice(1).every(name =>
    !activeRules.includes(name) || new Set(approvals[name] ?? []).size >= rules[name].requires.count);
}

test('same-repository alternative routes', () => {
  assert.equal(defaultApproved({ branch: 'feature', maintainers: ['maintainer-a'], attested: true }), true);
  assert.equal(defaultApproved({ branch: 'feature', maintainers: ['maintainer-a'], attested: false }), false);
  assert.equal(defaultApproved({ branch: 'feature', maintainers: ['maintainer-a', 'maintainer-b'], attested: false }), true);
  assert.equal(defaultApproved({ branch: 'feature', maintainers: ['maintainer-a', 'maintainer-b'], attested: true }), true);
  assert.equal(defaultApproved({ branch: 'feature', maintainers: [], attested: true }), false);
  assert.equal(defaultApproved({ branch: 'feature', maintainers: ['maintainer-a', 'maintainer-a'], attested: false }), false);
});

test('forks require two distinct maintainers regardless of attestation', () => {
  for (const attested of [false, true]) {
    assert.equal(defaultApproved({ branch: 'contributor:feature', maintainers: ['maintainer-a'], attested }), false);
    assert.equal(defaultApproved({ branch: 'contributor:feature', maintainers: ['maintainer-a', 'maintainer-b'], attested }), true);
  }
});

test('review routes preserve independent maintainer and signature requirements', () => {
  assert.deepEqual(defaultPaths[0].or, ['same_repo_attestation', 'two_maintainers']);
  assert.deepEqual(rules.same_repo_attestation.requires.teams, ['opentdf/maintainers']);
  assert.deepEqual(rules.two_maintainers.requires.teams, ['opentdf/maintainers']);
  for (const name of ['same_repo_attestation', 'two_maintainers']) {
    const rule = rules[name];
    assert.equal(rule.requires.conditions.has_valid_signatures, true);
    assert.equal(rule.options.invalidate_on_push, true);
    assert.equal(rule.options.allow_author ?? false, false);
  }
  assert.deepEqual(rules.same_repo_attestation.requires.conditions.has_status.statuses, ['driver-review']);
  assert.equal(Object.hasOwn(rules.two_maintainers.requires.conditions, 'has_status'), false);
  assert.deepEqual(rules.two_maintainers.options.methods, { comments: [], github_review: true });
});

test('special requirements compose with either default route', () => {
  for (const special of ['github_actions', 'go_mod', 'large_pr', 'repo_policy', 'external_contributors']) {
    const count = rules[special].requires.count;
    const reviewers = Array.from({ length: count }, (_, index) => `special-${index + 1}`);
    assert.equal(policyApproved({ branch: 'feature', maintainers: ['maintainer-a', 'maintainer-b'], attested: false,
      activeRules: [special], approvals: { [special]: reviewers.slice(0, -1) } }), false);
    assert.equal(policyApproved({ branch: 'feature', maintainers: ['maintainer-a', 'maintainer-b'], attested: false,
      activeRules: [special], approvals: { [special]: reviewers } }), true);
    assert.equal(policyApproved({ branch: 'feature', maintainers: ['maintainer-a'], attested: true,
      activeRules: [special], approvals: { [special]: reviewers } }), true);
  }
  assert.equal(policyApproved({ branch: 'contributor:feature', maintainers: ['maintainer-a'], attested: true,
    activeRules: ['external_contributors'], approvals: { external_contributors: ['architect'] } }), false);
  assert.equal(policyApproved({ branch: 'contributor:feature', maintainers: ['maintainer-a', 'maintainer-b'], attested: false,
    activeRules: ['external_contributors'], approvals: { external_contributors: ['architect'] } }), true);
});

test('zero-review bot exceptions remain alternatives', () => {
  for (const exception of ['dependabot_updates', 'autobump']) {
    assert.equal(policyApproved({ branch: 'contributor:feature', maintainers: [], attested: false, exception }), true);
  }
});

test('special paths and exceptions remain additional or alternative', () => {
  assert.deepEqual(defaultPaths.slice(1), ['github_actions', 'lib_ocrypto', 'go_mod', 'repo_policy', 'large_pr', 'external_contributors']);
  assert.deepEqual(approval.slice(1), ['dependabot_updates', 'autobump']);
  assert.deepEqual(policy.policy.disapproval.requires.teams, ['opentdf/maintainers', 'opentdf/architecture']);
  for (const [name, count] of Object.entries({ github_actions: 2, lib_ocrypto: 1, go_mod: 2,
    repo_policy: 1, large_pr: 2, external_contributors: 1, dependabot_updates: 0, autobump: 0 })) {
    assert.equal(rules[name].requires.count, count);
    assert.equal(rules[name].requires.conditions.has_valid_signatures, true);
  }
  for (const name of ['dependabot_updates', 'autobump']) {
    assert.deepEqual(rules[name].requires.conditions.has_status.statuses, ['ci', 'pull-request-checks']);
  }
});
