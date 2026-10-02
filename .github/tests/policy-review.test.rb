require 'minitest/autorun'
require 'yaml'

class PolicyReviewTest < Minitest::Test
  POLICY = YAML.load_file(File.expand_path('../../.policy.yml', __dir__))
  RULES = POLICY.fetch('approval_rules').to_h { |rule| [rule.fetch('name'), rule] }
  DEFAULT_PATHS = POLICY.fetch('policy').fetch('approval').first.fetch('or').first.fetch('and')

  def default_approved?(branch:, maintainers:, attested:)
    routes = DEFAULT_PATHS.first.fetch('or')
    routes.any? do |name|
      rule = RULES.fetch(name)
      from_branch = rule.fetch('if', {}).dig('from_branch', 'pattern')
      next false if from_branch && !Regexp.new(from_branch).match?(branch)

      requirements = rule.fetch('requires')
      status = requirements.dig('conditions', 'has_status')
      maintainers.uniq.length >= requirements.fetch('count') && (!status || attested)
    end
  end

  def policy_approved?(branch:, maintainers:, attested:, active_rules: [], approvals: {}, exception: nil)
    return RULES.fetch(exception).dig('requires', 'count').zero? if exception
    return false unless default_approved?(branch: branch, maintainers: maintainers, attested: attested)

    DEFAULT_PATHS.drop(1).all? do |name|
      !active_rules.include?(name) || approvals.fetch(name, []).uniq.length >= RULES.fetch(name).dig('requires', 'count')
    end
  end

  def test_same_repository_alternative_routes
    assert default_approved?(branch: 'feature', maintainers: ['maintainer-a'], attested: true)
    refute default_approved?(branch: 'feature', maintainers: ['maintainer-a'], attested: false)
    assert default_approved?(branch: 'feature', maintainers: %w[maintainer-a maintainer-b], attested: false)
    assert default_approved?(branch: 'feature', maintainers: %w[maintainer-a maintainer-b], attested: true)
    refute default_approved?(branch: 'feature', maintainers: [], attested: true)
    refute default_approved?(branch: 'feature', maintainers: %w[maintainer-a maintainer-a], attested: false)
  end

  def test_forks_require_two_distinct_maintainers_regardless_of_attestation
    [false, true].each do |attested|
      refute default_approved?(branch: 'contributor:feature', maintainers: ['maintainer-a'], attested: attested)
      assert default_approved?(branch: 'contributor:feature', maintainers: %w[maintainer-a maintainer-b], attested: attested)
    end
  end

  def test_review_routes_preserve_independent_maintainer_and_signature_requirements
    assert_equal %w[same_repo_attestation two_maintainers], DEFAULT_PATHS.first.fetch('or')
    assert_equal %w[opentdf/maintainers], RULES.fetch('same_repo_attestation').fetch('requires').fetch('teams')
    assert_equal %w[opentdf/maintainers], RULES.fetch('two_maintainers').fetch('requires').fetch('teams')
    %w[same_repo_attestation two_maintainers].each do |name|
      rule = RULES.fetch(name)
      assert_equal true, rule.dig('requires', 'conditions', 'has_valid_signatures')
      assert_equal true, rule.dig('options', 'invalidate_on_push')
      assert_equal false, rule.fetch('options', {}).fetch('allow_author', false)
    end
    assert_equal ['driver-review'], RULES.fetch('same_repo_attestation').dig('requires', 'conditions', 'has_status', 'statuses')
    refute RULES.fetch('two_maintainers').dig('requires', 'conditions').key?('has_status')
    assert_equal({ 'comments' => [], 'github_review' => true }, RULES.fetch('two_maintainers').dig('options', 'methods'))
  end

  def test_special_requirements_compose_with_either_default_route
    %w[github_actions go_mod large_pr repo_policy external_contributors].each do |special|
      count = RULES.fetch(special).dig('requires', 'count')
      reviewers = (1..count).map { |n| "special-#{n}" }
      refute policy_approved?(branch: 'feature', maintainers: %w[maintainer-a maintainer-b], attested: false,
        active_rules: [special], approvals: { special => reviewers.take(count - 1) })
      assert policy_approved?(branch: 'feature', maintainers: %w[maintainer-a maintainer-b], attested: false,
        active_rules: [special], approvals: { special => reviewers })
      assert policy_approved?(branch: 'feature', maintainers: ['maintainer-a'], attested: true,
        active_rules: [special], approvals: { special => reviewers })
    end
    refute policy_approved?(branch: 'contributor:feature', maintainers: ['maintainer-a'], attested: true,
      active_rules: ['external_contributors'], approvals: { 'external_contributors' => ['architect'] })
    assert policy_approved?(branch: 'contributor:feature', maintainers: %w[maintainer-a maintainer-b], attested: false,
      active_rules: ['external_contributors'], approvals: { 'external_contributors' => ['architect'] })
  end

  def test_zero_review_bot_exceptions_remain_alternatives
    %w[dependabot_updates autobump].each do |exception|
      assert policy_approved?(branch: 'contributor:feature', maintainers: [], attested: false, exception: exception)
    end
  end

  def test_special_paths_and_exceptions_remain_additional_or_alternative
    assert_equal %w[github_actions lib_ocrypto go_mod repo_policy large_pr external_contributors], DEFAULT_PATHS.drop(1)
    assert_equal %w[dependabot_updates autobump], POLICY.fetch('policy').fetch('approval').first.fetch('or').drop(1)
    assert_equal %w[opentdf/maintainers opentdf/architecture], POLICY.fetch('policy').fetch('disapproval').fetch('requires').fetch('teams')
    { 'github_actions' => 2, 'lib_ocrypto' => 1, 'go_mod' => 2,
      'repo_policy' => 1, 'large_pr' => 2, 'external_contributors' => 1,
      'dependabot_updates' => 0, 'autobump' => 0 }.each do |name, count|
      assert_equal count, RULES.fetch(name).fetch('requires').fetch('count')
      assert_equal true, RULES.fetch(name).dig('requires', 'conditions', 'has_valid_signatures')
    end
    %w[dependabot_updates autobump].each do |name|
      assert_equal %w[ci pull-request-checks], RULES.fetch(name).dig('requires', 'conditions', 'has_status', 'statuses')
    end
  end
end
