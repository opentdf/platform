# Consolidated PR report

The local **Submit PR report section** composite action uploads a JSON artifact;
it never writes a comment. Inputs are `section-id`, plain-text `title`, `status`
(`pending`, `passed`, `failed`, `cancelled`, `unavailable`), optional
`summary-file`, and optional `details-file`. Either file or both are supported;
at least one must be nonempty. Files must be UTF-8 and at most 16 KiB each;
titles are at most 256 UTF-8 bytes. Serialized JSON is bounded to 96 KiB,
and the publisher accepts ZIP downloads of at most 128 KiB.
Only the three declared IDs are supported in this first platform-local slice.
No new shared repository, service, queue, or maintaining team is introduced.
Existing CODEOWNERS review routing applies in both repositories.

## Rendering and identity

`.github/comment-template.md` is a narrow declarative layout: the heading and
one `<!-- section:ID -->` slot for each known ID, in display order. No expressions,
scripts, arbitrary Markdown layout, duplicate IDs, or unknown IDs are accepted.
The publisher reads this template from each PR's **trusted base SHA**, never the
PR head. The marker, head SHA, run link, attempt, and artifact identity are
publisher-owned. Producer titles and contents cannot control comment identity.
Producer text is rendered literally (including benchmark Markdown) with HTML,
mentions, and summary Markdown escaped; details are optional collapsed plain
text. Long displayed fields are explicitly truncated, with a run/artifact
reference retained. The final comment is bounded below GitHub's 65,536-character
limit. The earliest bot-owned matching marker comment is reused; it is not
literally pinned. Older independent comments are not deleted retroactively.

## Trust and reconciliation

`pr-report.yaml` runs on Checks requested/in_progress/completed events and manual
dispatch. Its write-token job checks out **only the default branch**, executes
only that trusted publisher, and reads results as bounded JSON ZIP data. It does
not check out PR code, evaluate templates, extract archive members, or run
artifact content. Fork and Dependabot PRs are excluded rather than using the
trusted token to bypass their restrictions. Benchmark/report producer jobs have
no write tokens. The tests reusable workflow preserves its existing permission
ceiling and independent-comment behavior for non-opted-in callers. The platform
caller explicitly adds `actions: read` for attempt/job/artifact enumeration;
its existing reusable-workflow write ceilings are not increased. Only eligible
non-fork, non-Dependabot PR calls opt in; non-PR calls retain their existing path.

One fixed repository-wide concurrency group serializes comment creation and
updates. Actions concurrency is **not a durable queue**: pending runs may be
replaced. Every surviving publisher scans **all open PRs**, selects each PR's
latest Checks run for its current SHA/branch/repository, and reconstructs all
sections from that run's current-attempt artifacts and attempt-specific jobs.
Thus a replaced notification does not drop a section or another PR's update.
Manual dispatch is also a recovery path. No result state is stored in or scraped
from previous comments or logs.

The publisher enforces the fixed section/producer-job allowlist, exact artifact
name, run/attempt/repository/PR/head identity, exact schema, size bounds, and
single `section.json` archive member. Duplicate artifacts, malformed content,
expired/missing results, skipped exports, and prior-attempt submissions cannot
become success. A failed benchmark job cannot submit `passed`. Govulncheck
aggregates **all nine module receipts**; failure may mean a scanner error as
well as a finding. Missing receipts are unavailable, not a clean scan.

A section submission is a **complete replacement**, not a patch. Re-submission
uses artifact overwrite at the same run/attempt/section name. Retries render the
same body and avoid a redundant comment write. The publisher always recomputes
complete state, so sequentialized concurrent section arrivals retain all
available current-attempt sections. Partial reruns do not revive prior-attempt
results; sections not regenerated are unavailable. X-Test exports the existing
`xct` aggregate, not optional benchmark/ZIP64 results, and excludes earlier
attempts' artifact links.

Artifacts and their text remain **untrusted PR-produced assertions**, not
cryptographic attestations or CI authorization. Job-name validation establishes
the expected Actions producer within the selected workflow, not authenticity
against a PR that deliberately rewrites its own workflow. Required CI checks
remain authoritative; this comment is informational only.

## Actual limitations / rollout

- Merge the companion `opentdf/tests` opt-in exporter before enabling the caller.
  Platform pins that companion revision; existing callers default to independent
  comments. Do not remove/suppress tests comments for callers without a publisher.
- The privileged `workflow_run` workflow and template must land on the default
  branch before they can operate. This PR cannot demonstrate live publisher
  behavior merely by changing its own PR head. PRs against older base revisions
  without the template fail closed until their base advances.
- Early pending means at the first surviving Checks event, subject to runner/API
  scheduling; it does not promise to be the first comment or a pinned comment.
  Detail updates reconcile at workflow events, not on every artifact arrival.
- Run selection and PR head are rechecked immediately before writes, but GitHub
  offers no atomic conditional comment write. A head update in the small final
  check/write window can briefly display stale state; the next surviving event
  repairs it. Only this workflow may write the marker comment.
- Auth/API outages or a cancelled publisher can delay reconciliation until the
  next surviving event or manual dispatch. Failures are surfaced in job output;
  there is no custom durable queue or automatic maintenance backend.
- Retention is 14 days. Expired artifacts yield unavailable, never passed.

## Offline verification

```sh
python3 -m unittest discover -s .github/actions/pr-report -p 'test_*.py'
(cd .github/actions/ci-checks && npm ci --ignore-scripts && npm test)
```

Tests cover schema/identity, archive bounds, stale runs/attempts, missing/duplicate
artifacts, escaping/length, whole-section replacement, idempotent stable comment
reuse, serialized arrivals/creation, recovery after pending replacement,
producer failure/cancellation, fork restrictions, and pagination. Workflow tests
check the trusted checkout, permissions, and serialization group. Live Actions
integration and maintainer review are separate rollout gates.
