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
Producer summaries and optional collapsed details render Markdown (including
bold, headings, benchmark tables, and links). Raw HTML, marker injection, and
mentions are neutralized before rendering; section titles remain plain text.
GitHub's Markdown renderer applies its own link/HTML sanitization as well.
Long displayed fields are explicitly truncated, with a run/artifact reference
retained. After truncation, unmatched root backtick/tilde fences and fence-like
lines in their tail are escaped so they cannot consume publisher-owned details
wrappers or later sections. This also repairs already-unmatched input fences;
ordinary matched fences still render as code. Fence-like lines indented by up
to three spaces are aligned to the root before matching, avoiding list/quote
container ambiguity at section boundaries (nested fence alignment may change).
Closing-fence character, minimum length, and trailing whitespace follow
CommonMark rules; four-space/tab-indented code is not treated as a root fence.
No arbitrarily long closing delimiter is appended, and the final comment-size
bound still applies. The final comment is bounded below GitHub's 65,536-character
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
results; sections not regenerated are unavailable. X-Test derives the complete
expected `xct` Cartesian product from resolved platform tags and SDK versions,
then requires exactly one completed current-attempt job per expected identity.
Missing, duplicate, unexpected, or unfinished cells are unavailable even if
`needs.xct.result` retained earlier successes. Only all-success current-attempt
conclusions can report passed. Optional benchmark/ZIP64 jobs are not included,
and earlier attempts' artifact links are excluded.

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
(cd .github/actions/ci-checks && npm ci --ignore-scripts && npm test)
```

Tests cover schema/identity, archive bounds, stale runs/attempts, missing/duplicate
artifacts, escaping/length, whole-section replacement, idempotent stable comment
reuse, serialized arrivals/creation, recovery after pending replacement,
producer failure/cancellation, fork restrictions, and pagination. Workflow tests
check the trusted checkout, permissions, and serialization group. The existing
Node CI suite directly exercises the JavaScript publisher and renders its output
with the same `markdown-it` CommonMark tooling used in independent review. This pinned
**test-only** dependency checks real subsequent headings/details boundaries for
truncated/unmatched fences, mismatched closers, and ordinary code/Markdown;
the publisher runs on **Node 24**, the same supported version as the existing CI
helper suite. Reporting code lives in `.github/actions/ci-checks`, sharing its
existing package/lockfile rather than adding another dependency manifest.
The trusted publisher installs only production dependencies with
`npm ci --omit=dev --ignore-scripts`, before the token-bearing publish step:
`yauzl` (3.4.0) provides maintained ZIP metadata/stream parsing and size checks;
`buffer-crc32` (1.0.0) preserves checksum verification; Microsoft's `jsonc-parser`
(3.3.1) detects duplicate decoded JSON property names before `JSON.parse`.
Single-member/local-header checks, actual decompressed byte bounds, strict UTF-8,
and CRC checks apply without extracting files. Native Node fetch manually strips
authorization on cross-origin artifact redirects and bounds streamed downloads.
Submit and govulncheck translation use only Node built-ins, with no npm install
needed in producers. The composite action sets up Node 24; the govulncheck
translator job also sets up Node 24 before aggregation. `markdown-it`, `yaml`,
and `yazl` (test ZIP generation only) remain dev dependencies and are excluded
from privileged runtime installation. Static equivalence fixtures record exact
rendered output from the approved pre-migration head; tests need no other runtime.
Live Actions integration and maintainer review are separate rollout gates.
