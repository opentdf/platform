import copy
import importlib.util
import io
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "report", Path(__file__).with_name("report.py")
)
report = importlib.util.module_from_spec(spec)
spec.loader.exec_module(report)
spec_gov = importlib.util.spec_from_file_location(
    "gov", Path(__file__).with_name("govulncheck.py")
)
gov = importlib.util.module_from_spec(spec_gov)
spec_gov.loader.exec_module(gov)

REPO = "opentdf/platform"
SHA = "a" * 40
PR = {
    "number": 12,
    "state": "open",
    "head": {
        "sha": SHA,
        "ref": "feature",
        "repo": {"id": 1, "full_name": REPO, "fork": False},
    },
    "base": {"sha": "b" * 40},
}
RUN = {
    "id": 7,
    "run_attempt": 2,
    "head_sha": SHA,
    "head_branch": "feature",
    "head_repository": {"full_name": REPO},
    "event": "pull_request",
    "path": ".github/workflows/checks.yaml",
    "pull_requests": [{"number": 12}],
    "status": "completed",
    "conclusion": "success",
    "html_url": "https://github.com/opentdf/platform/actions/runs/7",
}
IDENTITY = {"repository": REPO, "pr": 12, "sha": SHA, "run": 7, "attempt": 2}
TEMPLATE = "# Pull request checks\n" + "\n".join(
    f"<!-- section:{s} -->" for s in report.PRODUCERS
)


def data(section="benchmarks", **changes):
    result = dict(
        version=1,
        section=section,
        title="Title",
        status="passed",
        summary="Done",
        details="",
        **IDENTITY,
    )
    result.update(changes)
    return result


def archive(value, filename="section.json"):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as handle:
        handle.writestr(filename, json.dumps(value))
    return output.getvalue()


class FakeAPI:
    def __init__(self):
        self.pr = copy.deepcopy(PR)
        self.runs = [copy.deepcopy(RUN)]
        self.jobs = [
            {"name": v[1], "conclusion": "success"} for v in report.PRODUCERS.values()
        ]
        self.artifacts = []
        self.payloads = {}
        self.comments = []
        self.writes = []
        self.change_head = False
        self.change_attempt = False

    def pages(self, path, key=None):
        if path.startswith("/pulls?"):
            return [copy.deepcopy(self.pr)]
        if "workflow_runs" == key:
            return copy.deepcopy(self.runs)
        if key == "jobs":
            return self.jobs
        if key == "artifacts":
            return self.artifacts
        if path.endswith("/comments"):
            return self.comments
        raise AssertionError(path)

    def request(self, path, method="GET", body=None, binary=False):
        import base64

        if path.startswith("/contents/"):
            return {"content": base64.b64encode(TEMPLATE.encode()).decode()}
        if path.startswith("/pulls/"):
            if self.change_head:
                self.pr["head"]["sha"] = "c" * 40
            if self.change_attempt:
                self.runs[0]["run_attempt"] += 1
            return copy.deepcopy(self.pr)
        if path.endswith("/zip"):
            return self.payloads[int(path.split("/")[-2])]
        if method in {"POST", "PATCH"}:
            self.writes.append((path, method, body))
            if method == "POST":
                self.comments.append(
                    {
                        "id": 20,
                        "user": {"login": "github-actions[bot]"},
                        "body": body["body"],
                    }
                )
            else:
                self.comments[0]["body"] = body["body"]
            return {}
        raise AssertionError(path)

    def add(self, section, value=None, attempt=2):
        artifact_id = len(self.artifacts) + 1
        self.artifacts.append(
            {
                "id": artifact_id,
                "name": f"pr-report-{section}-7-{attempt}",
                "expired": False,
                "size_in_bytes": 1024,
                "workflow_run": {"id": 7, "head_sha": SHA, "head_repository_id": 1},
            }
        )
        self.payloads[artifact_id] = archive(value or data(section))


class ReportTests(unittest.TestCase):
    def test_schema_identity_bounds_and_optional_inputs(self):
        for value in [
            data(),
            data(summary="", details="Only details"),
            data(details="Both"),
        ]:
            self.assertEqual(report.validate(value, "benchmarks", IDENTITY), value)
        for value in [
            data(summary=""),
            data(extra="unknown"),
            data(section="other"),
            data(attempt=1),
            data(pr=13),
            data(sha="c" * 40),
            data(run=8),
            data(repository="other/repo"),
            data(status="success"),
            data(details="x" * 17000),
        ]:
            with self.assertRaises(ValueError):
                report.validate(value, "benchmarks", IDENTITY)

    def test_template_order_and_duplicate_unknown_ids(self):
        self.assertEqual(report.template_order(TEMPLATE), list(report.PRODUCERS))
        for template in [
            TEMPLATE + "\n<!-- section:benchmarks -->",
            TEMPLATE.replace("xtest", "unknown"),
            TEMPLATE + "script",
        ]:
            with self.assertRaises(ValueError):
                report.template_order(template)

    def test_render_escaping_summary_details_and_limit(self):
        sections = {
            s: data(
                s,
                summary="@someone <script> [click](https://evil)",
                details="</pre></details>" + "&" * 16000,
            )
            for s in report.PRODUCERS
        }
        text = report.render(list(report.PRODUCERS), sections, SHA, RUN)
        self.assertTrue(text.startswith(report.MARKER))
        self.assertNotIn("<script>", text)
        self.assertNotIn("@someone", text)
        self.assertIn("&lt;/pre&gt;", text)
        self.assertIn("truncated", text)
        self.assertLess(len(text), 60000)
        self.assertIn("\\[click\\]", text)

    def test_archive_rejects_paths_extra_members_and_bombs(self):
        self.assertEqual(report.decode_archive(archive(data())), data())
        for raw in [
            b"broken",
            archive(data(), "../section.json"),
            archive(data(details="x" * 100000)),
            b"x" * (report.MAX_ARCHIVE + 1),
        ]:
            with self.assertRaises((ValueError, zipfile.BadZipFile)):
                report.decode_archive(raw)

    def test_latest_run_rejects_stale_sha_repo_branch_pr_and_workflow(self):
        self.assertEqual(report.latest_run([RUN], PR, REPO), RUN)
        for changes in [
            {"head_sha": "old"},
            {"head_branch": "wrong"},
            {"event": "push"},
            {"path": "other.yml"},
            {"pull_requests": [{"number": 13}]},
            {"head_repository": {"full_name": "fork/repo"}},
        ]:
            self.assertIsNone(report.latest_run([dict(RUN, **changes)], PR, REPO))
        self.assertEqual(report.latest_run([RUN, dict(RUN, id=8)], PR, REPO)["id"], 8)

    def test_missing_malformed_duplicate_and_prior_attempt_are_not_success(self):
        for prepare in [
            lambda a: None,
            lambda a: a.add("benchmarks", attempt=1),
            lambda a: a.add("benchmarks", data(attempt=1)),
            lambda a: (a.add("benchmarks"), a.add("benchmarks")),
            lambda a: a.add("benchmarks", data(pr=99)),
        ]:
            api = FakeAPI()
            prepare(api)
            self.assertEqual(
                report.collect(api, REPO, PR, RUN)["benchmarks"]["status"],
                "unavailable",
            )
        api = FakeAPI()
        api.add("benchmarks")
        api.artifacts[0]["expired"] = True
        self.assertEqual(
            report.collect(api, REPO, PR, RUN)["benchmarks"]["status"], "unavailable"
        )

    def test_producer_failure_cancelled_pending_and_provenance(self):
        api = FakeAPI()
        api.add("benchmarks")
        api.jobs[0]["conclusion"] = "failure"
        self.assertEqual(
            report.collect(api, REPO, PR, RUN)["benchmarks"]["status"], "failed"
        )
        api.payloads[1] = archive(data(status="failed"))
        self.assertEqual(
            report.collect(api, REPO, PR, RUN)["benchmarks"]["status"], "failed"
        )
        api.jobs[0]["name"] = "wrong-producer"
        self.assertEqual(
            report.collect(api, REPO, PR, RUN)["benchmarks"]["status"], "unavailable"
        )
        self.assertEqual(
            report.fallback("benchmarks", dict(RUN, conclusion="cancelled"), [])[
                "status"
            ],
            "cancelled",
        )
        self.assertEqual(
            report.fallback("benchmarks", dict(RUN, status="in_progress"), [])[
                "status"
            ],
            "pending",
        )

    def test_idempotent_creation_arrivals_and_full_section_replacement(self):
        api = FakeAPI()
        report.reconcile(api, REPO, PR)
        report.reconcile(api, REPO, PR)
        self.assertEqual([w[1] for w in api.writes], ["POST"])
        api.add("benchmarks", data(details="First details"))
        report.reconcile(api, REPO, PR)
        api.add("govulncheck", data("govulncheck", status="failed"))
        report.reconcile(api, REPO, PR)
        api.payloads[1] = archive(data(summary="Replacement", details=""))
        report.reconcile(api, REPO, PR)
        self.assertEqual(len(api.comments), 1)
        self.assertNotIn("First details", api.comments[0]["body"])
        self.assertIn("— failed", api.comments[0]["body"])
        self.assertIn("— failed", api.comments[0]["body"])

    def test_marker_owner_fork_and_write_time_staleness(self):
        for attr in ["change_head", "change_attempt"]:
            api = FakeAPI()
            setattr(api, attr, True)
            report.reconcile(api, REPO, PR)
            self.assertEqual(api.writes, [])
        api = FakeAPI()
        fork = copy.deepcopy(PR)
        fork["head"]["repo"]["fork"] = True
        report.reconcile(api, REPO, fork)
        self.assertEqual(api.writes, [])
        bot = copy.deepcopy(PR)
        bot["user"] = {"login": "dependabot[bot]"}
        report.reconcile(api, REPO, bot)
        self.assertEqual(api.writes, [])
        api.comments = [
            {"id": 9, "body": report.MARKER + "\nforged", "user": {"login": "human"}}
        ]
        report.reconcile(api, REPO, PR)
        self.assertEqual(api.writes[0][1], "POST")

    def test_archive_redirect_does_not_forward_writer_token(self):
        request = report.urllib.request.Request(
            "https://api.github.com/artifact",
            headers={"Authorization": "Bearer private"},
        )
        redirected = report.ArtifactRedirect().redirect_request(
            request, None, 302, "Found", {}, "https://storage.example/artifact"
        )
        self.assertIsNone(redirected.get_header("Authorization"))

    def test_duplicate_json_keys_and_artifact_api_provenance(self):
        with self.assertRaises(ValueError):
            report.strict_json('{"status":"passed","status":"failed"}')
        api = FakeAPI()
        api.add("benchmarks")
        api.artifacts[0]["workflow_run"]["head_repository_id"] = 99
        self.assertEqual(
            report.collect(api, REPO, PR, RUN)["benchmarks"]["status"], "unavailable"
        )

    def test_submit_file_inputs_and_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "event.json").write_text(json.dumps({"pull_request": PR}))
            (root / "summary.txt").write_text("Summary")
            (root / "details.txt").write_text("Details")
            env = {
                "GITHUB_EVENT_PATH": str(root / "event.json"),
                "GITHUB_REPOSITORY": REPO,
                "GITHUB_SHA": "merge",
                "GITHUB_RUN_ID": "7",
                "GITHUB_RUN_ATTEMPT": "2",
                "REPORT_SECTION": "benchmarks",
                "REPORT_TITLE": "Title",
                "REPORT_STATUS": "passed",
                "REPORT_DIR": str(root / "out"),
            }
            for summary, details in [(True, False), (False, True), (True, True)]:
                with patch.dict(
                    os.environ,
                    dict(
                        env,
                        REPORT_SUMMARY=str(root / "summary.txt") if summary else "",
                        REPORT_DETAILS=str(root / "details.txt") if details else "",
                    ),
                ):
                    report.submit()
                value = json.loads((root / "out" / "section.json").read_text())
                report.validate(value, "benchmarks", IDENTITY)
                self.assertEqual(bool(value["summary"]), summary)
                self.assertEqual(bool(value["details"]), details)

    def test_surviving_publisher_reconciles_multiple_prs_after_pending_replacement(
        self,
    ):
        api = FakeAPI()
        second = copy.deepcopy(PR)
        second["number"] = 13
        second["head"]["sha"] = "d" * 40
        api.pages = lambda path, key=None: [PR, second]
        with (
            patch.dict(os.environ, {"GITHUB_REPOSITORY": REPO, "GH_TOKEN": "fake"}),
            patch.object(report, "GitHub", return_value=api),
            patch.object(report, "reconcile") as reconcile,
        ):
            report.publish()
        self.assertEqual(
            [call.args[2]["number"] for call in reconcile.call_args_list], [12, 13]
        )

    def test_pagination(self):
        api = report.GitHub(REPO, "fake")
        pages = [{"items": list(range(100))}, {"items": [100]}]
        with patch.object(api, "request", side_effect=pages) as request:
            self.assertEqual(len(api.pages("/endpoint?state=open", "items")), 101)
            self.assertIn("&per_page=100&page=2", request.call_args.args[0])

    def test_pending_replacement_recovers_all_open_prs_auth_error_isolated(self):
        api = FakeAPI()
        api.add("benchmarks")
        with (
            patch.dict(os.environ, {"GITHUB_REPOSITORY": REPO, "GH_TOKEN": "fake"}),
            patch.object(report, "GitHub", return_value=api),
        ):
            report.publish()
        self.assertIn("— passed", api.comments[0]["body"])
        # Surviving reconciliation is independent of the triggering event payload.
        api.runs[0]["run_attempt"] = 3
        api.runs[0]["status"] = "in_progress"
        report.reconcile(api, REPO, PR)
        self.assertNotIn("— passed", api.comments[0]["body"])
        self.assertIn("— pending", api.comments[0]["body"])
        with (
            patch.dict(os.environ, {"GITHUB_REPOSITORY": REPO, "GH_TOKEN": "fake"}),
            patch.object(report, "GitHub", return_value=api),
            patch.object(report, "reconcile", side_effect=ValueError("auth-blocked")),
            self.assertRaises(RuntimeError),
        ):
            report.publish()

    def test_govulncheck_missing_receipt_not_success(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(os.environ, {"GITHUB_RUN_ID": "7", "GITHUB_RUN_ATTEMPT": "2"}),
        ):
            self.assertEqual(gov.aggregate(directory)[0], "unavailable")
            for index, module in enumerate(gov.MODULES):
                Path(directory, f"{index}.json").write_text(
                    json.dumps(
                        {"module": module, "outcome": "success", "run": 7, "attempt": 2}
                    )
                )
            self.assertEqual(gov.aggregate(directory)[0], "passed")
            path = Path(directory, "0.json")
            value = json.loads(path.read_text())
            value["outcome"] = "failure"
            path.write_text(json.dumps(value))
            self.assertEqual(gov.aggregate(directory)[0], "failed")
            value["attempt"] = 1
            path.write_text(json.dumps(value))
            with self.assertRaises(ValueError):
                gov.aggregate(directory)


if __name__ == "__main__":
    unittest.main()
