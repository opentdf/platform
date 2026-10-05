"""Data-only submissions and trusted, full-state PR comment reconciliation.

No archive member is extracted or executed. The publisher has a fixed producer
allowlist, independent of the submitted title/content and PR workflow edits.
"""

import html
import io
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import zlib
from pathlib import Path

MARKER = "<!-- opentdf-pr-report:v1 -->"
STATES = {"pending", "passed", "failed", "cancelled", "unavailable"}
PRODUCERS = {
    "benchmarks": ("Benchmarks", "benchmark tests"),
    "govulncheck": ("Govulncheck", "report-govulncheck"),
    "xtest": ("X-Test", "platform-xtest / export-pr-report"),
}
MAX_ARCHIVE = 131072
MAX_SECTION = 98304
FIELDS = {
    "version",
    "section",
    "title",
    "status",
    "summary",
    "details",
    "repository",
    "pr",
    "sha",
    "run",
    "attempt",
}


def validate(data, section, identity):
    if not isinstance(data, dict) or set(data) != FIELDS:
        raise ValueError("Invalid section schema")
    if type(data["version"]) is not int or data["version"] != 1:
        raise ValueError("Unsupported section version")
    if data["section"] != section or section not in PRODUCERS:
        raise ValueError("Unknown section")
    if data["status"] not in STATES:
        raise ValueError("Invalid status")
    for key in ("title", "summary", "details"):
        if not isinstance(data[key], str) or len(data[key].encode()) > 16384:
            raise ValueError("Invalid or oversized text")
    if len(data["title"].encode()) > 256:
        raise ValueError("Oversized title")
    if not data["title"] or not (data["summary"] or data["details"]):
        raise ValueError("Empty section")
    for key, value in identity.items():
        if type(data[key]) is not type(value) or data[key] != value:
            raise ValueError("Section identity mismatch: " + key)
    return data


def submit():
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    pr = event.get("pull_request", {})
    section = os.environ["REPORT_SECTION"]
    identity = {
        "repository": os.environ["GITHUB_REPOSITORY"],
        "pr": pr.get("number", 0),
        "sha": pr.get("head", {}).get("sha", os.environ["GITHUB_SHA"]),
        "run": int(os.environ["GITHUB_RUN_ID"]),
        "attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
    }

    def read_file(name):
        path = os.environ.get(name)
        if not path:
            return ""
        if Path(path).stat().st_size > 16384:
            raise ValueError("Oversized input")
        return Path(path).read_text(encoding="utf-8")

    data = dict(
        version=1,
        section=section,
        title=os.environ["REPORT_TITLE"],
        status=os.environ["REPORT_STATUS"],
        summary=read_file("REPORT_SUMMARY"),
        details=read_file("REPORT_DETAILS"),
        **identity,
    )
    validate(data, section, identity)
    directory = Path(os.environ["REPORT_DIR"])
    directory.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(data, ensure_ascii=False)
    if len(serialized.encode()) > MAX_SECTION:
        raise ValueError("Oversized serialized section")
    (directory / "section.json").write_text(serialized, encoding="utf-8")


def strict_json(raw):
    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON field")
            result[key] = value
        return result

    return json.loads(raw, object_pairs_hook=object_pairs)


def decode_archive(raw):
    if len(raw) > MAX_ARCHIVE:
        raise ValueError("Oversized archive")
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        members = archive.infolist()
        if len(members) != 1 or members[0].filename != "section.json":
            raise ValueError("Unexpected archive members")
        if members[0].file_size > MAX_SECTION or members[0].flag_bits & 1:
            raise ValueError("Oversized/encrypted section")
        return strict_json(archive.read(members[0]).decode("utf-8"))


def template_order(template):
    slots = re.findall(r"<!-- section:([a-z0-9-]+) -->", template)
    if len(slots) != len(set(slots)) or set(slots) != set(PRODUCERS):
        raise ValueError("Template must declare each known section exactly once")
    if (
        re.sub(r"<!-- section:[a-z0-9-]+ -->", "", template).strip()
        != "# Pull request checks"
    ):
        raise ValueError("Template supports only heading and section slots")
    return slots


def safe_text(text, limit, markdown=False):
    # Neutralize mentions, HTML, and Markdown formatting in producer-controlled text.
    text = html.escape(text, quote=False).replace("@", "@\u200b")
    if markdown:
        text = re.sub(r"([\\`*_{}\[\]()#+.!|>-])", r"\\\1", text)
    return text[:limit] + (
        "\n… (truncated; see workflow artifacts)" if len(text) > limit else ""
    )


def render(order, sections, sha, run):
    body = [MARKER, "# Pull request checks", f"Head: `{sha}`"]
    if run:
        body.append(f"[Workflow run]({run['html_url']}) · attempt {run['run_attempt']}")
    for section in order:
        data = sections[section]
        body.append(f"## {safe_text(data['title'], 160, True)} — {data['status']}")
        if data.get("summary"):
            body.append(safe_text(data["summary"], 1500, True))
        if data.get("details"):
            body.append(
                "<details><summary>Details</summary>\n\n<pre>"
                + safe_text(data["details"], 9000)
                + "</pre>\n</details>"
            )
    result = "\n\n".join(body)
    if len(result) > 60000:
        raise ValueError("Comment exceeds safe GitHub length")
    return result


class ArtifactRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, hdrs, newurl):
        redirected = super().redirect_request(req, fp, code, msg, hdrs, newurl)
        if urllib.parse.urlparse(newurl).hostname != "api.github.com":
            redirected.remove_header("Authorization")
        return redirected


class GitHub:
    def __init__(self, repository, token):
        self.root = "https://api.github.com/repos/" + repository
        self.token = token

    def request(self, path, method="GET", body=None, binary=False):
        url = self.root + path
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + self.token,
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
            "User-Agent": "opentdf-pr-report",
        }
        payload = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(
            url, data=payload, headers=headers, method=method
        )

        # urllib strips Authorization on cross-host redirects only with a custom handler.
        # Artifact redirects must never forward the central writer token to storage.
        with urllib.request.build_opener(ArtifactRedirect()).open(
            request, timeout=30
        ) as response:
            raw = response.read(MAX_ARCHIVE + 1) if binary else response.read()
            return raw if binary else json.loads(raw)

    def pages(self, path, key=None):
        values = []
        for page in range(1, 1001):
            data = self.request(
                path + ("&" if "?" in path else "?") + f"per_page=100&page={page}"
            )
            rows = data[key] if key else data
            values.extend(rows)
            if len(rows) < 100:
                return values
        raise ValueError("Pagination limit exceeded")


def latest_run(runs, pr, repository):
    matches = [
        r
        for r in runs
        if r["event"] == "pull_request"
        and r["path"] == ".github/workflows/checks.yaml"
        and r["head_sha"] == pr["head"]["sha"]
        and r["head_branch"] == pr["head"]["ref"]
        and (r.get("head_repository") or {}).get("full_name") == repository
        and all(p["number"] == pr["number"] for p in r.get("pull_requests", []))
    ]
    return max(matches, key=lambda r: (r["id"], r["run_attempt"]), default=None)


def fallback(section, run, jobs):
    title, producer = PRODUCERS[section]
    matching = [job for job in jobs if job["name"] == producer]
    if not run or run["status"] != "completed":
        status, summary = "pending", "Waiting for structured results."
    elif run.get("conclusion") == "cancelled":
        status, summary = "cancelled", "Workflow cancelled; results may be incomplete."
    elif matching and any(
        j.get("conclusion") in {"failure", "timed_out"} for j in matching
    ):
        status, summary = "failed", "Producer failed without a valid structured result."
    else:
        status, summary = (
            "unavailable",
            "No valid result for this attempt (missing, skipped, expired, or malformed).",
        )
    return {"title": title, "status": status, "summary": summary, "details": ""}


def collect(api, repository, pr, run):
    if not run:
        return {s: fallback(s, None, []) for s in PRODUCERS}
    jobs = api.pages(
        f"/actions/runs/{run['id']}/attempts/{run['run_attempt']}/jobs", "jobs"
    )
    artifacts = api.pages(f"/actions/runs/{run['id']}/artifacts", "artifacts")
    sections = {s: fallback(s, run, jobs) for s in PRODUCERS}
    identity = {
        "repository": repository,
        "pr": pr["number"],
        "sha": pr["head"]["sha"],
        "run": run["id"],
        "attempt": run["run_attempt"],
    }
    for section, (_, producer) in PRODUCERS.items():
        name = f"pr-report-{section}-{run['id']}-{run['run_attempt']}"
        candidates = [a for a in artifacts if a["name"] == name and not a["expired"]]
        producers = [j for j in jobs if j["name"] == producer]
        # Accept only the expected producer's completed export.
        # Do not treat an uploaded 'passed' payload as proof of a failed benchmark job.
        if (
            len(candidates) != 1
            or len(producers) != 1
            or producers[0].get("conclusion")
            not in {"success", "failure", "cancelled", "timed_out"}
        ):
            continue
        artifact = candidates[0]
        provenance = artifact.get("workflow_run", {})
        if (
            artifact["size_in_bytes"] > MAX_ARCHIVE
            or provenance.get("id") != run["id"]
            or provenance.get("head_sha") != pr["head"]["sha"]
            or provenance.get("head_repository_id") != pr["head"]["repo"]["id"]
        ):
            continue
        try:
            data = validate(
                decode_archive(
                    api.request(f"/actions/artifacts/{artifact['id']}/zip", binary=True)
                ),
                section,
                identity,
            )
            if producers[0]["conclusion"] != "success" and data["status"] == "passed":
                raise ValueError("Failed producer cannot report passed")
            sections[section] = data
        except (
            ValueError,
            KeyError,
            TypeError,
            zipfile.BadZipFile,
            zlib.error,
            NotImplementedError,
            RuntimeError,
            EOFError,
            UnicodeError,
        ) as error:
            print(f"Rejected {section}: {error}")
    return sections


def reconcile(api, repository, pr):
    # Do not use workflow_run privileges to bypass fork/Dependabot token restrictions.
    if (
        pr.get("user", {}).get("login") == "dependabot[bot]"
        or not pr["head"].get("repo")
        or pr["head"]["repo"]["fork"]
        or pr["head"]["repo"]["full_name"] != repository
    ):
        return
    sha = pr["head"]["sha"]
    runs_path = "/actions/workflows/checks.yaml/runs?event=pull_request&head_sha=" + sha
    run = latest_run(api.pages(runs_path, "workflow_runs"), pr, repository)
    template_data = api.request(
        "/contents/.github/comment-template.md?ref=" + pr["base"]["sha"]
    )
    import base64

    order = template_order(base64.b64decode(template_data["content"]).decode())
    body = render(order, collect(api, repository, pr, run), sha, run)
    comments = api.pages(f"/issues/{pr['number']}/comments")
    owned = [
        c
        for c in comments
        if c.get("user", {}).get("login") == "github-actions[bot]"
        and c.get("body", "").startswith(MARKER + "\n")
    ]
    # A fixed repository-wide workflow concurrency group serializes all writes.
    # Surviving runs scan ALL open PRs, not only their triggering event.
    current = api.request(f"/pulls/{pr['number']}")
    latest = latest_run(api.pages(runs_path, "workflow_runs"), current, repository)
    if current["state"] != "open" or current["head"]["sha"] != sha or latest != run:
        print(f"Skipped stale reconciliation for PR {pr['number']}")
        return
    # GitHub comments have no compare-and-swap API. Minimize the unavoidable
    # check/write race; the next surviving reconciliation repairs any overlap.
    final = api.request(f"/pulls/{pr['number']}")
    if final["state"] != "open" or final["head"]["sha"] != sha:
        return
    if owned:
        first = min(owned, key=lambda c: c["id"])
        if first["body"] != body:
            api.request(f"/issues/comments/{first['id']}", "PATCH", {"body": body})
    else:
        api.request(f"/issues/{pr['number']}/comments", "POST", {"body": body})


def publish():
    repository = os.environ["GITHUB_REPOSITORY"]
    api = GitHub(repository, os.environ["GH_TOKEN"])
    errors = []
    for pr in api.pages("/pulls?state=open"):
        try:
            reconcile(api, repository, pr)
        except (urllib.error.URLError, TimeoutError, ValueError) as error:
            # One auth-blocked or invalid-template PR must not lose other PR updates.
            print(f"PR {pr['number']}: {error}")
            errors.append(pr["number"])
    if errors:
        raise RuntimeError(f"Unreconciled PRs: {errors}")


if __name__ == "__main__":
    {"submit": submit, "publish": publish}[sys.argv[1]]()
