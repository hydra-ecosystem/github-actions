import copy
import json
import runpy
import urllib.parse
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parents[2]
module = runpy.run_path(str(ROOT / "node/runtime/configuration_issue.py"))
MARKER = module["MARKER"]
BOT = {"login": "github-actions[bot]", "type": "Bot"}


def report(status="error", message="website/.nvmrc: found22; required24"):
    return {
        "schema_version": 1,
        "status": status,
        "message": message,
        "sources": [
            {
                "repository": "owner/defaults",
                "path": "defaults.json",
                "ref": "main",
                "commit": "a" * 40,
            }
        ],
        "required": {"node": "24", "pnpm": "11.21.0", "minimumReleaseAge": 14400},
    }


class GitHub:
    def __init__(self, issues=None):
        self.issues = copy.deepcopy(issues or [])
        self.calls = []
        self.comments = []

    def request(self, method, path, payload=None):
        self.calls.append((method, path, copy.deepcopy(payload)))
        assert path.startswith("repos/owner/site/issues")
        if method == "GET":
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)
            page = int(query["page"][0])
            if "/comments?" in path:
                return copy.deepcopy(self.comments[(page - 1) * 100 : page * 100])
            assert query["state"] == ["all"] and query["creator"] == [BOT["login"]]
            return copy.deepcopy(self.issues[(page - 1) * 100 : page * 100])
        if method == "POST":
            if path.endswith("/comments"):
                comment = {"id": len(self.comments) + 1, "user": BOT, **payload}
                self.comments.append(comment)
                return copy.deepcopy(comment)
            issue = {"number": 77, "user": BOT, "state": "open", **payload}
            self.issues.append(issue)
            return copy.deepcopy(issue)
        assert method == "PATCH"
        number = int(path.rsplit("/", 1)[1])
        issue = next(issue for issue in self.issues if issue["number"] == number)
        issue.update(payload)
        return copy.deepcopy(issue)


def update(
    github, status="error", run=1, message="website/.nvmrc: found22; required24"
):
    return module["update_issue"](
        "owner/site",
        report(status, message),
        f"https://github.com/owner/site/actions/runs/{run}",
        github.request,
    )


def test_one_issue_across_failure_updates_resolution_and_recurrence():
    github = GitHub()
    assert update(github) == {"operation": "created", "number": 77}
    assert update(github) == {"operation": "unchanged", "number": 77}
    assert update(github, run=2, message="pnpm differs") == {
        "operation": "updated",
        "number": 77,
    }
    failure_body = github.issues[0]["body"]
    assert update(github, "ok", 3) == {"operation": "closed", "number": 77}
    assert github.issues[0]["state"] == "closed"
    assert github.issues[0]["body"] == failure_body
    assert len(github.comments) == 1
    assert "Configuration preflight now passes." in github.comments[0]["body"]
    assert "https://github.com/owner/site/actions/runs/3" in github.comments[0]["body"]
    assert update(github, "ok", 4) == {"operation": "unchanged", "number": 77}
    assert update(github, run=5) == {"operation": "reopened", "number": 77}
    assert github.issues[0]["state"] == "open"
    assert len(github.issues) == 1
    assert (
        sum(
            method == "POST" and path == "repos/owner/site/issues"
            for method, path, _ in github.calls
        )
        == 1
    )
    assert (
        sum(
            method == "POST" and path.endswith("/comments")
            for method, path, _ in github.calls
        )
        == 1
    )


def test_healthy_installation_does_not_create_an_issue_and_pending_does_not_close_one():
    github = GitHub()
    assert update(github, "ok")["operation"] == "unchanged"
    assert not github.issues
    update(github)
    before = copy.deepcopy(github.issues)
    assert update(github, "pending")["operation"] == "skipped"
    assert github.issues == before


def test_closed_issue_is_found_through_pagination():
    issues = [
        {"number": i, "user": BOT, "state": "closed", "body": "unrelated"}
        for i in range(1, 102)
    ]
    issues[-1]["body"] = MARKER + "\nold configuration failure"
    github = GitHub(issues)
    assert update(github) == {"operation": "reopened", "number": 101}
    assert not any(method == "POST" for method, _, _ in github.calls)


def test_human_markers_and_pull_requests_do_not_authorize_issue_updates():
    github = GitHub(
        [
            {
                "number": 1,
                "user": {"login": "contributor", "type": "User"},
                "state": "open",
                "body": MARKER + "\nspoof",
            },
            {
                "number": 2,
                "user": BOT,
                "state": "open",
                "body": MARKER + "\nPR",
                "pull_request": {"url": "example"},
            },
        ]
    )
    assert update(github)["operation"] == "created"
    assert github.issues[0]["body"].endswith("spoof")
    assert github.issues[1]["body"].endswith("PR")


def test_ambiguous_existing_issues_never_create_a_third():
    github = GitHub(
        [
            {"number": i, "user": BOT, "state": "open", "body": MARKER + "\nold"}
            for i in (1, 2)
        ]
    )
    with pytest.raises(ValueError, match="Multiple bot-owned"):
        update(github)
    assert all(method == "GET" for method, _, _ in github.calls)


def test_issue_contains_actionable_error_provenance_and_run_link_without_html_injection():
    github = GitHub()
    update(github, message="</pre><script>bad</script>\n::error::injection")
    body = github.issues[0]["body"]
    assert body.startswith(MARKER + "\n")
    assert "<script>" not in body and "&lt;script&gt;" in body
    assert "owner/defaults/defaults.json @ main" in body and "a" * 40 in body
    assert "14400" in body and ".github/node-maintenance.json" in body
    assert "https://github.com/owner/site/actions/runs/1" in body


def test_long_diagnostics_keep_the_issue_bounded_and_preserve_resolved_commits():
    data = report(message="'" * 8000)
    data["sources"] = [
        {
            "repository": "owner/defaults",
            "path": "\U0001f600" * 2048,
            "ref": "'" * 2048,
            "commit": str(i) * 40,
        }
        for i in range(8)
    ]
    github = GitHub()
    result = module["update_issue"]("owner/site", data, "run", github.request)
    body = github.issues[0]["body"]
    assert result["operation"] == "created"
    assert len(json.dumps(data).encode()) > 65536
    assert len(body.encode()) < 65536 and "[truncated]" in body
    assert all(str(i) * 40 in body for i in range(8))
    assert "configuration artifact" in body


@pytest.mark.parametrize(
    "invalid",
    [
        None,
        {},
        {**report(), "status": "build-failed"},
        {**report(), "sources": "repo"},
        {**report(), "message": "x" * 8001},
    ],
)
def test_invalid_reports_cannot_mutate_issues(invalid):
    github = GitHub()
    with pytest.raises(ValueError, match="report"):
        module["update_issue"]("owner/site", invalid, "run", github.request)
    assert not github.calls


def test_cli_rejects_invalid_artifact_before_using_its_token(
    tmp_path, monkeypatch, capsys
):
    path = tmp_path / "report.json"
    path.write_text('{"status":"error"}')
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/site")
    monkeypatch.setenv("GITHUB_RUN_ID", "123")
    monkeypatch.setenv("GH_TOKEN", "must-not-be-printed")
    monkeypatch.setattr("sys.argv", ["report", "--report", str(path)])
    with pytest.raises(SystemExit) as error:
        module["main"]()
    assert error.value.code == 2
    output = capsys.readouterr()
    assert (
        "configuration issue" in output.out
        and "must-not-be-printed" not in output.out + output.err
    )


def test_reporting_job_is_serialized_and_has_no_consumer_checkout_or_app_key():
    workflow = yaml.safe_load((ROOT / ".github/workflows/node-audit.yml").read_text())
    audit = workflow["jobs"]["audit"]
    issue = workflow["jobs"]["configuration-issue"]
    assert audit["permissions"] == {"contents": "read"}
    assert issue["permissions"] == {"issues": "write", "contents": "read"}
    assert issue["needs"] == "audit" and "always()" in issue["if"]
    assert issue["concurrency"] == {
        "group": "node-audit-configuration-issue-${{ github.repository }}",
        "cancel-in-progress": False,
        "queue": "max",
    }
    assert not any("checkout@" in step.get("uses", "") for step in issue["steps"])
    assert "secrets." not in json.dumps(issue)
    steps = yaml.safe_load((ROOT / "node/audit/action.yml").read_text())["runs"][
        "steps"
    ]
    uploads = [
        step
        for step in steps
        if step.get("with", {}).get("name")
        == "${{ inputs.artifact-prefix || 'node-audit' }}-configuration"
    ]
    assert len(uploads) == 1 and "always()" in uploads[0]["if"]
    upload_index = steps.index(uploads[0])
    proposal_index = next(
        i for i, step in enumerate(steps) if step.get("id") == "proposal"
    )
    assert upload_index < proposal_index


def test_configuration_recovery_keeps_failure_open_if_comment_cannot_be_written():
    github = GitHub()
    update(github)
    before = copy.deepcopy(github.issues)

    def request(method, path, payload=None):
        if method == "POST" and path.endswith("/comments"):
            raise ValueError("comment unavailable")
        return github.request(method, path, payload)

    with pytest.raises(ValueError, match="comment unavailable"):
        module["update_issue"](
            "owner/site",
            report("ok"),
            "https://github.com/owner/site/actions/runs/2",
            request,
        )
    assert github.issues == before
    assert not any(method == "PATCH" for method, _, _ in github.calls)


def test_configuration_recovery_reuses_comment_after_close_request_failure():
    github = GitHub()
    update(github)
    failure_body = github.issues[0]["body"]

    def request(method, path, payload=None):
        if method == "PATCH" and payload == {"state": "closed"}:
            raise ValueError("close unavailable")
        return github.request(method, path, payload)

    with pytest.raises(ValueError, match="close unavailable"):
        module["update_issue"](
            "owner/site",
            report("ok"),
            "https://github.com/owner/site/actions/runs/2",
            request,
        )
    assert github.issues[0]["state"] == "open"
    assert github.issues[0]["body"] == failure_body
    assert len(github.comments) == 1
    assert update(github, "ok", 3) == {"operation": "closed", "number": 77}
    assert github.issues[0]["body"] == failure_body
    assert len(github.comments) == 1
