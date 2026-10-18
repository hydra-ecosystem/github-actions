"""Fleet setup checks inspect immutable data and never run project commands."""

import base64
import copy
import hashlib
import json
import runpy
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parents[2]
FLEET = runpy.run_path(str(ROOT / "node/runtime/fleet.py"))
REPORTER = runpy.run_path(str(ROOT / "node/runtime/fleet_issue.py"))
SHA = "a" * 40
SOURCE = {"repository": "owner/settings", "path": "defaults/policy.json", "ref": "main"}
DEFAULTS = json.loads((ROOT / "defaults/node-maintenance.json").read_text())


def data(value):
    return value.encode() if isinstance(value, str) else json.dumps(value).encode()


class GitHub(FLEET["GitHub"]):
    def __init__(self, manager="pnpm"):
        super().__init__()
        self.repos = {}
        self.calls = []
        self.states = {}
        self.read_defaults = self.public
        self.add(
            "owner/settings",
            {
                "defaults/policy.json": data(DEFAULTS),
                "defaults/repos.json": data(
                    {"defaults": SOURCE, "repositories": ["owner/project"]}
                ),
            },
        )
        self.add(
            "owner/actions",
            {
                "node/contract.json": (ROOT / "node/contract.json").read_bytes(),
                "node/runtime/toolchain.json": (
                    ROOT / "node/runtime/toolchain.json"
                ).read_bytes(),
                ".github/workflows/node-audit.yml": (
                    ROOT / ".github/workflows/node-audit.yml"
                ).read_bytes(),
                ".github/workflows/node-publish.yml": (
                    ROOT / ".github/workflows/node-publish.yml"
                ).read_bytes(),
            },
        )
        self.add("owner/project", project(manager))

    def add(self, name, files):
        self.repos[name] = copy.deepcopy(files)
        self.states[name] = "active"
        self.snapshots.clear()

    def public(self, url, accept="application/json"):
        if url.startswith("https://api.github.com/"):
            return SHA.encode()
        prefix = "https://raw.githubusercontent.com/"
        owner, repo, revision, path = url[len(prefix) :].split("/", 3)
        assert revision == SHA
        return self.repos[f"{owner}/{repo}"][path]

    def get(self, path):
        self.calls.append(path)
        parts = path.split("/")
        name = "/".join(parts[1:3])
        if name not in self.repos:
            raise FLEET["Unverified"](
                "GitHub read failed (HTTP 404); access unverified"
            )
        files = self.repos[name]
        if len(parts) == 3:
            return {"default_branch": "main"}
        if parts[3] == "commits":
            return {"sha": SHA, "commit": {"tree": {"sha": "b" * 40}}}
        if parts[3:5] == ["git", "trees"]:
            return {
                "truncated": False,
                "tree": [
                    {
                        "path": path,
                        "mode": "100644",
                        "type": "blob",
                        "size": len(body),
                        "sha": hashlib.sha1(
                            f"blob {len(body)}\0".encode() + body
                        ).hexdigest(),
                    }
                    for path, body in files.items()
                ],
            }
        if parts[3:5] == ["git", "blobs"]:
            for body in files.values():
                if (
                    hashlib.sha1(f"blob {len(body)}\0".encode() + body).hexdigest()
                    == parts[5]
                ):
                    return {
                        "encoding": "base64",
                        "content": base64.b64encode(body).decode(),
                    }
            raise AssertionError("unknown blob")
        if parts[3:5] == ["actions", "workflows"]:
            return {"state": self.states[name]}
        raise AssertionError(path)


def project(manager):
    manifest = {
        "name": "plain-project",
        "version": "1.0.0",
        "packageManager": "pnpm@11.21.0" if manager == "pnpm" else "npm@11.9.0",
        "engines": {"node": ">=24"},
        "scripts": {"check": "this command must never execute"},
    }
    caller = yaml.safe_load(
        (ROOT / "node/caller.yml")
        .read_text()
        .replace("__CENTRAL_REPOSITORY__", "owner/actions")
        .replace("__CENTRAL_REVISION__", SHA)
    )
    caller["on"]["schedule"] = [{"cron": cron} for cron in ["0 2 * * 1", "0 2 1 */3 *"]]
    files = {
        ".github/node-maintenance.json": data(
            {"directory": "app", "validationScript": "check", "defaults": SOURCE}
        ),
        ".github/workflows/dependency-audit.yml": yaml.safe_dump(caller).encode(),
        "app/package.json": data(manifest),
        "app/.nvmrc": b"24",
    }
    if manager == "pnpm":
        files["app/pnpm-lock.yaml"] = (
            b"lockfileVersion: '9.0'\nimporters: {'.': {}}\npackages: {}\n"
        )
        files["app/pnpm-workspace.yaml"] = (
            b"packages: ['.']\nminimumReleaseAge: 14400\n"
        )
    else:
        files["app/package-lock.json"] = data(
            {"lockfileVersion": 3, "packages": {"": manifest}}
        )
    return files


@pytest.mark.parametrize("manager", ["npm", "pnpm"])
def test_healthy_fleet_without_running_project_commands(monkeypatch, manager):
    def forbidden(*args, **kwargs):
        pytest.fail("A setup check must never run a project command")

    monkeypatch.setattr(subprocess, "run", forbidden)
    github = GitHub(manager)
    report = FLEET["check_fleet"](
        github,
        {"repository": "owner/settings", "path": "defaults/repos.json", "ref": ""},
    )
    assert report["status"] == "ok"
    assert report["inventory"]["commit"] == SHA
    assert report["results"][0]["status"] == "ok"
    assert all(call.startswith("repos/") for call in github.calls)


@pytest.mark.parametrize(
    "case",
    [
        "node",
        "cooldown",
        "lock",
        "script",
        "source",
        "schedule",
        "pin",
        "permissions",
        "dispatch",
        "forwarding",
        "disabled",
        "ancestor-workspace",
        "shrinkwrap",
        "engines",
    ],
)
def test_setup_drift_is_reported(case):
    github = GitHub()
    files = github.repos["owner/project"]
    if case == "node":
        files["app/.nvmrc"] = b"22"
    elif case == "cooldown":
        files["app/pnpm-workspace.yaml"] = b"packages: ['.']\nminimumReleaseAge: 1\n"
    elif case == "lock":
        files["app/pnpm-lock.yaml"] = b"lockfileVersion: '8.0'\n"
    elif case == "script":
        manifest = json.loads(files["app/package.json"])
        manifest["scripts"] = {}
        files["app/package.json"] = data(manifest)
    elif case == "source":
        config = json.loads(files[".github/node-maintenance.json"])
        config.pop("defaults")
        files[".github/node-maintenance.json"] = data(config)
    elif case == "disabled":
        github.states["owner/project"] = "disabled_manually"
    elif case == "ancestor-workspace":
        files["package.json"] = data({"workspaces": ["app"]})
    elif case == "shrinkwrap":
        files["app/npm-shrinkwrap.json"] = b"{}"
    elif case == "engines":
        manifest = json.loads(files["app/package.json"])
        manifest["engines"]["node"] = "<24"
        files["app/package.json"] = data(manifest)
    else:
        caller = yaml.safe_load(files[".github/workflows/dependency-audit.yml"])
        if case == "schedule":
            caller["on"]["schedule"] = []
        elif case == "pin":
            caller["jobs"]["audit"]["uses"] = caller["jobs"]["audit"]["uses"].replace(
                SHA, "main"
            )
        elif case == "permissions":
            caller["jobs"]["audit"]["permissions"]["contents"] = "write"
        elif case == "dispatch":
            caller["on"]["workflow_dispatch"]["inputs"]["audit-kind"]["options"] = [
                "security"
            ]
        elif case == "forwarding":
            caller["jobs"]["audit"]["with"] = {}
        files[".github/workflows/dependency-audit.yml"] = yaml.safe_dump(
            caller
        ).encode()
    result = FLEET["check_repository"](github, "owner/project", SOURCE)
    assert result["status"] == "failed", result
    assert result["diagnostic"]


def test_explicit_local_overrides_remain_valid():
    github = GitHub()
    files = github.repos["owner/project"]
    config = json.loads(files[".github/node-maintenance.json"])
    config["toolchain"] = {"node": "22"}
    files[".github/node-maintenance.json"] = data(config)
    files["app/.nvmrc"] = b"22.14.0"
    manifest = json.loads(files["app/package.json"])
    manifest["engines"]["node"] = ">=22.13"
    files["app/package.json"] = data(manifest)
    assert FLEET["check_repository"](github, "owner/project", SOURCE)["status"] == "ok"


def test_inaccessible_repo_does_not_hide_other_results():
    github = GitHub()
    github.repos["owner/settings"]["defaults/repos.json"] = data(
        {"defaults": SOURCE, "repositories": ["owner/missing", "owner/project"]}
    )
    report = FLEET["check_fleet"](
        github,
        {"repository": "owner/settings", "path": "defaults/repos.json", "ref": "main"},
    )
    assert report["status"] == "failed"
    assert [item["status"] for item in report["results"]] == ["unverified", "ok"]


def test_missing_inventory_is_a_reportable_failure():
    report = FLEET["check_fleet"](
        GitHub(),
        {"repository": "owner/settings", "path": "missing.json", "ref": "main"},
    )
    assert report["status"] == "failed" and report["inventory"]["commit"] == SHA


@pytest.mark.parametrize(
    "repos", [[], ["owner/repo", "OWNER/REPO"], ["../repo"], ["owner/repo"] * 26]
)
def test_inventory_rejects_ambiguous_or_unbounded_lists(repos):
    with pytest.raises(ValueError):
        FLEET["inventory"]({"defaults": SOURCE, "repositories": repos})


def test_symlink_and_changed_blob_are_rejected():
    github = GitHub()
    repo = github.snapshot("owner/project")
    repo.files["app/.nvmrc"]["mode"] = "120000"
    with pytest.raises(ValueError, match="regular file"):
        repo.read("app/.nvmrc")
    github = GitHub()
    repo = github.snapshot("owner/project")
    repo.files["app/.nvmrc"]["size"] += 1
    with pytest.raises(FLEET["Unverified"], match="size differs"):
        repo.read("app/.nvmrc")


class Issues:
    def __init__(self):
        self.items = []

    def request(self, method, path, payload=None):
        if method == "GET":
            return copy.deepcopy(self.items)
        if method == "POST":
            result = {
                **payload,
                "number": len(self.items) + 1,
                "state": "open",
                "user": {"login": "github-actions[bot]", "type": "Bot"},
            }
            self.items.append(result)
            return result
        number = int(path.rsplit("/", 1)[1])
        self.items[number - 1].update(payload)
        return self.items[number - 1]


def test_one_issue_per_inventory_updates_closes_and_reopens():
    github = GitHub()
    issues = Issues()
    report = FLEET["check_fleet"](
        github,
        {"repository": "owner/settings", "path": "defaults/repos.json", "ref": "main"},
    )
    report["status"] = "failed"
    report["results"][0].update(
        status="failed", diagnostic="Node mismatch <script>@someone</script>"
    )

    def update():
        return REPORTER["update_issue"](
            "owner/host",
            report,
            "https://github.com/owner/host/actions/runs/1",
            issues.request,
        )

    assert update()["operation"] == "created"
    assert update()["operation"] == "unchanged"
    assert "<script>" not in issues.items[0]["body"]
    report["status"] = "ok"
    report["results"][0].update(status="ok", diagnostic="Static setup checks passed")
    assert update()["operation"] == "closed"
    report["status"] = "unverified"
    report["diagnostic"] = "Access unavailable"
    assert update()["operation"] == "reopened"
    assert len(issues.items) == 1
    report["inventory"]["path"] = "defaults/other.json"
    assert update()["operation"] == "created" and len(issues.items) == 2


def test_workflow_splits_read_access_and_host_issue_write_access():
    workflow = yaml.safe_load(
        (ROOT / ".github/workflows/node-fleet-check.yml").read_text()
    )
    assert {"workflow_call", "workflow_dispatch"} == set(workflow["on"])
    assert workflow["jobs"]["check"]["permissions"] == {
        "contents": "read",
        "actions": "read",
    }
    assert workflow["jobs"]["report"]["permissions"] == {
        "actions": "read",
        "issues": "write",
    }
    assert workflow["jobs"]["report"]["if"] == "${{ always() && !cancelled() }}"
    assert workflow["concurrency"]["cancel-in-progress"] is False
    assert "read-token" not in json.dumps(workflow["jobs"]["report"])
    import re

    guide = (ROOT / "docs/node-fleet-setup.md").read_text()
    caller = next(
        yaml.safe_load(block)
        for block in re.findall(r"```yaml\n(.*?)\n```", guide, re.S)
        if "jobs:" in block
    )
    job = caller["jobs"]["setup"]
    assert job["uses"].endswith("/node-fleet-check.yml@REVIEWED_FULL_COMMIT_SHA")
    assert set(job["with"]) <= set(workflow["on"]["workflow_call"]["inputs"])
    assert job["permissions"] == {
        "contents": "read",
        "actions": "read",
        "issues": "write",
    }


@pytest.mark.parametrize(
    "expression,ok",
    [(">=24.14.0 <25", True), (">24.14 <24.15", False), (">24.14 <24.16", True)],
)
def test_major_engine_ranges_use_stable_boundaries(expression, ok):
    github = GitHub()
    manifest = json.loads(github.repos["owner/project"]["app/package.json"])
    manifest["engines"]["node"] = expression
    github.repos["owner/project"]["app/package.json"] = data(manifest)
    assert (
        FLEET["check_repository"](github, "owner/project", SOURCE)["status"] == "ok"
    ) is ok


def test_incomplete_tree_is_unverified_and_no_blob_is_read():
    github = GitHub()
    original = github.get

    def get(path):
        if "/git/trees/" in path:
            return {"truncated": True, "tree": []}
        return original(path)

    github.get = get
    result = FLEET["check_repository"](github, "owner/project", SOURCE)
    assert result["status"] == "unverified"
    assert not any("/git/blobs/" in call for call in github.calls)


def test_invalid_pinned_reusable_workflow_is_setup_failure():
    github = GitHub()
    github.repos["owner/actions"][".github/workflows/node-audit.yml"] = (
        b"on: push\njobs: {}\n"
    )
    assert (
        FLEET["check_repository"](github, "owner/project", SOURCE)["status"] == "failed"
    )


@pytest.mark.parametrize("job", ["audit", "pull-request"])
@pytest.mark.parametrize("condition", [False, "${{ false }}"])
def test_caller_jobs_must_be_unconditionally_enabled(job, condition):
    github = GitHub()
    caller = yaml.safe_load(
        github.repos["owner/project"][".github/workflows/dependency-audit.yml"]
    )
    caller["jobs"][job]["if"] = condition
    github.repos["owner/project"][".github/workflows/dependency-audit.yml"] = data(
        caller
    )
    result = FLEET["check_repository"](github, "owner/project", SOURCE)
    assert result["status"] == "failed"
    assert "unconditionally" in result["diagnostic"]


def test_empty_pinned_callable_jobs_are_rejected():
    github = GitHub()
    github.repos["owner/actions"][".github/workflows/node-audit.yml"] = (
        b"on:\n  workflow_call:\njobs: {}\n"
    )
    result = FLEET["check_repository"](github, "owner/project", SOURCE)
    assert result["status"] == "failed"


def test_required_pinned_inputs_and_secret_mappings_are_checked():
    github = GitHub()
    audit = yaml.safe_load(
        github.repos["owner/actions"][".github/workflows/node-audit.yml"]
    )
    audit["on"]["workflow_call"]["inputs"]["required-value"] = {
        "required": True,
        "type": "string",
    }
    github.repos["owner/actions"][".github/workflows/node-audit.yml"] = data(audit)
    result = FLEET["check_repository"](github, "owner/project", SOURCE)
    assert result["status"] == "failed"
    assert "required input" in result["diagnostic"]

    github = GitHub()
    publisher = yaml.safe_load(
        github.repos["owner/actions"][".github/workflows/node-publish.yml"]
    )
    publisher["on"]["workflow_call"]["secrets"]["app-private-key"]["required"] = True
    github.repos["owner/actions"][".github/workflows/node-publish.yml"] = data(
        publisher
    )
    caller = yaml.safe_load(
        github.repos["owner/project"][".github/workflows/dependency-audit.yml"]
    )
    caller["jobs"]["pull-request"].pop("secrets")
    github.repos["owner/project"][".github/workflows/dependency-audit.yml"] = data(
        caller
    )
    result = FLEET["check_repository"](github, "owner/project", SOURCE)
    assert result["status"] == "failed"
    assert "required secret mapping" in result["diagnostic"]


def test_invalid_cron_bounds_fail_even_when_policy_and_caller_match():
    github = GitHub()
    files = github.repos["owner/project"]
    config = json.loads(files[".github/node-maintenance.json"])
    config["schedule"] = ["99 99 * * *"]
    files[".github/node-maintenance.json"] = data(config)
    caller = yaml.safe_load(files[".github/workflows/dependency-audit.yml"])
    caller["on"]["schedule"] = [{"cron": "99 99 * * *"}]
    files[".github/workflows/dependency-audit.yml"] = data(caller)
    result = FLEET["check_repository"](github, "owner/project", SOURCE)
    assert result["status"] == "failed"
    assert "outside" in result["diagnostic"]


def test_supported_cron_forms_keep_their_exact_spelling():
    github = GitHub()
    files = github.repos["owner/project"]
    expressions = ["*/15 0-23 1,15 JAN-MAR MON-FRI/2"]
    config = json.loads(files[".github/node-maintenance.json"])
    config["schedule"] = expressions
    files[".github/node-maintenance.json"] = data(config)
    caller = yaml.safe_load(files[".github/workflows/dependency-audit.yml"])
    caller["on"]["schedule"] = [{"cron": expressions[0]}]
    files[".github/workflows/dependency-audit.yml"] = data(caller)
    assert FLEET["check_repository"](github, "owner/project", SOURCE)["status"] == "ok"


@pytest.mark.parametrize(
    "cron",
    ["٠ ٢ * * ١", "0 2 * * ١", "*/١٥ 2 * * 1"],
)
def test_legacy_schedule_rejects_unicode_cron_digits(cron):
    github = GitHub()
    files = github.repos["owner/project"]
    config = json.loads(files[".github/node-maintenance.json"])
    config["schedule"] = [cron]
    files[".github/node-maintenance.json"] = data(config)
    caller = yaml.safe_load(files[".github/workflows/dependency-audit.yml"])
    caller["on"]["schedule"] = [{"cron": cron}]
    files[".github/workflows/dependency-audit.yml"] = data(caller)
    result = FLEET["check_repository"](github, "owner/project", SOURCE)
    assert result["status"] == "failed"


def test_issue_identity_survives_ref_changes():
    source = {**SOURCE, "path": "defaults/repos.json", "commit": SHA}
    assert REPORTER["marker"](source) == REPORTER["marker"]({**source, "ref": SHA})


def test_partial_healthy_report_cannot_close_an_issue():
    report = FLEET["check_fleet"](
        GitHub(),
        {"repository": "owner/settings", "path": "defaults/repos.json", "ref": "main"},
    )
    report["results"][0]["commit"] = None
    issues = Issues()
    with pytest.raises(ValueError, match="checked commit"):
        REPORTER["update_issue"](
            "owner/host",
            report,
            "https://github.com/owner/host/actions/runs/1",
            issues.request,
        )
    assert issues.items == []


def test_api_token_stays_on_fixed_origin_and_redirects_are_disabled(monkeypatch):
    import urllib.error
    import urllib.parse
    import urllib.request

    observed = []

    class Opener:
        def open(self, request, timeout):
            observed.append(request)
            raise urllib.error.HTTPError(request.full_url, 302, "moved", {}, None)

    def opener(handler):
        assert handler is FLEET["CONFIGURATION"]["NoRedirect"]
        return Opener()

    monkeypatch.setattr(urllib.request, "build_opener", opener)
    with pytest.raises(FLEET["Unverified"], match="HTTP 302"):
        FLEET["GitHub"]("test-token").get("repos/owner/project")
    assert urllib.parse.urlsplit(observed[0].full_url).netloc == "api.github.com"
    assert observed[0].get_header("Authorization") == "Bearer test-token"


def test_pinned_workflow_must_support_the_resolved_toolchain():
    github = GitHub()
    support = json.loads(github.repos["owner/actions"]["node/runtime/toolchain.json"])
    support["supported"]["pnpm"] = ["11.20.0"]
    github.repos["owner/actions"]["node/runtime/toolchain.json"] = data(support)
    result = FLEET["check_repository"](github, "owner/project", SOURCE)
    assert result["status"] == "failed"
    assert "Pinned workflows do not support" in result["diagnostic"]


def test_large_fleet_issue_is_bounded_and_retains_member_identity():
    report = {
        "schema_version": 1,
        "inventory": {**SOURCE, "commit": SHA},
        "results": [
            {
                "repository": f"owner/repository-{index}",
                "commit": None,
                "status": "failed" if index % 2 else "unverified",
                "diagnostic": "<&é" * 1000,
            }
            for index in range(25)
        ],
        "status": "failed",
        "diagnostic": "<&é" * 1000,
    }
    issues = Issues()
    run_url = "https://github.com/owner/host/actions/runs/99"
    assert (
        REPORTER["update_issue"]("owner/host", report, run_url, issues.request)[
            "operation"
        ]
        == "created"
    )
    body = issues.items[0]["body"]
    assert len(body.encode()) <= REPORTER["MAX_ISSUE_BYTES"]
    assert body.startswith(REPORTER["marker"](report["inventory"]) + "\n")
    assert "[truncated]" in body
    assert "node-fleet-report artifact" in body
    assert run_url in body
    assert "not tested" in body
    for index in range(25):
        status = "failed" if index % 2 else "unverified"
        assert f"### owner/repository-{index}: {status}" in body

    for item in report["results"]:
        item.update(commit=SHA, status="ok", diagnostic="Static setup checks passed")
    report.update(status="ok", diagnostic="")
    assert (
        REPORTER["update_issue"]("owner/host", report, run_url, issues.request)[
            "operation"
        ]
        == "closed"
    )
    report["status"] = "failed"
    report["results"][0].update(commit=None, status="failed", diagnostic="x" * 4000)
    assert (
        REPORTER["update_issue"]("owner/host", report, run_url, issues.request)[
            "operation"
        ]
        == "reopened"
    )
