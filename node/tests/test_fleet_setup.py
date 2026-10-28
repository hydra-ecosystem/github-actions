"""Fleet setup checks inspect immutable data and never run project commands."""

import base64
import copy
import hashlib
import io
import json
import runpy
import subprocess
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier, Event, Lock
from urllib.parse import parse_qs, urlparse

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
                ".github/workflows/node-maintenance.yml": (
                    ROOT / ".github/workflows/node-maintenance.yml"
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


@pytest.mark.parametrize(
    "problem", [None, "branch", "paths", "permissions", "condition", "unsupported"]
)
def test_fleet_accepts_coordinated_installation_and_checks_trigger_contract(problem):
    github = GitHub()
    caller = yaml.safe_load(
        (ROOT / "node/coordinated-caller.yml")
        .read_text()
        .replace("__CENTRAL_REPOSITORY__", "owner/actions")
        .replace("__CENTRAL_REVISION__", SHA)
        .replace("__DEFAULT_BRANCH__", "main")
    )
    caller["on"]["schedule"] = [{"cron": cron} for cron in ["0 2 * * 1", "0 2 1 */3 *"]]
    if problem == "branch":
        caller["on"]["push"]["branches"] = ["wrong"]
    if problem == "paths":
        caller["on"]["push"]["paths"] = ["**"]
    if problem == "permissions":
        caller["jobs"]["maintenance"]["permissions"].pop("issues")
    if problem == "condition":
        caller["jobs"]["maintenance"]["if"] = "false"
    if problem == "unsupported":
        contract = json.loads(github.repos["owner/actions"]["node/contract.json"])
        del contract["coordinated_maintenance"]
        github.repos["owner/actions"]["node/contract.json"] = data(contract)
    github.repos["owner/project"][".github/workflows/dependency-audit.yml"] = (
        yaml.safe_dump(caller).encode()
    )
    result = FLEET["check_repository"](github, "owner/project", SOURCE)
    assert result["status"] == ("ok" if problem is None else "failed"), result


@pytest.mark.parametrize("coordinated", [False, True])
@pytest.mark.parametrize("permission", ["actions", "checks"])
def test_fleet_rejects_missing_publisher_evidence_permissions(coordinated, permission):
    github = GitHub()
    files = github.repos["owner/project"]
    if coordinated:
        caller = yaml.safe_load(
            (ROOT / "node/coordinated-caller.yml")
            .read_text()
            .replace("__CENTRAL_REPOSITORY__", "owner/actions")
            .replace("__CENTRAL_REVISION__", SHA)
            .replace("__DEFAULT_BRANCH__", "main")
        )
        caller["on"]["schedule"] = [
            {"cron": cron} for cron in ["0 2 * * 1", "0 2 1 */3 *"]
        ]
    else:
        caller = yaml.safe_load(files[".github/workflows/dependency-audit.yml"])
    publisher = caller["jobs"]["maintenance" if coordinated else "pull-request"]
    publisher["permissions"].pop(permission, None)
    files[".github/workflows/dependency-audit.yml"] = yaml.safe_dump(caller).encode()
    result = FLEET["check_repository"](github, "owner/project", SOURCE)
    assert result["status"] == "failed", result
    assert "permissions" in result["diagnostic"]


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


def test_inventory_major_release_branch_keeps_generic_ref_resolution():
    github = GitHub()
    report = FLEET["check_fleet"](
        github,
        {"repository": "owner/settings", "path": "defaults/repos.json", "ref": "v1"},
    )
    assert report["status"] == "ok"
    assert report["inventory"]["ref"] == "v1"
    assert [call for call in github.calls if "owner/settings/commits/" in call] == [
        "repos/owner/settings/commits/v1"
    ]


@pytest.mark.parametrize("ref", ["v1", "v2", "v123", SHA])
def test_matching_release_references_are_resolved_once_per_scan(ref):
    github = GitHub()
    files = project("npm")
    path = ".github/workflows/dependency-audit.yml"
    files[path] = files[path].replace(SHA.encode(), ref.encode())
    for name in ("owner/one", "owner/two"):
        github.add(name, files)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(
                lambda name: FLEET["check_repository"](github, name, SOURCE),
                ["owner/one", "owner/two"],
            )
        )
    assert [result["status"] for result in results] == ["ok", "ok"]
    # Explicit tag namespace avoids inspecting a same-named branch instead.
    resolved = "tags%2F" + ref if ref.startswith("v") else ref
    calls = [call for call in github.calls if "owner/actions/commits/" in call]
    assert calls == ["repos/owner/actions/commits/" + resolved]


@pytest.mark.parametrize("ref", ["main", "v0", "v01", "v1.2", "V1", "tags/v1"])
def test_branch_and_malformed_release_references_fail_setup(ref):
    github = GitHub()
    path = ".github/workflows/dependency-audit.yml"
    files = github.repos["owner/project"]
    files[path] = files[path].replace(SHA.encode(), ref.encode())
    result = FLEET["check_repository"](github, "owner/project", SOURCE)
    assert result["status"] == "failed"
    assert "same major release tag" in result["diagnostic"]


def test_audit_and_publisher_cannot_mix_release_references():
    github = GitHub()
    path = ".github/workflows/dependency-audit.yml"
    files = github.repos["owner/project"]
    files[path] = files[path].replace(("@" + SHA).encode(), b"@v1", 1)
    result = FLEET["check_repository"](github, "owner/project", SOURCE)
    assert result["status"] == "failed"


def test_unavailable_release_tag_is_unverified_without_branch_fallback():
    github = GitHub()
    path = ".github/workflows/dependency-audit.yml"
    files = github.repos["owner/project"]
    files[path] = files[path].replace(SHA.encode(), b"v1")
    original = github.get

    def get(path):
        if path == "repos/owner/actions/commits/tags%2Fv1":
            raise FLEET["Unverified"]("Release tag unavailable")
        return original(path)

    github.get = get
    result = FLEET["check_repository"](github, "owner/project", SOURCE)
    assert result["status"] == "unverified"
    assert "Release tag unavailable" in result["diagnostic"]


@pytest.mark.parametrize("failure", [None, "old-pin"])
def test_fleet_verifies_compact_patch_assertions_and_pinned_support(
    monkeypatch, failure
):
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: pytest.fail("Fleet checks execute no project commands"),
    )
    github = GitHub()
    files = github.repos["owner/project"]
    config = json.loads(files[".github/node-maintenance.json"])
    config["localPatches"] = ["GHSA-2345-6789-cfgh"]
    files[".github/node-maintenance.json"] = data(config)
    if failure == "old-pin":
        contract = json.loads(github.repos["owner/actions"]["node/contract.json"])
        contract.pop("local_patches")
        github.repos["owner/actions"]["node/contract.json"] = data(contract)
    result = FLEET["check_repository"](github, "owner/project", SOURCE)
    assert result["status"] == ("ok" if failure is None else "failed")
    if failure == "old-pin":
        assert "do not support localPatches" in result["diagnostic"]


def test_fleet_checks_five_at_a_time_and_retains_order_and_failures(monkeypatch):
    github = GitHub()
    names = [f"owner/project-{number}" for number in range(9)]
    github.repos["owner/settings"]["defaults/repos.json"] = data(
        {"defaults": SOURCE, "repositories": names}
    )
    ready = Barrier(6)
    release = Event()
    guard = Lock()
    active = maximum = 0

    def check(github, name, expected):
        nonlocal active, maximum
        assert expected == SOURCE
        with guard:
            active += 1
            maximum = max(maximum, active)
        try:
            if names.index(name) < 5:
                ready.wait(timeout=5)
                assert release.wait(timeout=5)
            return {
                "repository": name,
                "commit": SHA,
                "status": "failed" if name == names[2] else "ok",
                "diagnostic": "example failure" if name == names[2] else "passed",
            }
        finally:
            with guard:
                active -= 1

    monkeypatch.setitem(FLEET["check_fleet"].__globals__, "check_repository", check)
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(
            FLEET["check_fleet"],
            github,
            {
                "repository": "owner/settings",
                "path": "defaults/repos.json",
                "ref": "main",
            },
        )
        try:
            ready.wait(timeout=5)
        finally:
            release.set()
        report = future.result(timeout=5)
    assert maximum == 5
    assert [item["repository"] for item in report["results"]] == names
    assert report["status"] == "failed"
    assert report["results"][2]["diagnostic"] == "example failure"


def test_concurrent_checks_share_one_pinned_repository_snapshot(monkeypatch):
    github = FLEET["GitHub"]()
    entered = Event()
    release = Event()
    ready = Barrier(6)
    constructions = []

    def repository(client, name, ref):
        constructions.append((name, ref))
        entered.set()
        assert release.wait(timeout=5)
        return object()

    monkeypatch.setitem(FLEET["GitHub"].snapshot.__globals__, "Repository", repository)

    def snapshot():
        ready.wait(timeout=5)
        return github.snapshot("OWNER/PROJECT", "main")

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(snapshot) for _ in range(5)]
        try:
            ready.wait(timeout=5)
            assert entered.wait(timeout=5)
        finally:
            release.set()
        snapshots = [future.result(timeout=5) for future in futures]
    assert constructions == [("owner/project", "main")]
    assert all(item is snapshots[0] for item in snapshots)


def test_concurrent_defaults_reads_resolve_shared_ref_once(monkeypatch):
    calls = []

    def public(url, accept):
        calls.append((url, accept))
        return b"immutable result"

    monkeypatch.setitem(FLEET["CONFIGURATION"], "public_read", public)
    github = FLEET["GitHub"]()
    ready = Barrier(5)

    def read():
        ready.wait(timeout=5)
        return github.read_defaults(
            "https://api.github.com/repos/owner/settings/commits/main"
        )

    with ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(lambda _: read(), range(5)))
    assert results == [b"immutable result"] * 5
    assert len(calls) == 1


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
        self.calls = []

    def request(self, method, path, payload=None):
        self.calls.append((method, path, copy.deepcopy(payload)))
        if method == "GET":
            query = parse_qs(urlparse(path).query)
            assert query["state"] == ["all"]
            assert query["creator"] == ["github-actions[bot]"]
            assert query["sort"] == ["created"]
            assert query["direction"] == ["desc"]
            page = int(query["page"][0])
            assert query["per_page"] == ["100"]
            items = sorted(self.items, key=lambda issue: issue["number"], reverse=True)
            return copy.deepcopy(items[(page - 1) * 100 : page * 100])
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


def test_one_issue_per_failure_episode_with_manual_closure_and_recovery():
    github = GitHub()
    issues = Issues()
    report = FLEET["check_fleet"](
        github,
        {"repository": "owner/settings", "path": "defaults/repos.json", "ref": "main"},
    )
    report["status"] = "failed"
    report["results"][0].update(
        status="failed",
        diagnostic="Node mismatch <script>@someone</script> | extra\n[link]",
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
    assert "| Repository | Setup | Detail |" in issues.items[0]["body"]
    assert (
        "| [owner/project](https://github.com/owner/project) | ⚠️ Needs attention |"
        in issues.items[0]["body"]
    )
    assert "&#124; extra<br>&#91;link&#93;" in issues.items[0]["body"]
    assert "<summary>Checked revisions</summary>" in issues.items[0]["body"]
    issues.items[0]["state"] = "closed"
    assert update() == {"operation": "reopened", "number": 1}
    report["results"][0]["diagnostic"] = "Different setup failure"
    assert update() == {"operation": "updated", "number": 1}
    report["status"] = "ok"
    report["results"][0].update(status="ok", diagnostic="Static setup checks passed")
    assert update()["operation"] == "closed"
    recovered = copy.deepcopy(issues.items[0])
    assert REPORTER["RESOLVED"] in recovered["body"]
    assert update() == {"operation": "unchanged", "number": 1}
    recovered_body = issues.items[0]["body"]
    issues.items[0]["state"] = "open"
    report["status"] = "unverified"
    report["diagnostic"] = "Access unavailable"
    assert update() == {"operation": "created", "number": 2}
    assert issues.items[0]["body"] == recovered_body == recovered["body"]
    assert update() == {"operation": "unchanged", "number": 2}
    report["inventory"]["path"] = "defaults/other.json"
    assert update()["operation"] == "created" and len(issues.items) == 3


@pytest.fixture
def fleet_report():
    return FLEET["check_fleet"](
        GitHub(),
        {"repository": "owner/settings", "path": "defaults/repos.json", "ref": "main"},
    )


def test_healthy_fleet_does_not_create_issue_or_rewrite_recovered_history(fleet_report):
    issues = Issues()

    def update():
        return REPORTER["update_issue"](
            "owner/host", fleet_report, "run", issues.request
        )

    assert update() == {"operation": "unchanged", "number": None}
    assert all(call[0] == "GET" for call in issues.calls)
    fleet_report["status"] = "unverified"
    assert update()["operation"] == "created"
    fleet_report["status"] = "ok"
    assert update()["operation"] == "closed"
    issues.calls.clear()
    assert update() == {"operation": "unchanged", "number": 1}
    assert len(issues.calls) == 1 and issues.calls[0][0] == "GET"


@pytest.mark.parametrize("closed", [False, True])
@pytest.mark.parametrize("healthy", [False, True])
def test_legacy_issue_is_adopted_until_recovery_is_confirmed(
    fleet_report, closed, healthy
):
    issues = Issues()
    fleet_report["status"] = "unverified"
    REPORTER["update_issue"]("owner/host", fleet_report, "run", issues.request)
    issue = issues.items[0]
    issue["body"] = issue["body"].replace(REPORTER["ACTIVE"] + "\n", "")
    issue["state"] = "closed" if closed else "open"
    fleet_report["status"] = "ok" if healthy else "unverified"
    result = REPORTER["update_issue"]("owner/host", fleet_report, "run", issues.request)
    assert result == {
        "operation": "closed" if healthy else "reopened" if closed else "updated",
        "number": 1,
    }
    assert len(issues.items) == 1
    assert (REPORTER["RESOLVED"] if healthy else REPORTER["ACTIVE"]) in issue["body"]


def test_lookup_stops_at_newest_matching_incident_without_scanning_history(
    fleet_report,
):
    issues = Issues()
    fleet_report["status"] = "unverified"
    REPORTER["update_issue"]("owner/host", fleet_report, "run", issues.request)
    historical = copy.deepcopy(issues.items[0])
    for number in range(2, 302):
        issues.items.append({**historical, "number": number, "state": "closed"})
    # The newest incident wins even with many historical matches. PRs and
    # user-authored lookalikes cannot take over the reporter's identity.
    issues.items.extend(
        [
            {**historical, "number": 302, "pull_request": {}},
            {**historical, "number": 303, "user": {"login": "someone", "type": "User"}},
        ]
    )
    issues.calls.clear()
    result = REPORTER["update_issue"]("owner/host", fleet_report, "run", issues.request)
    assert result == {"operation": "reopened", "number": 301}
    assert [call[0] for call in issues.calls] == ["GET", "PATCH"]
    assert issues.items[0] == historical


def test_lookup_paginates_newer_unrelated_issues(fleet_report):
    issues = Issues()
    fleet_report["status"] = "unverified"
    REPORTER["update_issue"]("owner/host", fleet_report, "run", issues.request)
    for number in range(2, 102):
        issues.items.append({"number": number, "body": "unrelated"})
    issues.calls.clear()
    result = REPORTER["update_issue"]("owner/host", fleet_report, "run", issues.request)
    assert result == {"operation": "unchanged", "number": 1}
    assert len(issues.calls) == 2
    assert issues.calls[-1][1].endswith("page=2")


@pytest.mark.parametrize(
    "response, message",
    [
        ({}, "issue list"),
        ([None], "invalid issue"),
        ([{"number": 1, "state": "unknown"}], "invalid marked fleet issue"),
        ([{"number": True, "state": "open"}], "invalid marked fleet issue"),
    ],
)
def test_lookup_rejects_invalid_api_evidence_without_writes(
    fleet_report, response, message
):
    calls = []

    def request(method, path, payload=None):
        calls.append(method)
        if isinstance(response, list) and response[0] is not None:
            return [
                {
                    **response[0],
                    "body": REPORTER["marker"](fleet_report["inventory"]) + "\nold",
                    "user": {"login": "github-actions[bot]", "type": "Bot"},
                }
            ]
        return response

    with pytest.raises(ValueError, match=message):
        REPORTER["update_issue"]("owner/host", fleet_report, "run", request)
    assert calls == ["GET"]


def test_incomplete_lookup_does_not_create_duplicate(fleet_report):
    calls = []

    def request(method, path, payload=None):
        calls.append(method)
        return [{"body": "unrelated"}] * 100

    with pytest.raises(ValueError, match="lookup limit"):
        REPORTER["update_issue"]("owner/host", fleet_report, "run", request)
    assert calls == ["GET"] * 100


def test_workflow_splits_read_access_and_host_issue_write_access():
    workflow = yaml.safe_load(
        (ROOT / ".github/workflows/node-fleet-check.yml").read_text()
    )
    assert {"workflow_call", "workflow_dispatch", "schedule"} == set(workflow["on"])
    assert workflow["on"]["schedule"] == [{"cron": "0 3 * * 1"}]
    assert workflow["name"] == "Node maintenance setup check"
    assert workflow["jobs"]["check"]["steps"][0]["with"]["inventory-path"] == (
        "${{ inputs.inventory-path || 'defaults/node-repositories.json' }}"
    )
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
    assert job["uses"].endswith("/node-fleet-check.yml@v1")
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


@pytest.mark.parametrize("job", ["audit", "pull-request"])
def test_unrelated_job_cannot_block_maintenance(job):
    github = GitHub()
    files = github.repos["owner/project"]
    caller = yaml.safe_load(files[".github/workflows/dependency-audit.yml"])
    caller["jobs"]["optional-check"] = {
        "if": False,
        "runs-on": "ubuntu-latest",
        "steps": [{"run": "true"}],
    }
    caller["jobs"][job]["needs"] = (
        ["audit", "optional-check"] if job == "pull-request" else "optional-check"
    )
    files[".github/workflows/dependency-audit.yml"] = data(caller)
    result = FLEET["check_repository"](github, "owner/project", SOURCE)
    assert result["status"] == "failed"
    assert "prerequisites" in result["diagnostic"]


def test_single_audit_dependency_list_is_supported():
    github = GitHub()
    files = github.repos["owner/project"]
    caller = yaml.safe_load(files[".github/workflows/dependency-audit.yml"])
    caller["jobs"]["pull-request"]["needs"] = ["audit"]
    files[".github/workflows/dependency-audit.yml"] = data(caller)
    assert FLEET["check_repository"](github, "owner/project", SOURCE)["status"] == "ok"


@pytest.mark.parametrize("weekday", ["7", "0-7"])
def test_cron_weekdays_outside_github_range_fail(weekday):
    github = GitHub()
    files = github.repos["owner/project"]
    cron = f"0 2 * * {weekday}"
    config = json.loads(files[".github/node-maintenance.json"])
    config["schedule"] = [cron]
    files[".github/node-maintenance.json"] = data(config)
    caller = yaml.safe_load(files[".github/workflows/dependency-audit.yml"])
    caller["on"]["schedule"] = [{"cron": cron}]
    files[".github/workflows/dependency-audit.yml"] = data(caller)
    result = FLEET["check_repository"](github, "owner/project", SOURCE)
    assert result["status"] == "failed"
    assert "outside 0-6" in result["diagnostic"]


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


@pytest.mark.parametrize("central_error", [None, 403])
def test_public_workflow_reads_do_not_inherit_private_monitoring_token(
    monkeypatch, central_error
):
    server = GitHub("npm")
    observed = []

    class Opener:
        def open(self, request, timeout):
            path = urlparse(request.full_url).path.lstrip("/")
            if urlparse(request.full_url).query:
                path += "?" + urlparse(request.full_url).query
            authorization = request.get_header("Authorization")
            observed.append((path, authorization))
            if path.startswith("repos/owner/actions"):
                # Reproduce an organization rejecting an otherwise valid PAT.
                if authorization or central_error:
                    raise urllib.error.HTTPError(
                        request.full_url, 403, "organization policy", {}, None
                    )
            else:
                # Inventory, project files and Actions state still need the PAT.
                assert authorization == "Bearer test-token"
            return io.BytesIO(json.dumps(server.get(path)).encode())

    monkeypatch.setattr(urllib.request, "build_opener", lambda handler: Opener())
    github = FLEET["GitHub"]("test-token")
    github.read_defaults = server.public
    source = {
        "repository": "owner/settings",
        "path": "defaults/repos.json",
        "ref": "main",
    }
    report = FLEET["check_fleet"](github, source)
    result = report["results"][0]
    assert result["status"] == ("unverified" if central_error else "ok")
    central_reads = [
        item for item in observed if item[0].startswith("repos/owner/actions")
    ]
    assert central_reads and all(auth is None for _, auth in central_reads)
    if central_error:
        assert "HTTP 403" in result["diagnostic"]
        assert len(central_reads) == 1  # No retry with the private credential.
    else:
        assert any("git/blobs/" in path for path, _ in central_reads)
        assert any("actions/workflows/" in path for path, _ in observed)
        # Repeated installations share the unauthenticated pinned snapshot.
        before = len(observed)
        assert FLEET["check_fleet"](github, source)["status"] == "ok"
        assert len(observed) == before


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
        label = "⚠️ Needs attention" if status == "failed" else "❔ Unverified"
        assert (
            f"| [owner/repository-{index}](https://github.com/owner/repository-{index}) | {label} |"
            in body
        )

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
        == "created"
    )
