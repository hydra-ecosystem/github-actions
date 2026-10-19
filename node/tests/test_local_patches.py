"""Compact assertions identify advisories without certifying arbitrary patch code."""

import copy
import json
import runpy
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from test_configuration_issue import GitHub
from test_node_standard import audit_module
from test_node_standard import npm_project as npm_project
from test_node_standard import pnpm_project as pnpm_project

ROOT = Path(__file__).parents[2]
PATCHES = runpy.run_path(str(ROOT / "node/runtime/local_patches.py"))
ISSUE = runpy.run_path(str(ROOT / "node/runtime/local_patch_issue.py"))
PROJECT = runpy.run_path(str(ROOT / "node/runtime/project.py"))
ID = "GHSA-2345-6789-cfgh"
ASSERTION = {"advisory": ID, "comment": "Covered by regression tests."}


def evidence(source="pnpm", patched_range=">=1.0.1"):
    nodes = ["renderer@1.0.0"] if source == "pnpm" else ["node_modules/renderer"]
    detail = {
        "title": "Example advisory",
        "url": "https://github.com/advisories/" + ID,
        "severity": "high",
        "range": "<1.0.1",
        "patchedRange": patched_range,
        "nodes": nodes,
    }
    return {
        "package_manager": source,
        "metadata": {"vulnerabilities": {"high": 1, "total": 1}},
        "vulnerabilities": {
            "renderer": {
                "severity": "high",
                "range": "<1.0.1",
                "nodes": nodes,
                "fixAvailable": True,
                "via": [detail],
            }
        },
    }


def report(status="fix-available", complete=True):
    return {
        "schema_version": 1,
        "complete": complete,
        "patches": [
            {
                **ASSERTION,
                "package": "renderer",
                "version": "1.0.0",
                "status": status,
                "fixedVersions": ["1.0.1"] if status == "fix-available" else [],
            }
        ],
    }


def maximum_report():
    value = report()
    value["patches"] = [
        {
            **value["patches"][0],
            "package": f"renderer-{version}",
            "version": f"1.0.{version}",
            "comment": "🧪" * 2048,
            "fixedVersions": ["2.0.0"],
        }
        for version in range(256)
    ]
    return value


@pytest.mark.parametrize(
    "value,comment",
    [
        (ID, ""),
        ([ID, "Covered by regression tests."], "Covered by regression tests."),
        ([ID, ""], ""),
    ],
)
def test_advisory_ids_and_optional_comments(value, comment):
    assert PATCHES["validate_declarations"]([value]) == [
        {"advisory": ID, "comment": comment}
    ]


@pytest.mark.parametrize(
    "value",
    [
        None,
        {},
        [ID],
        [ID, "comment", "extra"],
        [ID, None],
        [ID, "two\nlines"],
        "invalid",
        {"advisory": ID, "comment": "Old object form"},
        [ID, "x" * 2049],
    ],
)
def test_invalid_or_superseded_assertion_forms_fail(value):
    with pytest.raises(ValueError):
        PATCHES["validate_declarations"]([value])


def test_duplicate_ids_rejected_across_shorthand_and_comment_forms():
    with pytest.raises(ValueError, match="Duplicate"):
        PATCHES["validate_declarations"]([ID, [ID, "comment"]])


@pytest.mark.parametrize("source", ["npm", "pnpm"])
def test_package_versions_are_inferred_from_audit_and_lock_evidence(source):
    lock = {"packages": {"node_modules/renderer": {"version": "1.0.0"}}}

    def published(specifier, *, all_versions=False):
        return (
            {"1.0.0", "1.0.1"}
            if all_versions
            else {"1.0.0"}
            if "<" in specifier
            else {"1.0.1"}
        )

    value = PATCHES["assess"](
        [ASSERTION], evidence(source), evidence(source), published, lock
    )
    PATCHES["validate_report"](value)
    assert value == report()


def test_each_affected_version_gets_a_notification_row():
    data = evidence()
    data["vulnerabilities"]["renderer"]["via"][0]["nodes"].append("renderer@1.0.2")
    value = PATCHES["assess"]([ASSERTION], data, data, lambda *a, **kw: {"1.0.3"}, {})
    PATCHES["validate_report"](value)
    assert [row["version"] for row in value["patches"]] == ["1.0.0", "1.0.2"]


@pytest.mark.parametrize("complete", [False, True])
def test_missing_evidence_does_not_invent_package_metadata_or_a_fix(complete):
    data = {"vulnerabilities": {}} if complete else "Audit unavailable"
    value = PATCHES["assess"](
        [ASSERTION], data, data, lambda *a, **kw: pytest.fail("No finding to query"), {}
    )
    PATCHES["validate_report"](value)
    row = value["patches"][0]
    assert not row["package"] and not row["version"] and not row["fixedVersions"]
    assert row["status"] == ("not-reported" if complete else "unverified")


def test_unresolved_affected_versions_remain_unverified():
    value = PATCHES["assess"](
        [ASSERTION],
        evidence("npm"),
        evidence("npm"),
        lambda *a, **kw: pytest.fail("Version unknown"),
        {},
    )
    PATCHES["validate_report"](value)
    assert value["patches"][0]["status"] == "unverified"


def test_npm_official_fix_excludes_every_vulnerable_range():
    data = evidence("npm")
    details = data["vulnerabilities"]["renderer"]["via"]
    details.append({**details[0], "range": ">=1.0.2 <1.0.3"})

    def published(specifier, *, all_versions=False):
        if all_versions:
            return {"1.0.0", "1.0.1", "1.0.2", "1.0.3"}
        return {"1.0.2"} if ">=" in specifier else {"1.0.0"}

    assert PATCHES["fixed_versions"](
        data, {**ASSERTION, "package": "renderer", "version": "1.0.0"}, published
    ) == ("fix-available", ["1.0.1", "1.0.3"])


def test_one_issue_lifecycle_preserves_unknown_evidence_and_escapes_comments():
    github = GitHub()

    def update(value, run=1):
        return ISSUE["update_issue"](
            "owner/site",
            value,
            f"https://github.com/owner/site/actions/runs/{run}",
            github.request,
        )

    value = report()
    value["patches"][0]["comment"] = "Review | <script> [link](bad)"
    assert update(value)["operation"] == "created"
    assert update(value)["operation"] == "unchanged"
    assert update(value, 2)["operation"] == "updated"
    assert update(report("unverified", False))["operation"] == "skipped"
    assert github.issues[0]["state"] == "open"
    assert (
        update({"schema_version": 1, "complete": True, "patches": []})["operation"]
        == "closed"
    )
    assert update(value)["operation"] == "reopened"
    assert len(github.issues) == 1
    assert sum(method == "POST" for method, _, _ in github.calls) == 1
    assert (
        "&#124;" in github.issues[0]["body"]
        and "<script>" not in github.issues[0]["body"]
    )


def test_unknown_official_fix_availability_cannot_close_an_issue():
    data = evidence()
    value = PATCHES["assess"]([ASSERTION], data, data, lambda *a, **kw: None, {})
    assert value["patches"][0]["status"] == "unverified"
    github = GitHub()
    assert (
        ISSUE["update_issue"]("owner/site", value, "run", github.request)["operation"]
        == "skipped"
    )
    assert not github.calls


@pytest.mark.parametrize(
    "project_fixture,source,error,expected",
    [
        (
            "npm_project",
            "npm",
            {"code": "E404", "summary": "Not Found"},
            "unverified",
        ),
        (
            "pnpm_project",
            "pnpm",
            {"code": "ERR_PNPM_PACKAGE_NOT_FOUND"},
            "unverified",
        ),
        (
            "pnpm_project",
            "pnpm",
            {"code": "ERR_PNPM_NO_MATCHING_VERSION"},
            "no-fix",
        ),
    ],
)
def test_registry_metadata_errors_preserve_inferred_rows(
    request, monkeypatch, project_fixture, source, error, expected
):
    root = request.getfixturevalue(project_fixture)
    if source == "npm":
        (root / "package-lock.json").write_text(
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {"node_modules/renderer": {"version": "1.0.0"}},
                }
            )
        )
    module = audit_module["prepare"].__globals__
    monkeypatch.setitem(
        module, "audit", lambda *a, **kw: copy.deepcopy(evidence(source))
    )
    monkeypatch.setitem(
        module,
        "fix_security",
        lambda *a, **kw: subprocess.CompletedProcess([], 0, "", ""),
    )
    monkeypatch.setitem(module, "describe_npm_fixes", lambda *a, **kw: None)
    monkeypatch.setitem(module, "describe_pnpm_fixes", lambda *a, **kw: None)

    def run(directory, *args, **kwargs):
        if args[0] == "view":
            return subprocess.CompletedProcess(
                args, 1, json.dumps({"error": error}), ""
            )
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setitem(module, "run", run)
    validation = {}
    audit_module["prepare"](
        root,
        maintenance_mode="security-only",
        local_patches=[[ID, ASSERTION["comment"]]],
        validation=validation,
    )
    row = validation["local_patches"]["patches"][0]
    assert (row["package"], row["version"], row["status"]) == (
        "renderer",
        "1.0.0",
        expected,
    )


def test_maximum_report_round_trips_through_producer_and_cli_reader(
    pnpm_project, monkeypatch
):
    root = pnpm_project
    full_report = maximum_report()
    validation = {
        "passed": True,
        "audit_errors": [],
        "local_patches": full_report,
    }

    def prepare(directory, **kwargs):
        kwargs["validation"].update(validation)
        return "Complete report\n"

    monkeypatch.setitem(audit_module["main"].__globals__, "prepare", prepare)
    monkeypatch.chdir(root)
    artifact = root / "patches.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "dependency_audit.py",
            "--directory",
            ".",
            "--report",
            str(root / "report.md"),
            "--local-patches-report",
            str(artifact),
        ],
    )
    audit_module["main"]()
    assert json.loads(artifact.read_text()) == full_report
    assert artifact.stat().st_size <= PATCHES["MAX_REPORT_BYTES"]

    github = GitHub()
    received = {}

    def update_issue(repository, value, run_url):
        received["report"] = value
        return ISSUE["update_issue"](repository, value, run_url, github.request)

    monkeypatch.setitem(ISSUE["main"].__globals__, "update_issue", update_issue)
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/site")
    monkeypatch.setenv("GITHUB_RUN_ID", "1")
    monkeypatch.setattr(
        sys, "argv", ["local_patch_issue.py", "--report", str(artifact)]
    )
    ISSUE["main"]()
    assert received["report"] == full_report
    assert github.issues[0]["state"] == "open"
    assert len(github.issues[0]["body"].encode()) < 65536


def test_local_patch_cli_rejects_report_over_transport_bound(tmp_path, monkeypatch):
    artifact = tmp_path / "oversized.json"
    artifact.write_bytes(b"0" * (PATCHES["MAX_REPORT_BYTES"] + 1))
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/site")
    monkeypatch.setenv("GITHUB_RUN_ID", "1")
    monkeypatch.setattr(
        sys, "argv", ["local_patch_issue.py", "--report", str(artifact)]
    )
    with pytest.raises(SystemExit) as error:
        ISSUE["main"]()
    assert error.value.code == 1


@pytest.mark.parametrize("comment", ["x" * 2048, "🧪<&|" * 500])
def test_large_valid_reports_still_notify_with_a_bounded_table_preview(comment):
    value = report()
    value["patches"] = [
        {
            **value["patches"][0],
            "comment": comment,
            "version": f"1.0.{version}",
            "fixedVersions": ["2.0.0"],
        }
        for version in range(256)
    ]
    original = copy.deepcopy(value)
    github = GitHub()
    assert (
        ISSUE["update_issue"]("owner/site", value, "run", github.request)["operation"]
        == "created"
    )
    body = github.issues[0]["body"]
    assert len(body.encode()) < 65536
    assert "Table preview truncated" in body and "node-audit-local-patches" in body
    assert "No patch is removed automatically" in body
    assert value == original


def test_known_release_can_notify_even_if_final_audit_failed():
    value = PATCHES["assess"](
        [ASSERTION], evidence(), "Unavailable", lambda *a, **kw: {"1.0.1"}, {}
    )
    PATCHES["validate_report"](value)
    assert not value["complete"]
    github = GitHub()
    assert (
        ISSUE["update_issue"]("owner/site", value, "run", github.request)["operation"]
        == "created"
    )


def test_malformed_report_cannot_write_an_issue():
    value = report()
    value["patches"][0]["fixedVersions"] = ["$(execute)"]
    github = GitHub()
    with pytest.raises(ValueError):
        ISSUE["update_issue"]("owner/site", value, "run", github.request)
    assert not github.calls


@pytest.mark.parametrize("changed", [False, True])
def test_cli_freezes_assertions_and_comments_in_existing_configuration_snapshot(
    pnpm_project, monkeypatch, changed
):
    root = pnpm_project
    (root / ".github").mkdir()
    path = root / ".github/node-maintenance.json"
    config = {
        "directory": ".",
        "toolchain": {"node": "24"},
        "localPatches": [[ID, ASSERTION["comment"]]],
    }
    path.write_text(json.dumps(config))
    snapshot = root / "resolved.json"
    PROJECT["resolve_for_run"](root, snapshot, [])

    def prepare(directory, **kwargs):
        assert not changed
        assert kwargs["local_patches"] == config["localPatches"]
        kwargs["validation"].update(
            passed=True, audit_errors=[], local_patches=report()
        )
        return "Complete report\n"

    monkeypatch.setitem(audit_module["main"].__globals__, "prepare", prepare)
    if changed:
        config["localPatches"] = [ID]
        path.write_text(json.dumps(config))
    monkeypatch.chdir(root)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "dependency_audit.py",
            "--directory",
            ".",
            "--resolved-config",
            str(snapshot),
            "--report",
            str(root / "report.md"),
            "--local-patches-report",
            str(root / "patches.json"),
        ],
    )
    if changed:
        with pytest.raises(SystemExit) as error:
            audit_module["main"]()
        assert error.value.code == 2
    else:
        audit_module["main"]()
        assert json.loads((root / "patches.json").read_text()) == report()


def test_engine_keeps_raw_advisory_counts_and_does_not_touch_patch_files(
    pnpm_project, monkeypatch
):
    patch = pnpm_project / "arbitrary.patch"
    patch.write_text("Maintainer-managed patch\n")
    module = audit_module["prepare"].__globals__
    monkeypatch.setitem(module, "audit", lambda *a, **kw: copy.deepcopy(evidence()))
    monkeypatch.setitem(
        module,
        "fix_security",
        lambda *a, **kw: subprocess.CompletedProcess([], 0, "", ""),
    )
    monkeypatch.setitem(module, "describe_pnpm_fixes", lambda *a, **kw: None)
    monkeypatch.setitem(
        module,
        "run",
        lambda directory, *args, **kw: subprocess.CompletedProcess(
            args, 0, '["1.0.1"]' if args[0] == "view" else "", ""
        ),
    )
    validation = {}
    original = {p: p.read_bytes() for p in pnpm_project.rglob("*") if p.is_file()}
    body = audit_module["prepare"](
        pnpm_project,
        maintenance_mode="security-only",
        local_patches=[[ID, ASSERTION["comment"]]],
        validation=validation,
    )
    assert not validation["audit_errors"]
    assert validation["local_patches"] == report()
    assert "0 security fixes" in body and "1 advisory remains" in body
    assert ASSERTION["comment"] in body and "not independently verified" in body
    assert all(p.read_bytes() == value for p, value in original.items())


def test_declarations_are_local_and_reporter_has_no_project_execution_authority():
    assert PROJECT["CONFIGURATION"]["merge_shared"]({}, {"localPatches": [ID]}) == {}
    workflow = yaml.safe_load((ROOT / ".github/workflows/node-audit.yml").read_text())
    job = workflow["jobs"]["configuration-issue"]
    assert job["permissions"] == {"issues": "write"}
    assert not any("checkout@" in step.get("uses", "") for step in job["steps"])
