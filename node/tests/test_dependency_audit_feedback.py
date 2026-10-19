import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from test_node_standard import audit_module, fake_npm
from test_node_standard import npm_project as npm_project
from test_node_standard import pnpm_project as pnpm_project


@pytest.mark.parametrize("exit_code", [0, 1])
def test_command_logs_include_successful_output_and_warnings(
    npm_project, monkeypatch, capsys, exit_code
):
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(
            command, exit_code, "build output", "build warning"
        ),
    )
    audit_module["run"](npm_project, "run", "build")
    output = capsys.readouterr().out
    assert "build output" in output and "build warning" in output


@pytest.mark.parametrize("install,build", [(0, 0), (1, 0), (0, 1)])
def test_validation_output_and_dependency_fingerprints(
    npm_project, monkeypatch, install, build
):
    fake_npm(monkeypatch, install=install, build=build)
    validation = {}
    report = audit_module["prepare"](npm_project, validation=validation)
    assert validation["passed"] == (install == build == 0)
    for name in ("package.json", "package-lock.json"):
        assert hashlib.sha256((npm_project / name).read_bytes()).hexdigest() in report


@pytest.mark.parametrize("build", [0, 1])
def test_cli_exports_validation_status_without_preventing_report_publication(
    npm_project, monkeypatch, build
):
    fake_npm(monkeypatch, build=build)
    monkeypatch.chdir(npm_project.parent)
    report = npm_project / "report.md"
    output = npm_project / "github-output"
    output.write_text("existing=value\n")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "dependency_audit.py",
            "--directory",
            npm_project.name,
            "--report",
            str(report),
            "--github-output",
            str(output),
        ],
    )
    audit_module["main"]()
    assert report.exists()
    assert output.read_text() == (
        f"existing=value\nvalidation_passed={'true' if build == 0 else 'false'}\n"
    )


@pytest.mark.parametrize("missing", ["initial", "final", "both"])
def test_cli_fails_incomplete_audit_but_retains_successful_project_checks(
    npm_project, monkeypatch, capsys, missing
):
    fake_npm(monkeypatch)
    original_audit = audit_module["audit"]
    calls = 0

    def evidence(*args, **kwargs):
        nonlocal calls
        calls += 1
        phase = "initial" if calls == 1 else "final"
        if missing in (phase, "both"):
            return f"Audit unavailable: {phase} registry response is incomplete."
        return original_audit(*args, **kwargs)

    monkeypatch.setitem(audit_module["prepare"].__globals__, "audit", evidence)
    monkeypatch.chdir(npm_project.parent)
    report = npm_project / "report.md"
    output = npm_project / "github-output"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "dependency_audit.py",
            "--directory",
            npm_project.name,
            "--maintenance-mode",
            "security-only",
            "--report",
            str(report),
            "--github-output",
            str(output),
        ],
    )
    with pytest.raises(SystemExit) as error:
        audit_module["main"]()
    assert error.value.code == 1
    assert calls == 2
    assert "- Project checks: passed." in report.read_text()
    assert "Security audit incomplete" in report.read_text()
    assert output.read_text() == "validation_passed=true\n"
    assert "registry response is incomplete" in capsys.readouterr().err


def test_cli_fails_unavailable_pnpm_evidence_without_rewriting_project_policy(
    pnpm_project, monkeypatch
):
    workspace = pnpm_project / "pnpm-workspace.yaml"
    policy = yaml.safe_load(workspace.read_bytes())
    policy["auditConfig"] = {"ignoreGhsas": ["GHSA-example"]}
    workspace.write_text(yaml.safe_dump(policy))
    original = workspace.read_bytes()
    module = audit_module["prepare"].__globals__
    monkeypatch.setitem(
        module,
        "fix_security",
        lambda *a, **kw: subprocess.CompletedProcess([], 0, "", ""),
    )
    monkeypatch.setitem(
        module, "run", lambda *a, **kw: subprocess.CompletedProcess([], 0, "", "")
    )
    monkeypatch.chdir(pnpm_project.parent)
    report = pnpm_project / "report.md"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "dependency_audit.py",
            "--directory",
            pnpm_project.name,
            "--maintenance-mode",
            "security-only",
            "--report",
            str(report),
        ],
    )
    with pytest.raises(SystemExit) as error:
        audit_module["main"]()
    assert error.value.code == 1
    assert workspace.read_bytes() == original
    assert "Audit unavailable" in report.read_text()
    assert "- Project checks: passed." in report.read_text()


@pytest.mark.parametrize("report_exists", [False, True])
def test_action_retains_incomplete_audit_summary_and_artifact(tmp_path, report_exists):
    action = yaml.safe_load(
        (Path(__file__).parents[1] / "audit/action.yml").read_text()
    )
    steps = action["runs"]["steps"]
    summary = next(
        step
        for step in steps
        if step.get("name", "").startswith("Retain the audit summary")
    )
    artifact = next(
        step
        for step in steps
        if step.get("with", {}).get("name") == "dependency-audit-report"
    )
    for step in (summary, artifact):
        assert step["if"] == "${{ always() && !cancelled() }}"
    assert artifact["with"]["if-no-files-found"] == "ignore"
    text = "Security audit incomplete.\nProject checks passed.\n$(never-execute)\n"
    if report_exists:
        (tmp_path / "dependency-audit-pr.md").write_text(text)
    destination = tmp_path / "summary.md"
    subprocess.run(
        ["bash", "-e", "-o", "pipefail", "-c", summary["run"]],
        env={
            **os.environ,
            "RUNNER_TEMP": str(tmp_path),
            "GITHUB_STEP_SUMMARY": str(destination),
        },
        check=True,
    )
    assert (
        destination.read_text() == text if report_exists else not destination.exists()
    )


@pytest.mark.parametrize("pnpm", [False, True])
def test_all_locked_version_changes_include_transitives_additions_and_removals(pnpm):
    old = {
        "packages": {
            "node_modules/leaf": {"version": "1.0.0"},
            "node_modules/gone": {"version": "1.0.0"},
        }
    }
    new = {
        "packages": {
            "node_modules/leaf": {"version": "1.1.0"},
            "node_modules/nested/node_modules/leaf": {"version": "1.0.0"},
            "node_modules/new": {"version": "2.0.0"},
        }
    }
    if pnpm:
        old = {
            "packages": {
                "leaf@1.0.0": {"name": "leaf", "version": "1.0.0"},
                "gone@1.0.0": {"name": "gone", "version": "1.0.0"},
            }
        }
        new = {
            "packages": {
                "leaf@1.0.0": {"name": "leaf", "version": "1.0.0"},
                "leaf@1.1.0": {"name": "leaf", "version": "1.1.0"},
                "new@2.0.0": {"name": "new", "version": "2.0.0"},
            }
        }
    assert audit_module["locked_changes"](old, new) == [
        "- gone: `1.0.0` → `not installed`",
        "- leaf: `1.0.0` → `1.0.0, 1.1.0`",
        "- new: `not installed` → `2.0.0`",
    ]


def test_report_includes_non_advisory_transitive_upgrade(pnpm_project, monkeypatch):
    lockfile = pnpm_project / "pnpm-lock.yaml"
    lock = yaml.safe_load(lockfile.read_bytes())
    lock["packages"]["leaf@1.0.0"] = {}
    lockfile.write_text(yaml.safe_dump(lock))

    def invoke(command, **kwargs):
        args = command[5:]
        stdout = ""
        if args[:2] == ["audit", "--json"]:
            stdout = json.dumps(
                {"metadata": {"vulnerabilities": {"total": 0}}, "advisories": {}}
            )
        elif args[0] == "view":
            stdout = '"1.0.0"'
        elif "--lockfile-only" in args:
            candidate = yaml.safe_load(lockfile.read_bytes())
            candidate["packages"].pop("leaf@1.0.0", None)
            candidate["packages"]["leaf@1.0.1"] = {}
            lockfile.write_text(yaml.safe_dump(candidate))
        return subprocess.CompletedProcess(command, 0, stdout, "")

    monkeypatch.setattr(subprocess, "run", invoke)
    report = audit_module["prepare"](pnpm_project)
    assert "- leaf: `1.0.0` → `1.0.1`" in report
