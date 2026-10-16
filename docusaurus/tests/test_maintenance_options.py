import json
import runpy
import subprocess
from pathlib import Path

import pytest
import yaml

RUNTIME = Path(__file__).parents[1] / "runtime"
reader = runpy.run_path(str(RUNTIME / "project.py"))
helper = runpy.run_path(str(RUNTIME / "templates/dependency_audit.py"))


@pytest.fixture
def site(tmp_path):
    (tmp_path / ".github").mkdir()
    (tmp_path / ".github/docusaurus.json").write_text('{"directory":"website"}')
    directory = tmp_path / "website"
    directory.mkdir()
    (directory / "package.json").write_text(
        json.dumps(
            {
                "packageManager": "pnpm@11.21.0",
                "scripts": {
                    "build": "site build",
                    "docs:build": "checks && site build",
                },
                "dependencies": {"renderer": "^1.2.3"},
            }
        )
    )
    (directory / "pnpm-workspace.yaml").write_text(
        "packages: ['.']\nminimumReleaseAge: 14400\nblockExoticSubdeps: true\n"
    )
    write_lock(directory, "1.2.3")
    return directory


def write_lock(directory, version):
    manifest = json.loads((directory / "package.json").read_text())
    (directory / "pnpm-lock.yaml").write_text(
        yaml.safe_dump(
            {
                "lockfileVersion": "9.0",
                "importers": {
                    ".": {
                        "dependencies": {
                            "renderer": {
                                "specifier": manifest["dependencies"]["renderer"],
                                "version": version,
                            }
                        }
                    }
                },
                "packages": {f"renderer@{version}": {}},
            }
        )
    )


def fake_commands(monkeypatch, *, resolved=None, build=0, recent=()):
    commands = []

    def invoke(directory, *args, **kwargs):
        commands.append((directory, args))
        stdout, code = "", 0
        if args[0] == "view":
            if args[2] == "versions":
                stdout = json.dumps(["1.2.4", "1.3.0", "2.0.0"])
            elif args[2] == "time":
                stdout = json.dumps(
                    {
                        v: "2999-01-01T00:00:00Z"
                        if v in recent
                        else "2020-01-01T00:00:00Z"
                        for v in ["1.2.4", "1.3.0", "2.0.0"]
                    }
                )
            else:
                stdout = '"2.0.0"'
        elif args[0] == "install" and "--lockfile-only" in args:
            specifier = json.loads((directory / "package.json").read_text())[
                "dependencies"
            ]["renderer"]
            write_lock(directory, resolved or specifier.lstrip("~^"))
        elif args[:1] == ("run",):
            code = build
        return subprocess.CompletedProcess(args, code, stdout, "")

    monkeypatch.setitem(helper["prepare"].__globals__, "run", invoke)
    monkeypatch.setitem(
        helper["prepare"].__globals__,
        "audit",
        lambda *a, **k: {
            "vulnerabilities": {},
            "metadata": {"vulnerabilities": {"total": 0}},
        },
    )
    monkeypatch.setitem(
        helper["prepare"].__globals__,
        "fix_security",
        lambda *a, **k: subprocess.CompletedProcess([], 0, "", ""),
    )
    monkeypatch.setitem(
        helper["prepare"].__globals__, "describe_pnpm_fixes", lambda *a, **k: None
    )
    return commands


@pytest.mark.parametrize(
    "scope,expected", [("patch", "1.2.4"), ("minor", "1.3.0"), ("major", "2.0.0")]
)
def test_routine_selection_obeys_maximum_scope(site, monkeypatch, scope, expected):
    fake_commands(monkeypatch)
    helper["prepare"](site, upgrade_scope=scope)
    assert (
        json.loads((site / "package.json").read_text())["dependencies"]["renderer"]
        == expected
    )


def test_restricted_selection_retains_release_age(site, monkeypatch):
    fake_commands(monkeypatch, recent=("1.3.0",))
    helper["prepare"](site, upgrade_scope="minor")
    assert (
        json.loads((site / "package.json").read_text())["dependencies"]["renderer"]
        == "1.2.4"
    )


def test_out_of_scope_resolved_version_restores_security_snapshot(site, monkeypatch):
    fake_commands(monkeypatch, resolved="2.0.0")
    before = helper["valid_snapshot"](site)
    report = helper["prepare"](site, upgrade_scope="patch")
    assert helper["valid_snapshot"](site) == before
    assert "maintenance.upgradeScope=patch" in report
    assert "0 additional package updates (0 total)" in report


def test_security_only_omits_routine_resolution_and_uses_selected_script(
    site, monkeypatch
):
    commands = fake_commands(monkeypatch)
    validation = {}
    report = helper["prepare"](
        site,
        maintenance_mode="security-only",
        build_script="docs:build",
        validation=validation,
    )
    assert not any(
        args[0] == "view" or "--lockfile-only" in args for _, args in commands
    )
    assert (site, ("run", "docs:build")) in commands
    assert "Routine upgrades disabled" in report
    assert validation["passed"]


@pytest.mark.parametrize("build", [0, 1])
def test_custom_build_failure_is_reported(site, monkeypatch, build):
    fake_commands(monkeypatch, build=build)
    validation = {}
    report = helper["prepare"](site, build_script="docs:build", validation=validation)
    assert validation["passed"] is (build == 0)
    assert "docs:build" in report


@pytest.mark.parametrize(
    "settings",
    [
        {"buildScript": "missing"},
        {"buildScript": "build && other"},
        {"buildScript": 1},
        {"maintenance": None},
        {"maintenance": {"mode": "other"}},
        {"maintenance": {"upgradeScope": "other"}},
        {"maintenance": {"unknown": True}},
    ],
)
def test_reader_rejects_invalid_options_without_commands(site, settings, monkeypatch):
    manifest = json.loads((site / "package.json").read_text())
    manifest["dependencies"]["@docusaurus/core"] = "3.10.2"
    (site / "package.json").write_text(json.dumps(manifest))
    (site.parent / ".github/docusaurus.json").write_text(
        json.dumps({"directory": "website", **settings})
    )
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **k: pytest.fail("dependency command ran")
    )
    with pytest.raises(ValueError, match="buildScript|maintenance"):
        reader["project"](site.parent)


def test_invalid_helper_selection_stops_before_commands(site, monkeypatch):
    monkeypatch.setitem(
        helper["prepare"].__globals__,
        "run",
        lambda *a, **k: pytest.fail("dependency command ran"),
    )
    with pytest.raises(ValueError, match="script"):
        helper["prepare"](site, build_script="missing")


@pytest.mark.parametrize("mode", ["security-only", "security-and-maintenance"])
@pytest.mark.parametrize("scope", ["patch", "minor"])
def test_security_fix_is_independent_of_routine_scope(site, monkeypatch, mode, scope):
    commands = fake_commands(monkeypatch, resolved="2.0.0")
    original = helper["valid_snapshot"](site)
    fixed = False
    findings = {
        "vulnerabilities": {
            "renderer": {"severity": "high", "range": "<1.3.0", "via": [], "nodes": []}
        },
        "metadata": {"vulnerabilities": {"high": 1, "total": 1}},
    }

    def audit(*args, **kwargs):
        return (
            findings
            if not fixed
            else {"vulnerabilities": {}, "metadata": {"vulnerabilities": {"total": 0}}}
        )

    def security(directory, *args, **kwargs):
        nonlocal fixed
        fixed = True
        # A compatible fix may cross the routine patch/minor boundary.
        write_lock(directory, "1.3.0")
        return subprocess.CompletedProcess([], 0, "", "")

    monkeypatch.setitem(helper["prepare"].__globals__, "audit", audit)
    monkeypatch.setitem(helper["prepare"].__globals__, "fix_security", security)
    report = helper["prepare"](site, maintenance_mode=mode, upgrade_scope=scope)
    final = helper["valid_snapshot"](site)
    assert final[0] == original[0]
    assert helper["direct_versions"](final)[("dependencies", "renderer")] == (1, 3, 0)
    assert "1 total" in report
    if mode == "security-only":
        assert not any(
            args[0] == "view" or "--lockfile-only" in args for _, args in commands
        )
    else:
        assert "Restored accepted security fixes" in report


def test_security_only_keeps_unresolved_findings_visible(site, monkeypatch):
    fake_commands(monkeypatch)
    monkeypatch.setitem(
        helper["prepare"].__globals__,
        "audit",
        lambda *a, **k: "Audit unavailable: registry offline",
    )
    monkeypatch.setitem(
        helper["prepare"].__globals__,
        "fix_security",
        lambda *a, **k: subprocess.CompletedProcess([], 1, "", ""),
    )
    report = helper["prepare"](site, maintenance_mode="security-only")
    assert "registry offline" in report
    assert "security fix returned exit 1" in report
    assert "unconfirmed" in report


@pytest.mark.parametrize(
    "section", ["dependencies", "devDependencies", "optionalDependencies"]
)
@pytest.mark.parametrize("scope,version", [("patch", "1.3.0"), ("minor", "2.0.0")])
def test_scope_checks_unselected_direct_dependencies(site, section, scope, version):
    manifest = json.loads((site / "package.json").read_text())
    manifest[section] = {"renderer": "^1.2.3"}
    (site / "package.json").write_text(json.dumps(manifest))
    write_lock(site, "1.2.3")
    lock = yaml.safe_load((site / "pnpm-lock.yaml").read_text())
    lock["importers"]["."] = {
        section: {"renderer": {"specifier": "^1.2.3", "version": "1.2.3"}}
    }
    (site / "pnpm-lock.yaml").write_text(yaml.safe_dump(lock))
    before = helper["valid_snapshot"](site)
    lock["importers"]["."][section]["renderer"]["version"] = version
    (site / "pnpm-lock.yaml").write_text(yaml.safe_dump(lock))
    after = helper["valid_snapshot"](site)
    assert "resolved version" in helper["routine_scope_violation"](before, after, scope)


def test_options_cross_project_environment_and_action_boundary(site, tmp_path):
    import os
    import sys

    manifest = json.loads((site / "package.json").read_text())
    manifest["dependencies"]["@docusaurus/core"] = "3.10.2"
    (site / "package.json").write_text(json.dumps(manifest))
    (site.parent / ".github/docusaurus.json").write_text(
        json.dumps(
            {
                "directory": "website",
                "buildScript": "docs:build",
                "maintenance": {"mode": "security-only", "upgradeScope": "patch"},
            }
        )
    )
    environment = tmp_path / "github-env"
    subprocess.run(
        [
            sys.executable,
            str(RUNTIME / "project.py"),
            "--root",
            str(site.parent),
            "--github-env",
            str(environment),
        ],
        check=True,
    )
    env = dict(
        os.environ,
        **dict(line.split("=", 1) for line in environment.read_text().splitlines()),
    )
    # Execute the actual folded YAML command with a recording Python executable.
    binary = tmp_path / "bin"
    binary.mkdir()
    executable = binary / "python"
    executable.write_text(
        '#!/bin/sh\nprintf "%s\\n" "$@" > "$RUNNER_TEMP/arguments"\ntouch "$RUNNER_TEMP/dependency-audit-pr.md"\n'
    )
    executable.chmod(0o755)
    env.update(
        PATH=str(binary) + os.pathsep + env["PATH"],
        GITHUB_ACTION_PATH=str(RUNTIME.parent / "audit"),
        RUNNER_TEMP=str(tmp_path),
        GITHUB_OUTPUT=str(tmp_path / "output"),
        GITHUB_STEP_SUMMARY=str(tmp_path / "summary"),
    )
    steps = yaml.safe_load((RUNTIME.parent / "audit/action.yml").read_text())["runs"][
        "steps"
    ]
    command = next(step["run"] for step in steps if step.get("id") == "proposal")
    subprocess.run(["bash", "-e", "-c", command], env=env, check=True)
    args = (tmp_path / "arguments").read_text().splitlines()
    for flag, expected in [
        ("--directory", "website"),
        ("--build-script", "docs:build"),
        ("--maintenance-mode", "security-only"),
        ("--upgrade-scope", "patch"),
    ]:
        assert args[args.index(flag) + 1] == expected


@pytest.mark.parametrize("package_manager", ["pnpm", "npm"])
@pytest.mark.parametrize("changed", [False, True])
def test_unknown_direct_reference_must_remain_unchanged(site, package_manager, changed):
    manifest = {
        "packageManager": f"{package_manager}@11.21.0",
        "dependencies": {"alias": "npm:renderer@^1.0.0"},
    }
    (site / "package.json").write_text(json.dumps(manifest))
    if package_manager == "npm":
        (site / "pnpm-lock.yaml").unlink()
        (site / "pnpm-workspace.yaml").unlink()

    def snapshot(version):
        if package_manager == "pnpm":
            lock = {
                "lockfileVersion": "9.0",
                "importers": {".": {"dependencies": {"alias": {"version": version}}}},
                "packages": {version: {}},
            }
            (site / "pnpm-lock.yaml").write_text(yaml.safe_dump(lock))
        else:
            lock = {"packages": {"node_modules/alias": {"resolved": version}}}
            (site / "package-lock.json").write_text(json.dumps(lock))
        result = helper["valid_snapshot"](site)
        assert result is not None
        return result

    before = snapshot("renderer@1.2.3")
    after = snapshot("renderer@1.3.0" if changed else "renderer@1.2.3")
    violation = helper["routine_scope_violation"](before, after, "patch")
    assert (violation is not None) is changed
    if changed:
        assert "unverifiable direct reference" in violation
