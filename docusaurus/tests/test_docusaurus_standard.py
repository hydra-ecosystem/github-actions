import hashlib
import json
import os
import runpy
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml
from workflow_source import load_workflow

audit_module = runpy.run_path(
    str(Path(__file__).parents[1] / "runtime/templates/dependency_audit.py")
)
format_remaining_audit = audit_module["format_remaining_audit"]
format_audit = audit_module["format_audit"]
audit = audit_module["audit"]
prepare = audit_module["prepare"]


@pytest.mark.parametrize("name", ["renderer", "@scope/renderer"])
def test_pnpm_peer_qualified_lock_records_canonical_affected_version(
    pnpm_project, monkeypatch, name
):
    lockfile = pnpm_project / "pnpm-lock.yaml"
    lock = yaml.safe_load(lockfile.read_bytes())
    lock["packages"] = {f"{name}@1.0.0(peer@2.0.0)": {}}
    lockfile.write_text(yaml.safe_dump(lock))

    def invoke(command, **kwargs):
        return subprocess.CompletedProcess(
            command,
            1,
            json.dumps(
                {
                    "metadata": {"vulnerabilities": {"high": 1, "total": 1}},
                    "advisories": {
                        "peer-advisory": {
                            "module_name": name,
                            "severity": "high",
                            "title": "Peer-qualified advisory",
                            "url": "https://github.com/advisories/peer-advisory",
                            "vulnerable_versions": "<1.0.1",
                            "patched_versions": ">=1.0.1",
                            "findings": [{"version": "1.0.0"}],
                        }
                    },
                }
            ),
            "",
        )

    monkeypatch.setattr(subprocess, "run", invoke)
    snapshot = audit_module["valid_snapshot"](pnpm_project)
    report = format_remaining_audit(audit(pnpm_project), snapshot[3])
    assert f"locked `{name}@1.0.0`;" in report
    assert "not recorded in lockfile" not in report


@pytest.mark.parametrize(
    ("first_versions", "second_versions"),
    [(["1.0.0"], ["2.0.0"]), (["1.0.0", "2.0.0"], ["2.0.0"]), ([], ["2.0.0"])],
)
def test_pnpm_remaining_versions_are_scoped_to_each_advisory(
    pnpm_project, monkeypatch, first_versions, second_versions
):
    lockfile = pnpm_project / "pnpm-lock.yaml"
    lock = yaml.safe_load(lockfile.read_bytes())
    lock["packages"]["renderer@2.0.0"] = {}
    lockfile.write_text(yaml.safe_dump(lock))
    advisories = {
        name: {
            "module_name": "renderer",
            "severity": "high",
            "title": name,
            "url": f"https://github.com/advisories/{name}",
            "vulnerable_versions": "*",
            "patched_versions": "<0.0.0",
            "findings": [{"version": version} for version in versions],
        }
        for name, versions in (("first", first_versions), ("second", second_versions))
    }

    def invoke(command, **kwargs):
        return subprocess.CompletedProcess(
            command,
            1,
            json.dumps(
                {
                    "metadata": {"vulnerabilities": {"high": 2, "total": 2}},
                    "advisories": advisories,
                }
            ),
            "",
        )

    monkeypatch.setattr(subprocess, "run", invoke)
    data = audit(pnpm_project)
    report = format_remaining_audit(
        data, audit_module["valid_snapshot"](pnpm_project)[3]
    )

    for name, versions in (("first", first_versions), ("second", second_versions)):
        line = next(line for line in report.splitlines() if f"[{name}]" in line)
        expected = ", ".join(sorted(versions)) or "not recorded in lockfile"
        assert f"locked `renderer@{expected}`;" in line
    assert set(data["vulnerabilities"]["renderer"]["nodes"]) == {
        f"renderer@{version}" for version in first_versions + second_versions
    }


@pytest.mark.parametrize("changed", [False, True], ids=["unchanged", "changed"])
def test_pnpm_report_keeps_advisory_versions_in_complete_audit(
    pnpm_project, monkeypatch, changed
):
    before_versions = ("1.0.0", "2.0.0")
    after_versions = ("1.1.0", "2.1.0") if changed else before_versions
    lockfile = pnpm_project / "pnpm-lock.yaml"
    lock = yaml.safe_load(lockfile.read_bytes())
    lock["packages"] = {
        f"renderer@{version}": {} for version in (*before_versions, *after_versions)
    }
    lockfile.write_text(yaml.safe_dump(lock))

    def findings(versions):
        details = [
            ("First advisory", "first", versions[0]),
            ("Second advisory", "second", versions[1]),
        ]
        advisories = {
            key: {
                "module_name": "renderer",
                "severity": "high",
                "title": title,
                "url": f"https://github.com/advisories/{key}",
                "vulnerable_versions": "*",
                "patched_versions": "<0.0.0",
                "findings": [{"version": version}],
            }
            for title, key, version in details
        }
        return {
            "metadata": {"vulnerabilities": {"high": 2, "total": 2}},
            "advisories": advisories,
            "package_manager": "pnpm",
            "vulnerabilities": {
                "renderer": {
                    "severity": "high",
                    "range": "*",
                    "nodes": [f"renderer@{version}" for _, _, version in details],
                    "via": [
                        {
                            "title": title,
                            "url": f"https://github.com/advisories/{key}",
                            "severity": "high",
                            "range": "*",
                            "nodes": [f"renderer@{version}"],
                            "patchedRange": "<0.0.0",
                        }
                        for title, key, version in details
                    ],
                    "fixAvailable": False,
                }
            },
        }

    audit_results = iter(
        [findings(before_versions), findings(after_versions), findings(after_versions)]
    )

    def fake_audit(*args, **kwargs):
        return next(audit_results)

    module_globals = prepare.__globals__
    monkeypatch.setitem(module_globals, "audit", fake_audit)
    monkeypatch.setitem(
        module_globals,
        "fix_security",
        lambda *args, **kwargs: subprocess.CompletedProcess([], 0, "", ""),
    )
    monkeypatch.setitem(
        module_globals, "describe_pnpm_fixes", lambda *args, **kwargs: None
    )

    def fake_run(directory, *args, **kwargs):
        stdout = '"1.0.0"' if args[:1] == ("view",) else ""
        return subprocess.CompletedProcess(args, 0, stdout, "")

    monkeypatch.setitem(module_globals, "run", fake_run)
    report = prepare(pnpm_project)

    for title, before_version, after_version in (
        ("First advisory", before_versions[0], after_versions[0]),
        ("Second advisory", before_versions[1], after_versions[1]),
    ):
        lines = [line for line in report.splitlines() if f"[{title}]" in line]
        assert lines
        assert any(f"locked `renderer@{before_version}`" in line for line in lines)
        assert any(f"locked `renderer@{after_version}`" in line for line in lines)


def fake_npm(monkeypatch, *, install=0, build=0, audit_error=False):
    def invoke(command, *, cwd, **kwargs):
        args = command[4:]
        stdout, code = "", 0
        if args[0] == "view":
            stdout = '"2.0.0"'
        elif args[0] == "install":
            (cwd / "package-lock.json").write_text('{"candidate": true}')
        elif args[0] == "ci":
            code = install
        elif args[:2] == ["run", "build"]:
            code = build
        elif args[:2] == ["audit", "--json"]:
            code = 1
            stdout = json.dumps(
                {"error": {"code": "ENETUNREACH"}}
                if audit_error
                else {
                    "metadata": {"vulnerabilities": {"total": 0}},
                    "vulnerabilities": {},
                }
            )
        return subprocess.CompletedProcess(command, code, stdout, "")

    monkeypatch.setattr(subprocess, "run", invoke)


def test_remaining_summary_deduplicates_propagated_advisories():
    advisory = {
        "title": "Nested pattern exhaustion",
        "url": "https://github.com/advisories/GHSA-example",
        "severity": "high",
        "range": "<=3.0.3",
    }
    data = {
        "metadata": {"vulnerabilities": {"high": 3, "total": 3}},
        "vulnerabilities": {
            "braces": {
                "nodes": ["node_modules/braces"],
                "via": [advisory, advisory],
            },
            "micromatch": {"via": ["braces"]},
            "docusaurus": {"via": ["micromatch"]},
        },
    }
    lock = {"packages": {"node_modules/braces": {"version": "3.0.3"}}}

    report = format_remaining_audit(data, lock)

    assert report.count("https://github.com/advisories/GHSA-example") == 1
    assert "braces@3.0.3" in report
    assert "high: 3, total: 3" in report
    assert "not distinct advisory counts" in report
    assert "docusaurus" not in report


def test_remaining_summary_prioritizes_severity():
    data = {
        "metadata": {"vulnerabilities": {"low": 1, "critical": 1, "total": 2}},
        "vulnerabilities": {
            name: {
                "via": [
                    {
                        "title": name,
                        "url": f"https://github.com/advisories/{name}",
                        "severity": severity,
                        "range": "*",
                    }
                ]
            }
            for name, severity in (("low-issue", "low"), ("urgent", "critical"))
        },
    }

    report = format_remaining_audit(data, {})

    assert report.index("[urgent]") < report.index("[low-issue]")


@pytest.mark.parametrize(
    "data, expected",
    [
        ("Audit unavailable (exit 124).", "Audit unavailable"),
        (
            {"metadata": {"vulnerabilities": {"total": 0}}},
            "No known vulnerabilities reported by npm.",
        ),
        (
            {
                "metadata": {"vulnerabilities": {"high": 1, "total": 1}},
                "vulnerabilities": {"parent": {"via": ["child"]}},
            },
            "npm supplied no direct advisory details",
        ),
    ],
)
def test_remaining_summary_reports_unavailable_and_incomplete_evidence(data, expected):
    assert expected in format_remaining_audit(data, {})


def test_reusable_workflow_uses_the_configured_project():
    workflow = load_workflow()
    assert "workflow_call" in workflow.get("on", workflow.get(True))
    publisher = workflow["jobs"]["pull-request"]["steps"][-1]
    assert (
        publisher["env"]["PR_TITLE"]
        == "Docusaurus maintenance: security audit and dependency upgrades"
    )
    assert "inputs.directory" not in json.dumps(workflow)
    assert "Landscape" not in json.dumps(workflow)
    reader = next(
        step
        for step in workflow["jobs"]["audit"]["steps"]
        if step.get("name") == "Read project configuration"
    )
    assert "runtime/project.py" in reader["run"]


def test_publisher_uses_the_audited_revision_and_default_branch_base():
    workflow = load_workflow()
    for job in ("audit", "pull-request"):
        checkout = next(
            step
            for step in workflow["jobs"][job]["steps"]
            if step.get("uses", "").startswith("actions/checkout@")
        )
        assert checkout["with"]["ref"] == "${{ github.sha }}"
    publisher = workflow["jobs"]["pull-request"]["steps"][-1]
    assert (
        publisher["env"]["BASE_BRANCH"]
        == "${{ github.event.repository.default_branch }}"
    )
    assert '--base "$BASE_BRANCH"' in publisher["run"]


@pytest.mark.parametrize("failure", [None, "fetch", "checkout", "changed", "compare"])
def test_publisher_refreshes_base_and_rejects_stale_or_unreadable_inputs(
    tmp_path, failure
):
    workflow = load_workflow()
    steps = workflow["jobs"]["pull-request"]["steps"]
    guard = next(
        step for step in steps if step.get("name") == "Verify audit dependency state"
    )
    guard_index = steps.index(guard)
    assert all(
        "download-artifact@" not in step.get("uses", "") for step in steps[:guard_index]
    )
    executable = tmp_path / "git"
    executable.write_text(
        "#!/bin/sh\n"
        'printf "%s\\n" "$*" >> "$COMMAND_LOG"\n'
        'case "$1:$FAILURE" in\n'
        "  fetch:fetch|checkout:checkout) exit 2 ;;\n"
        "  diff:changed) exit 1 ;;\n"
        "  diff:compare) exit 2 ;;\n"
        "esac\n"
        "exit 0\n"
    )
    executable.chmod(0o755)
    command_log = tmp_path / "commands.log"
    result = subprocess.run(
        ["bash", "-c", guard["run"]],
        env=dict(
            os.environ,
            PATH=f"{tmp_path}{os.pathsep}{os.environ['PATH']}",
            COMMAND_LOG=str(command_log),
            FAILURE=failure or "",
            AUDIT_SHA="audited-revision",
            BASE_BRANCH="main",
            NPM_PROJECT="website",
        ),
        capture_output=True,
        text=True,
    )
    commands = command_log.read_text().splitlines()
    assert commands[0] == "fetch --no-tags origin main:refs/remotes/origin/main"
    assert (result.returncode == 0) == (failure is None)
    if failure != "fetch":
        assert commands[1] == "checkout --detach refs/remotes/origin/main"
    if failure in (None, "changed", "compare"):
        assert commands[-1] == "diff --quiet audited-revision HEAD -- ."


@pytest.fixture
def npm_project(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"renderer": "1.0.0"}})
    )
    (tmp_path / "package-lock.json").write_text('{"lockfileVersion": 3}')
    return tmp_path


@pytest.mark.parametrize(
    "changed_path",
    [
        "website/docusaurus.config.js",
        "website/scripts/test-security-patches.mjs",
        "landscape.yaml",
        "docs/example.md",
    ],
)
def test_publisher_rejects_changed_non_package_build_inputs(tmp_path, changed_path):
    workflow = load_workflow()
    guard = next(
        step
        for step in workflow["jobs"]["pull-request"]["steps"]
        if step.get("name") == "Verify audit dependency state"
    )
    remote = tmp_path / "origin.git"
    subprocess.run(
        ["git", "init", "--bare", str(remote)], check=True, capture_output=True
    )
    checkout = tmp_path / "checkout"
    checkout.mkdir()

    def git(*args):
        return subprocess.run(
            [
                "git",
                "-C",
                str(checkout),
                "-c",
                "user.name=Audit test",
                "-c",
                "user.email=audit@example.invalid",
                *args,
            ],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    git("init", "-b", "main")
    git("remote", "add", "origin", str(remote))
    package = checkout / "website/package.json"
    package.parent.mkdir()
    package.write_text("{}\n")
    build_input = checkout / changed_path
    build_input.parent.mkdir(parents=True, exist_ok=True)
    build_input.write_text("audited input\n")
    git("add", ".")
    git("commit", "-m", "Audited source")
    audited = git("rev-parse", "HEAD")
    build_input.write_text("changed after audit\n")
    git("add", ".")
    git("commit", "-m", "Changed build input")
    git("push", "origin", "main")
    result = subprocess.run(
        ["bash", "-c", guard["run"]],
        cwd=checkout,
        env=dict(
            os.environ, AUDIT_SHA=audited, BASE_BRANCH="main", NPM_PROJECT="website"
        ),
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "rerun the audit" in result.stdout


@pytest.mark.parametrize("package_manager", ["npm", "pnpm"])
@pytest.mark.parametrize(
    ("initial_patched", "final_patched", "changed"),
    [("1.0.0", "1.0.1", True), ("1.0.1", "1.0.1", False), ("1.0.1", "1.0.2", True)],
)
def test_summary_reports_partial_security_lock_upgrades(
    request, monkeypatch, package_manager, initial_patched, final_patched, changed
):
    project = request.getfixturevalue(f"{package_manager}_project")
    (project / "package.json").write_text('{"dependencies": {}}')
    lockfile = project / (
        "pnpm-lock.yaml" if package_manager == "pnpm" else "package-lock.json"
    )
    lock = (
        yaml.safe_load(lockfile.read_text())
        if package_manager == "pnpm"
        else json.loads(lockfile.read_text())
    )

    def write_lock(patched):
        if package_manager == "pnpm":
            lock["packages"] = {"leaf@1.0.0": {}, f"leaf@{patched}": {}}
            lockfile.write_text(yaml.safe_dump(lock))
        else:
            lock["packages"] = {
                "node_modules/first/node_modules/leaf": {"version": "1.0.0"},
                "node_modules/second/node_modules/leaf": {"version": patched},
            }
            lockfile.write_text(json.dumps(lock))

    write_lock(initial_patched)

    def invoke(command, *, cwd, **kwargs):
        args = command[5:] if package_manager == "pnpm" else command[4:]
        if args[:2] in (["audit", "fix"], ["audit", "--fix=update"]):
            write_lock(final_patched)
        stdout = ""
        if args[:2] == ["audit", "--json"]:
            if package_manager == "pnpm":
                data = {
                    "metadata": {"vulnerabilities": {"high": 1, "total": 1}},
                    "advisories": {
                        "leaf-advisory": {
                            "module_name": "leaf",
                            "severity": "high",
                            "title": "Leaf advisory",
                            "url": "https://github.com/advisories/leaf-advisory",
                            "vulnerable_versions": "<1.0.1",
                            "patched_versions": ">=1.0.1",
                            "findings": [{"version": "1.0.0"}],
                        }
                    },
                }
            else:
                data = {
                    "metadata": {"vulnerabilities": {"high": 1, "total": 1}},
                    "vulnerabilities": {
                        "leaf": {
                            "severity": "high",
                            "range": "<1.0.1",
                            "fixAvailable": True,
                            "nodes": [
                                node
                                for node, package in lock["packages"].items()
                                if package["version"] == "1.0.0"
                            ],
                            "via": [],
                        }
                    },
                }
            stdout = json.dumps(data)
        return subprocess.CompletedProcess(command, 0, stdout, "")

    monkeypatch.setattr(subprocess, "run", invoke)
    summary = prepare(project).split("<summary>Full before/after")[0]

    if changed:
        old = ", ".join(sorted({"1.0.0", initial_patched}))
        new = ", ".join(sorted({"1.0.0", final_patched}))
        assert (
            f"leaf: `{old}` → `{new}`; still reported by {package_manager}." in summary
        )
        assert "No upgrades to affected dependencies resolved." not in summary
    else:
        assert "- leaf:" not in summary
        assert "## Security findings and fixes" not in summary


@pytest.mark.parametrize("package_manager", ["npm", "pnpm"])
@pytest.mark.parametrize("changed", [False, True])
def test_summary_reports_path_changes_with_unchanged_version_sets(
    request, monkeypatch, package_manager, changed
):
    project = request.getfixturevalue(f"{package_manager}_project")
    (project / "package.json").write_text('{"dependencies": {}}')
    lockfile = project / (
        "pnpm-lock.yaml" if package_manager == "pnpm" else "package-lock.json"
    )
    lock = (
        yaml.safe_load(lockfile.read_text())
        if package_manager == "pnpm"
        else json.loads(lockfile.read_text())
    )
    if package_manager == "pnpm":
        lock["packages"] = {"leaf@1.0.0": {}, "leaf@2.0.0": {}}
        lock["snapshots"] = {
            "first@1.0.0": {"dependencies": {"leaf": "1.0.0"}},
            "second@1.0.0": {"dependencies": {"leaf": "1.0.0"}},
            "third@1.0.0": {"dependencies": {"leaf": "2.0.0"}},
            "leaf@1.0.0": {},
            "leaf@2.0.0": {},
        }
    else:
        lock["packages"] = {
            "node_modules/first/node_modules/leaf": {"version": "1.0.0"},
            "node_modules/second/node_modules/leaf": {"version": "1.0.0"},
            "node_modules/third/node_modules/leaf": {"version": "2.0.0"},
        }

    def save_lock():
        lockfile.write_text(
            yaml.safe_dump(lock) if package_manager == "pnpm" else json.dumps(lock)
        )

    save_lock()

    def invoke(command, *, cwd, **kwargs):
        args = command[5:] if package_manager == "pnpm" else command[4:]
        if changed and args[:2] in (["audit", "fix"], ["audit", "--fix=update"]):
            if package_manager == "pnpm":
                lock["snapshots"]["first@1.0.0"]["dependencies"]["leaf"] = "2.0.0"
            else:
                lock["packages"]["node_modules/first/node_modules/leaf"]["version"] = (
                    "2.0.0"
                )
            save_lock()
        stdout = ""
        if args[:2] == ["audit", "--json"]:
            data = {"metadata": {"vulnerabilities": {"high": 1, "total": 1}}}
            if package_manager == "pnpm":
                data["advisories"] = {
                    "leaf-advisory": {
                        "module_name": "leaf",
                        "severity": "high",
                        "title": "Leaf advisory",
                        "url": "https://github.com/advisories/leaf-advisory",
                        "vulnerable_versions": "<2.0.0",
                        "patched_versions": ">=2.0.0",
                        "findings": [{"version": "1.0.0"}],
                    }
                }
            else:
                data["vulnerabilities"] = {
                    "leaf": {
                        "severity": "high",
                        "range": "<2.0.0",
                        "fixAvailable": True,
                        "nodes": [
                            node
                            for node, package in lock["packages"].items()
                            if package["version"] == "1.0.0"
                        ],
                        "via": [],
                    }
                }
            stdout = json.dumps(data)
        return subprocess.CompletedProcess(command, 0, stdout, "")

    monkeypatch.setattr(subprocess, "run", invoke)
    summary = prepare(project).split("<summary>Full before/after")[0]
    if changed:
        assert (
            "leaf: dependency paths changed; installed versions `1.0.0, 2.0.0`"
            in summary
        )
        assert f"still reported by {package_manager}." in summary
        assert "No upgrades to affected dependencies resolved." not in summary
    else:
        assert "- leaf:" not in summary
        assert "## Security findings and fixes" not in summary


@pytest.mark.parametrize("package_manager", ["npm", "pnpm"])
@pytest.mark.parametrize("patched", [False, True])
def test_summary_uses_final_manifest_and_stable_phase_security_findings(
    request, monkeypatch, package_manager, patched
):
    project = request.getfixturevalue(f"{package_manager}_project")
    manifest_path = project / "package.json"
    fixes = 0

    def save_version(version):
        manifest = json.loads(manifest_path.read_text())
        manifest["dependencies"]["renderer"] = version
        manifest_path.write_text(json.dumps(manifest))
        if package_manager == "pnpm":
            lock = {
                "lockfileVersion": "9.0",
                "importers": {
                    ".": {
                        "dependencies": {
                            "renderer": {
                                "specifier": version,
                                "version": version,
                            }
                        }
                    }
                },
                "packages": {f"renderer@{version}": {}},
            }
            (project / "pnpm-lock.yaml").write_text(yaml.safe_dump(lock))
        else:
            (project / "package-lock.json").write_text(
                json.dumps(
                    {
                        "lockfileVersion": 3,
                        "packages": {"node_modules/renderer": {"version": version}},
                    }
                )
            )

    save_version("1.0.0")

    def invoke(command, *, cwd, **kwargs):
        nonlocal fixes
        args = command[5:] if package_manager == "pnpm" else command[4:]
        stdout = ""
        if args[0] == "view":
            stdout = (
                json.dumps({"2.0.0": "2000-01-01T00:00:00Z"})
                if "time" in args
                else '"2.0.0"'
            )
        elif args[0] == "install" and "--frozen-lockfile" not in args:
            save_version(
                json.loads(manifest_path.read_text())["dependencies"]["renderer"]
            )
        elif args[:2] in (["audit", "fix"], ["audit", "--fix=update"]):
            fixes += 1
            if fixes == 2 and patched:
                save_version("3.0.0")
        elif args[:2] == ["audit", "--json"]:
            vulnerable = (
                json.loads(manifest_path.read_text())["dependencies"]["renderer"]
                == "2.0.0"
            )
            data = {
                "metadata": {
                    "vulnerabilities": {
                        "high": int(vulnerable),
                        "total": int(vulnerable),
                    }
                }
            }
            if package_manager == "pnpm":
                data["advisories"] = (
                    {
                        "stable-issue": {
                            "module_name": "renderer",
                            "severity": "high",
                            "title": "Stable issue",
                            "url": "https://github.com/advisories/stable-issue",
                            "vulnerable_versions": "2.0.0",
                            "patched_versions": ">=3.0.0",
                            "findings": [{"version": "2.0.0"}],
                        }
                    }
                    if vulnerable
                    else {}
                )
            else:
                data["vulnerabilities"] = (
                    {
                        "renderer": {
                            "severity": "high",
                            "range": "2.0.0",
                            "fixAvailable": True,
                            "nodes": ["node_modules/renderer"],
                            "via": [],
                        }
                    }
                    if vulnerable
                    else {}
                )
            stdout = json.dumps(data)
        return subprocess.CompletedProcess(command, 0, stdout, "")

    monkeypatch.setattr(subprocess, "run", invoke)
    summary = prepare(project).split("<summary>Full before/after")[0]
    security = summary.split("## Locked dependency changes")[0]
    final = "3.0.0" if patched else "2.0.0"
    assert f"- renderer: `1.0.0` → `{final}`;" in security
    assert "## Other stable dependency upgrades" not in summary
    assert (
        "still reported" in security
        if not patched
        else "no longer reported" in security
    )
    assert json.loads(manifest_path.read_text())["dependencies"]["renderer"] == final


@pytest.mark.parametrize(
    "section", ["dependencies", "devDependencies", "optionalDependencies"]
)
def test_multiple_stable_candidates_preserve_security_snapshot(
    pnpm_project, monkeypatch, section
):
    manifest_path = pnpm_project / "package.json"
    manifest = json.loads(manifest_path.read_text())
    manifest.setdefault(section, {})["second"] = "^1.0.0"
    manifest_path.write_text(json.dumps(manifest))
    lockfile = pnpm_project / "pnpm-lock.yaml"
    lock = yaml.safe_load(lockfile.read_text())
    lock["importers"]["."].setdefault(section, {})["second"] = {
        "specifier": "^1.0.0",
        "version": "1.0.0",
    }
    lock["packages"]["second@1.0.0"] = {}
    lockfile.write_text(yaml.safe_dump(lock))

    def invoke(command, *, cwd, **kwargs):
        args = command[5:]
        stdout = ""
        if args[:2] == ["audit", "--json"]:
            stdout = json.dumps(
                {"metadata": {"vulnerabilities": {"total": 0}}, "advisories": {}}
            )
        elif args[0] == "view":
            stdout = (
                json.dumps({"2.0.0": "2000-01-01T00:00:00Z"})
                if "time" in args
                else '"2.0.0"'
            )
        elif args[0] == "install" and "--lockfile-only" in args:
            proposal = json.loads(manifest_path.read_text())
            lock["packages"] = {}
            for group in ("dependencies", "devDependencies", "optionalDependencies"):
                for name, specifier in proposal.get(group, {}).items():
                    version = specifier.lstrip("~^")
                    lock["importers"]["."].setdefault(group, {})[name] = {
                        "specifier": specifier,
                        "version": version,
                    }
                    lock["packages"][f"{name}@{version}"] = {}
            lockfile.write_text(yaml.safe_dump(lock))
        return subprocess.CompletedProcess(command, 0, stdout, "")

    monkeypatch.setattr(subprocess, "run", invoke)
    summary = prepare(pnpm_project).split("<summary>Full before/after")[0]
    result = json.loads(manifest_path.read_text())
    assert result["dependencies"]["renderer"] == "2.0.0"
    assert result[section]["second"] == "2.0.0"
    assert "changed protected pnpm policy" not in summary
    assert "second: `^1.0.0` → `2.0.0`" in summary


@pytest.mark.parametrize("context", ["importer", "alias", "peers"])
def test_pnpm_path_comparison_retains_scoped_context_and_ignores_metadata(context):
    name = "@scope/leaf"
    lock = {
        "packages": {f"{name}@1.0.0": {}, f"{name}@2.0.0": {}},
        "importers": {".": {"dependencies": {name: {"version": "1.0.0"}}}},
        "snapshots": {
            "parent@1.0.0": {"optionalDependencies": {"alias": f"{name}@1.0.0"}},
            f"{name}@1.0.0(peer@1.0.0)": {},
        },
    }
    paths = audit_module["package_paths"]
    original = paths(lock, name, "pnpm")
    lock["packages"][f"{name}@1.0.0"]["resolution"] = {"integrity": "metadata-only"}
    assert paths(lock, name, "pnpm") == original
    if context == "importer":
        lock["importers"]["."]["dependencies"][name]["version"] = "2.0.0"
    elif context == "alias":
        lock["snapshots"]["parent@1.0.0"]["optionalDependencies"]["alias"] = (
            f"{name}@2.0.0"
        )
    else:
        lock["snapshots"][f"{name}@1.0.0(peer@2.0.0)"] = lock["snapshots"].pop(
            f"{name}@1.0.0(peer@1.0.0)"
        )
    assert paths(lock, name, "pnpm") != original
    assert set(lock["packages"]) == {f"{name}@1.0.0", f"{name}@2.0.0"}


def test_summary_precedes_collapsed_full_audit(npm_project, monkeypatch):
    fake_npm(monkeypatch)

    report = prepare(npm_project)
    summary, details = report.split("<details>", 1)

    assert "**Changes:** 1 direct / 0 locked dependencies." in summary
    assert "🟢 **Remaining:** 0 affected package entries." in summary
    assert "⚪ **Resolved:** none." in summary
    assert "## Production build\n\nPassed." in summary
    assert len(summary) < 600
    assert "renderer: `1.0.0` → `2.0.0`" in details
    assert "No upgrades to affected dependencies" not in report
    assert "No additional tool errors recorded" not in report
    assert "This is a best-effort" not in report
    assert "### Before" not in summary and "### After" not in summary
    assert "Before and after findings are unchanged." in details
    assert details.endswith("</details>\n")
    assert not (npm_project / "dependency-audit.md").exists()


@pytest.mark.parametrize(
    "package_manager, label",
    [("pnpm", "registry advisories"), ("npm", "affected package entries")],
)
def test_compact_security_summary_keeps_severity_and_count_meaning(
    package_manager, label
):
    summarize = audit_module["format_audit_summary"]
    before = {"metadata": {"vulnerabilities": {"critical": 3, "high": 2, "total": 5}}}
    after = {
        "metadata": {
            "vulnerabilities": {"critical": 2, "high": 1, "moderate": 1, "total": 4}
        }
    }
    result = summarize(before, after, package_manager)
    assert f"**Remaining:** 4 {label} (2 critical, 1 high, 1 moderate)." in result
    assert "**Resolved:** unconfirmed" in result
    assert "Audit unavailable" in summarize(
        before, "Audit unavailable (exit 1).", package_manager
    )


def test_unchanged_findings_are_rendered_once(npm_project, monkeypatch):
    fake_npm(monkeypatch)
    report = prepare(npm_project)
    assert report.count("No known vulnerabilities reported by npm.") == 1
    assert report.count("<details>") == report.count("</details>")


@pytest.fixture
def security_findings():
    def make(rows):
        data = {"metadata": {"vulnerabilities": {}}, "vulnerabilities": {}}
        counts = data["metadata"]["vulnerabilities"]
        for name, identity, severity, status in rows:
            counts[severity] = counts.get(severity, 0) + 1
            package = data["vulnerabilities"].setdefault(name, {"via": []})
            package["via"].append(
                {
                    "url": f"https://github.com/advisories/{identity}",
                    "severity": severity,
                    "fixStatus": status,
                }
            )
        return data

    return make


def test_security_outcomes_distinguish_resolved_and_new_with_equal_counts(
    security_findings,
):
    before = security_findings([("old-package", "old", "high", "")])
    after = security_findings([("new-package", "new", "high", "")])
    result = audit_module["format_audit_summary"](before, after, "pnpm")
    assert "**Resolved:** 1 (`old-package`)" in result
    assert "**New:** 1 (`new-package`)" in result
    assert "**Remaining:** 1 registry advisory" in result


def test_security_outcomes_keep_shared_advisory_open_after_path_change(
    security_findings,
):
    before = security_findings([("old-path", "same", "critical", "")])
    after = security_findings([("new-path", "same", "critical", "")])
    result = audit_module["format_audit_summary"](before, after, "pnpm")
    assert "**Resolved:** none." in result
    assert "**New:**" not in result


def test_security_outcomes_report_partial_resolution_for_one_package(security_findings):
    first = ("leaf", "first", "high", "")
    second = ("leaf", "second", "high", "")
    result = audit_module["format_audit_summary"](
        security_findings([first, second]), security_findings([first]), "pnpm"
    )
    assert "**Resolved:** 1 (`leaf`)" in result
    assert "**Remaining:** 1 registry advisory" in result
    assert "| `leaf` (1 high) |" in result


def test_security_outcomes_keep_missing_initial_evidence_unconfirmed(security_findings):
    result = audit_module["format_audit_summary"](
        "Audit unavailable", security_findings([]), "pnpm"
    )
    assert "**Resolved:** unconfirmed" in result
    assert "**Resolved:** none" not in result


def test_security_outcomes_summarize_concrete_blockers(security_findings):
    constraints = "Published patches exist, but no single patch satisfies all checked parent constraints. Blocked by existing parent constraints: `@docusaurus/core@3.10.2` requires `tinypool ^1.0.2`."
    before = security_findings(
        [
            ("tinypool", "first", "critical", constraints),
            ("tinypool", "second", "critical", constraints),
            (
                "braces",
                "third",
                "high",
                "No published stable patch matches registry range `>=3.0.4`.",
            ),
        ]
    )
    result = audit_module["format_audit_summary"](before, before, "pnpm")
    assert (
        "| `tinypool` (2 critical) | Blocked by the `@docusaurus/core` version constraint. |"
        in result
    )
    assert "No published patch matches the fix range." in result
    assert result.count("| `tinypool`") == 1


def test_security_outcomes_bound_the_visible_package_list(security_findings):
    data = security_findings([(f"package-{i}", str(i), "high", "") for i in range(7)])
    result = audit_module["format_audit_summary"](data, data, "pnpm")
    assert "**Remaining:** 7 registry advisories" in result
    assert "2 more affected packages are listed in the audit details." in result
    assert result.count("| `package-") == 5


def test_publisher_footer_is_only_a_run_link():
    workflow = load_workflow()
    footer = workflow["jobs"]["pull-request"]["steps"][-1]["env"]["PR_FOOTER"]
    assert footer.strip() == (
        "[Workflow run](${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }})"
    )


@pytest.mark.parametrize("install, build", [(1, 0), (0, 1)])
def test_summary_keeps_failed_validation_visible(
    npm_project, monkeypatch, install, build
):
    fake_npm(monkeypatch, install=install, build=build, audit_error=True)

    summary = prepare(npm_project).split("<details>")[0]

    assert "Audit unavailable" in summary
    assert "No known vulnerabilities" not in summary
    assert "Passed." not in summary
    assert "failed" in summary.lower()


def test_summary_marks_security_fix_unconfirmed_when_initial_audit_is_unavailable(
    pnpm_project, monkeypatch
):
    fixes = 0

    def invoke(command, *, cwd, **kwargs):
        nonlocal fixes
        args = command[5:]
        if args[:2] == ["audit", "--json"]:
            if fixes:
                return subprocess.CompletedProcess(
                    command,
                    0,
                    json.dumps(
                        {
                            "metadata": {"vulnerabilities": {"total": 0}},
                            "advisories": {},
                        }
                    ),
                    "",
                )
            return subprocess.CompletedProcess(
                command,
                1,
                json.dumps(
                    {"metadata": {"vulnerabilities": {"high": 1}}, "advisories": []}
                ),
                "",
            )
        if args[:2] == ["audit", "--fix=update"]:
            fixes += 1
            lockfile = cwd / "pnpm-lock.yaml"
            lock = yaml.safe_load(lockfile.read_bytes())
            lock["packages"] = {"renderer@1.0.1": {}}
            lockfile.write_text(yaml.safe_dump(lock))
        elif args[0] == "view":
            return subprocess.CompletedProcess(command, 0, '"1.0.0"', "")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(subprocess, "run", invoke)
    report = prepare(pnpm_project)
    summary = report.split("<details>")[0]

    assert "Initial audit evidence was unavailable" in summary
    assert "retained security-fix changes are unconfirmed" in summary
    assert "No upgrades to affected dependencies resolved." not in summary
    assert "No additional tool errors recorded." not in summary
    assert (
        "## Remaining advisories\n\nNo known vulnerabilities reported by pnpm."
        in report
    )


@pytest.mark.parametrize("mutation", ["audit-fix", "install", "ci", "build", "missing"])
def test_failed_mutation_restores_valid_files_and_reports_partial_work(
    npm_project, monkeypatch, mutation
):
    calls = {"audit-fix": 0}

    def invoke(command, *, cwd, **kwargs):
        args = command[4:]
        stdout, code = "", 0
        if args[0] == "view":
            stdout = '"2.0.0"'
        elif args[:2] == ["audit", "fix"]:
            calls["audit-fix"] += 1
            if mutation in {"audit-fix", "missing"} and calls["audit-fix"] == 1:
                if mutation == "missing":
                    (cwd / "package-lock.json").unlink()
                else:
                    (cwd / "package-lock.json").write_text("{")
                code = 124
        elif args[0] == "install":
            (cwd / "package-lock.json").write_text(
                "{" if mutation == "install" else '{"candidate": true}'
            )
            code = 0
        elif args[0] == "ci":
            if mutation == "ci":
                (cwd / "package.json").write_text("{")
                code = 1
        elif args[:2] == ["run", "build"]:
            if mutation == "build":
                (cwd / "package.json").write_text("{")
                code = 1
        elif args[:2] == ["audit", "--json"]:
            code = 1
            stdout = json.dumps(
                {
                    "metadata": {"vulnerabilities": {"total": 0}},
                    "vulnerabilities": {},
                }
            )
        return subprocess.CompletedProcess(command, code, stdout, "")

    monkeypatch.setattr(subprocess, "run", invoke)

    report = prepare(npm_project)

    json.loads((npm_project / "package.json").read_text())
    json.loads((npm_project / "package-lock.json").read_text())
    assert "restored" in report
    assert "did not claim its changes" in report or "failed" in report.lower()
    if mutation == "install":
        assert "renderer: `1.0.0` → `2.0.0`" not in report


@pytest.fixture
def pnpm_project(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps(
            {"packageManager": "pnpm@11.21.0", "dependencies": {"renderer": "^1.0.0"}}
        )
    )
    (tmp_path / "pnpm-lock.yaml").write_text(
        yaml.safe_dump(
            {
                "lockfileVersion": "9.0",
                "importers": {".": {}},
                "packages": {"renderer@1.0.0": {}},
            }
        )
    )
    (tmp_path / "pnpm-workspace.yaml").write_text(
        yaml.safe_dump(
            {
                "packages": ["."],
                "minimumReleaseAge": 14400,
                "minimumReleaseAgeExclude": ["other@3.0.0"],
                "blockExoticSubdeps": True,
                "strictDepBuilds": True,
                "allowBuilds": {"core-js": False},
                "overrides": {"other": "3.0.0"},
                "resolutionMode": "highest",
            }
        )
    )
    return tmp_path


@pytest.mark.parametrize("failure", [None, "stable", "policy", "frozen"])
def test_pnpm_security_first_and_policy_restoration(pnpm_project, monkeypatch, failure):
    commands = []
    fixes = 0
    workspace = pnpm_project / "pnpm-workspace.yaml"
    lockfile = pnpm_project / "pnpm-lock.yaml"

    def invoke(command, *, cwd, **kwargs):
        nonlocal fixes
        assert command[3:5] == ["corepack", "pnpm"]
        args = command[5:]
        commands.append(args)
        stdout, code = "", 0
        if args[:2] == ["audit", "--json"]:
            stdout = json.dumps(
                {
                    "metadata": {"vulnerabilities": {"high": 1}},
                    "advisories": {
                        "123": {
                            "module_name": "renderer",
                            "severity": "high",
                            "title": "Render bug",
                            "url": "https://github.com/advisories/GHSA-render",
                            "vulnerable_versions": "<1.0.1",
                            "patched_versions": ">=1.0.1",
                            "findings": [
                                {"version": "1.0.0" if fixes == 0 else "1.0.1"}
                            ],
                        }
                    },
                }
            )
        elif args[:2] == ["audit", "--fix=update"]:
            fixes += 1
            policy = yaml.safe_load(workspace.read_text())
            exclusions = policy["minimumReleaseAgeExclude"]
            if "renderer@1.0.1" not in exclusions:
                exclusions.append("renderer@1.0.1")
            workspace.write_text(yaml.safe_dump(policy))
            locked = yaml.safe_load(lockfile.read_text())
            locked["packages"] = {"renderer@1.0.1": {}}
            lockfile.write_text(yaml.safe_dump(locked))
            if failure == "policy" and fixes == 1:
                workspace.write_text("[")
                code = 124
        elif args[0] == "view":
            stdout = (
                '{"2.0.0": "2020-01-01T00:00:00Z"}' if args[-2] == "time" else '"2.0.0"'
            )
        elif args[0] == "install" and "--lockfile-only" in args:
            if failure == "stable":
                workspace.write_text("[")
                lockfile.unlink()
                code = 1
        elif args == ["install", "--frozen-lockfile"] and failure == "frozen":
            (cwd / "package.json").write_text("{")
        return subprocess.CompletedProcess(command, code, stdout, "")

    monkeypatch.setattr(subprocess, "run", invoke)
    report = prepare(pnpm_project)
    policy = yaml.safe_load(workspace.read_text())
    assert policy["minimumReleaseAge"] == 14400
    assert policy["blockExoticSubdeps"] and policy["strictDepBuilds"]
    assert policy["allowBuilds"] == {"core-js": False}
    assert policy["overrides"] == {"other": "3.0.0"}
    assert commands.index(
        ["audit", "--fix=update", "--audit-level", "info", "--ignore-scripts"]
    ) < next(i for i, args in enumerate(commands) if args[0] == "view")
    assert "--force" not in str(commands)
    assert "pnpm" in report and "Render bug" in report
    assert "Registry advisory counts" in report
    assert "Full before/after pnpm audit" in report
    if failure == "stable":
        assert policy["minimumReleaseAgeExclude"] == ["other@3.0.0", "renderer@1.0.1"]
        assert "renderer: `^1.0.0` → `2.0.0`" not in report
        assert "renderer: `1.0.0` → `1.0.1`" in report
    if failure == "policy":
        assert "restored" in report and "exit 124" in report
    if failure == "frozen":
        assert "Not run: pnpm frozen install failed" in report
        assert ["run", "build"] not in commands


def test_info_advisory_is_reported_and_fix_attempt_includes_info(
    pnpm_project, monkeypatch
):
    commands = []
    response = {
        "metadata": {"vulnerabilities": {"info": 1, "total": 1}},
        "advisories": {
            "123": {
                "module_name": "renderer",
                "severity": "info",
                "title": "Informational renderer notice",
                "url": "https://github.com/advisories/GHSA-info",
                "vulnerable_versions": "<1.0.1",
                "patched_versions": ">=1.0.1",
                "findings": [{"version": "1.0.0"}],
            }
        },
    }

    def invoke(command, *, cwd, **kwargs):
        commands.append(command[5:])
        return subprocess.CompletedProcess(command, 1, json.dumps(response), "")

    monkeypatch.setattr(subprocess, "run", invoke)
    data = audit(pnpm_project)
    audit_module["fix_security"](pnpm_project, float("inf"), before=data)
    assert commands[:2] == [
        ["audit", "--json", "--audit-level", "info"],
        ["audit", "--fix=update", "--audit-level", "info", "--ignore-scripts"],
    ]
    resolution = next(args for args in commands[2:] if args[0] == "install")
    assert resolution[:4] == [
        "install",
        "--lockfile-only",
        "--no-frozen-lockfile",
        "--ignore-scripts",
    ]
    lock = audit_module["valid_snapshot"](pnpm_project)[3]
    for report in (format_remaining_audit(data, lock), format_audit(data, lock)):
        for detail in (
            "info",
            "Informational renderer notice",
            "https://github.com/advisories/GHSA-info",
            "<1.0.1",
            "1.0.0",
        ):
            assert detail in report


@pytest.mark.parametrize("mutation", ["severity", "via", "nodes", "fixAvailable"])
def test_audit_rejects_malformed_npm_vulnerability_details(
    npm_project, monkeypatch, mutation
):
    detail: Any = {
        "severity": "high",
        "range": "<1.0.1",
        "nodes": ["node_modules/renderer"],
        "via": [
            {
                "title": "Render bug",
                "url": "https://github.com/advisories/GHSA-render",
                "severity": "high",
                "range": "<1.0.1",
            }
        ],
        "fixAvailable": False,
    }
    if mutation == "severity":
        del detail["severity"]
    elif mutation == "via":
        del detail["via"][0]["range"]
    elif mutation == "nodes":
        detail["nodes"] = [None]
    else:
        detail["fixAvailable"] = {"name": 7}

    response = {
        "metadata": {"vulnerabilities": {"high": 1, "total": 1}},
        "vulnerabilities": {"renderer": detail},
    }
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(
            command, 1, json.dumps(response), ""
        ),
    )

    result = audit(npm_project)

    assert isinstance(result, str) and "unavailable" in result.lower()
    assert "unavailable" in format_audit(result, {}).lower()
    assert "unavailable" in format_remaining_audit(result, {}).lower()


@pytest.mark.parametrize(
    ("location", "severity"),
    [
        ("vulnerability", []),
        ("vulnerability", {}),
        ("via", []),
        ("via", {}),
    ],
)
def test_audit_rejects_non_scalar_npm_severity(
    npm_project, monkeypatch, location, severity
):
    detail: Any = {
        "severity": "high",
        "range": "<1.0.1",
        "nodes": ["node_modules/renderer"],
        "via": [
            {
                "title": "Render bug",
                "url": "https://github.com/advisories/GHSA-render",
                "severity": "high",
                "range": "<1.0.1",
            }
        ],
        "fixAvailable": False,
    }
    if location == "vulnerability":
        detail["severity"] = severity
    else:
        detail["via"][0]["severity"] = severity
    response = {
        "metadata": {"vulnerabilities": {"high": 1, "total": 1}},
        "vulnerabilities": {"renderer": detail},
    }
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(
            command, 1, json.dumps(response), ""
        ),
    )

    result = audit(npm_project)

    assert isinstance(result, str) and "unavailable" in result.lower()


@pytest.mark.parametrize(
    "counts",
    [
        {"high": 2, "total": 2},
        {"low": 1, "total": 1},
    ],
)
def test_audit_rejects_npm_count_mismatches(npm_project, monkeypatch, counts):
    response = {
        "metadata": {"vulnerabilities": counts},
        "vulnerabilities": {
            "renderer": {
                "severity": "high",
                "range": "<1.0.1",
                "nodes": ["node_modules/renderer"],
                "via": [
                    {
                        "title": "Render bug",
                        "url": "https://github.com/advisories/GHSA-render",
                        "severity": "high",
                        "range": "<1.0.1",
                    }
                ],
                "fixAvailable": False,
            }
        },
    }
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(
            command, 1, json.dumps(response), ""
        ),
    )

    result = audit(npm_project)

    assert isinstance(result, str) and "unavailable" in result.lower()


def test_audit_preserves_valid_npm_propagated_findings(npm_project, monkeypatch):
    response = {
        "metadata": {"vulnerabilities": {"high": 2, "total": 2}},
        "vulnerabilities": {
            "renderer": {
                "severity": "high",
                "range": "<1.0.1",
                "nodes": ["node_modules/renderer"],
                "via": [
                    {
                        "title": "Render bug",
                        "url": "https://github.com/advisories/GHSA-render",
                        "severity": "high",
                        "range": "<1.0.1",
                    }
                ],
                "fixAvailable": False,
            },
            "application": {
                "severity": "high",
                "range": "*",
                "nodes": ["node_modules/application"],
                "via": ["renderer"],
                "fixAvailable": False,
            },
        },
    }
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(
            command, 1, json.dumps(response), ""
        ),
    )

    result = audit(npm_project)

    assert isinstance(result, dict)
    assert result["vulnerabilities"]["application"]["via"] == ["renderer"]
    assert "GHSA-render" in format_remaining_audit(result, {})


@pytest.mark.parametrize("reverse", [False, True])
def test_pnpm_group_summary_is_order_independent(pnpm_project, monkeypatch, reverse):
    advisories = {
        "low": {
            "module_name": "renderer",
            "severity": "low",
            "title": "Low issue",
            "url": "https://github.com/advisories/GHSA-low",
            "vulnerable_versions": "<1.0.1",
            "patched_versions": ">=1.0.1",
            "findings": [{"version": "1.0.0"}],
        },
        "critical": {
            "module_name": "renderer",
            "severity": "critical",
            "title": "Critical issue",
            "url": "https://github.com/advisories/GHSA-critical",
            "vulnerable_versions": ">=2 <2.0.1",
            "patched_versions": ">=2.0.1",
            "findings": [{"version": "1.0.0"}],
        },
    }
    if reverse:
        advisories = dict(reversed(tuple(advisories.items())))
    response = {
        "metadata": {"vulnerabilities": {"low": 1, "critical": 1, "total": 2}},
        "advisories": advisories,
    }
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(
            command, 1, json.dumps(response), ""
        ),
    )

    result = audit(pnpm_project)

    assert isinstance(result, dict)
    summary = result["vulnerabilities"]["renderer"]
    assert summary["severity"] == "critical"
    assert summary["range"] == "<1.0.1 || >=2 <2.0.1"


@pytest.mark.parametrize("exit_code", [0, 1])
@pytest.mark.parametrize(
    "operation, field, value",
    [
        ("initial-audit", "minimumReleaseAge", 1),
        ("initial-fix", "overrides", {"other": "changed"}),
        ("view", "allowBuilds", {}),
        ("install", "blockExoticSubdeps", False),
        ("stable-audit", "minimumReleaseAge", 1),
        ("followup-fix", "strictDepBuilds", False),
        ("frozen", "minimumReleaseAgeExclude", ["unrelated@9.0.0"]),
        ("build", "resolutionMode", "lowest-direct"),
        ("final-audit", "audit", {"ignore": ["GHSA-hidden"]}),
    ],
)
def test_valid_policy_mutation_restores_all_package_files(
    pnpm_project, monkeypatch, operation, field, value, exit_code
):
    workspace = pnpm_project / "pnpm-workspace.yaml"
    files = {
        name: (pnpm_project / name).read_bytes()
        for name in ("package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml")
    }
    audits = fixes = 0
    mutated = False

    def invoke(command, *, cwd, **kwargs):
        nonlocal audits, fixes, mutated
        args = command[5:]
        stdout, boundary = "", None
        if args[:2] == ["audit", "--json"]:
            audits += 1
            boundary = ("initial-audit", "stable-audit", "final-audit")[audits - 1]
            stdout = json.dumps(
                {"metadata": {"vulnerabilities": {"total": 0}}, "advisories": {}}
            )
        elif args[:2] == ["audit", "--fix=update"]:
            fixes += 1
            boundary = "initial-fix" if fixes == 1 else "followup-fix"
        elif args[0] == "view":
            boundary, stdout = "view", '"1.0.0"'
        elif "--lockfile-only" in args:
            boundary = "install"
        elif args == ["install", "--frozen-lockfile"]:
            boundary = "frozen"
        elif args == ["run", "build"]:
            boundary = "build"
        if boundary == operation and not mutated:
            policy = yaml.safe_load(workspace.read_text())
            policy[field] = value
            workspace.write_text(yaml.safe_dump(policy))
            (cwd / "package.json").write_text(
                json.dumps({"packageManager": "pnpm@11.21.0", "dependencies": {}})
            )
            lockfile = cwd / "pnpm-lock.yaml"
            lock = yaml.safe_load(lockfile.read_text())
            lock["packages"] = {"unrelated@9.0.0": {}}
            lockfile.write_text(yaml.safe_dump(lock))
            mutated = True
            return subprocess.CompletedProcess(command, exit_code, stdout, "")
        return subprocess.CompletedProcess(command, 0, stdout, "")

    monkeypatch.setattr(subprocess, "run", invoke)
    report = prepare(pnpm_project)

    assert mutated
    for name, content in files.items():
        assert (pnpm_project / name).read_bytes() == content
    assert "changed protected pnpm policy" in report


@pytest.mark.parametrize("phase", ["initial", "followup"])
@pytest.mark.parametrize(
    "addition, accepted, retained",
    [
        ("renderer@1.0.1", True, True),
        ("renderer@2.0.0", True, False),
        ("@scope/safe@2.0.0", True, False),
        ("unrelated@3.0.0", True, False),
        ("renderer@*", False, False),
        ("renderer@1.0.1 || 2.0.0", True, True),
        (None, False, False),
    ],
)
def test_security_exclusions_require_each_fix_complete_normalized_lock_delta(
    pnpm_project, monkeypatch, phase, addition, accepted, retained
):
    workspace = pnpm_project / "pnpm-workspace.yaml"
    lockfile = pnpm_project / "pnpm-lock.yaml"
    original_policy = yaml.safe_load(workspace.read_text())
    baseline_packages = {
        "renderer@1.0.0": {},
        "renderer@2.0.0": {},
        "@scope/safe@2.0.0(peer@1.0.0)": {},
    }
    if phase == "initial":
        lock = yaml.safe_load(lockfile.read_text())
        lock["packages"] = baseline_packages
        lockfile.write_text(yaml.safe_dump(lock))
    fixes = 0

    def invoke(command, *, cwd, **kwargs):
        nonlocal fixes
        args = command[5:]
        stdout = ""
        if args[:2] == ["audit", "--json"]:
            stdout = json.dumps(
                {"metadata": {"vulnerabilities": {"total": 0}}, "advisories": {}}
            )
        elif args[0] == "view":
            stdout = '"1.0.0"'
        elif "--lockfile-only" in args and phase == "followup":
            lock = yaml.safe_load(lockfile.read_text())
            lock["packages"] = baseline_packages
            lockfile.write_text(yaml.safe_dump(lock))
        elif args[:2] == ["audit", "--fix=update"]:
            fixes += 1
            if fixes == (1 if phase == "initial" else 2):
                lock = yaml.safe_load(lockfile.read_text())
                lock["packages"].pop("renderer@1.0.0")
                lock["packages"]["renderer@1.0.1"] = {}
                lock["packages"].pop("@scope/safe@2.0.0(peer@1.0.0)")
                lock["packages"]["@scope/safe@2.0.0(peer@2.0.0)"] = {}
                lockfile.write_text(yaml.safe_dump(lock))
                policy = yaml.safe_load(workspace.read_text())
                if addition is None:
                    policy["minimumReleaseAgeExclude"] = []
                else:
                    policy["minimumReleaseAgeExclude"].append(addition)
                workspace.write_text(yaml.safe_dump(policy))
        return subprocess.CompletedProcess(command, 0, stdout, "")

    monkeypatch.setattr(subprocess, "run", invoke)
    report = prepare(pnpm_project)
    policy = yaml.safe_load(workspace.read_text())
    if retained:
        original_policy["minimumReleaseAgeExclude"].append("renderer@1.0.1")
    assert policy == original_policy
    packages = yaml.safe_load(lockfile.read_text())["packages"]
    assert ("renderer@1.0.1" in packages) == accepted
    assert ("changed protected pnpm policy" in report) == (not accepted)


@pytest.mark.parametrize("security_fix", [False, True])
@pytest.mark.parametrize(
    "union, permitted",
    [
        ("renderer@1.0.0 || 1.0.1", True),
        ("renderer@1.0.1", False),
        ("renderer@1.0.0 || *", False),
        ("renderer@1.0.0 || 2.0.0", True),
        ("renderer@1.0.0 || ^1.0.1", False),
    ],
)
def test_pnpm_merged_exclusions_preserve_existing_exact_versions(
    pnpm_project, security_fix, union, permitted
):
    workspace = pnpm_project / "pnpm-workspace.yaml"
    lockfile = pnpm_project / "pnpm-lock.yaml"
    policy = yaml.safe_load(workspace.read_text())
    policy["minimumReleaseAgeExclude"].append("renderer@1.0.0")
    workspace.write_text(yaml.safe_dump(policy))
    original_policy = workspace.read_text().replace(
        "minimumReleaseAgeExclude:\n- other@3.0.0\n- renderer@1.0.0\n",
        "# Preserve the release-age policy.\n"
        "minimumReleaseAgeExclude: # Existing policy.\n"
        "- 'other@3.0.0' # Existing rationale.\n"
        "- 'renderer@1.0.0' # Baseline pin.\n",
    )
    workspace.write_text(original_policy)
    lock = yaml.safe_load(lockfile.read_text())
    lock["packages"]["renderer@2.0.0"] = {}
    lockfile.write_text(yaml.safe_dump(lock))
    snapshot = audit_module["valid_snapshot"](pnpm_project)
    policy["minimumReleaseAgeExclude"] = ["other@3.0.0", union]
    workspace.write_text(yaml.safe_dump(policy))
    lock["packages"].pop("renderer@1.0.0")
    lock["packages"]["renderer@1.0.1"] = {}
    lockfile.write_text(yaml.safe_dump(lock))
    notes = []

    restored = audit_module["restore_invalid_state"](
        pnpm_project, snapshot, notes, "Test command", security_fix=security_fix
    )

    accepted = permitted and security_fix
    assert restored == (not accepted)
    if accepted:
        expected_policy_text = original_policy
        if union == "renderer@1.0.0 || 1.0.1":
            expected_policy_text = original_policy.replace(
                "- 'renderer@1.0.0' # Baseline pin.\n",
                "- 'renderer@1.0.0' # Baseline pin.\n- renderer@1.0.1\n",
            )
        assert workspace.read_text() == expected_policy_text
        expected_policy = yaml.safe_load(expected_policy_text)
        baseline_policy = yaml.safe_load(snapshot[1]["pnpm-workspace.yaml"])
        expected_exclusions = ["other@3.0.0", "renderer@1.0.0"]
        if union == "renderer@1.0.0 || 1.0.1":
            expected_exclusions.append("renderer@1.0.1")
        assert expected_policy["minimumReleaseAgeExclude"] == expected_exclusions
        expected_policy.pop("minimumReleaseAgeExclude")
        baseline_policy.pop("minimumReleaseAgeExclude")
        assert expected_policy == baseline_policy
        assert yaml.safe_load(lockfile.read_text()) == lock
        assert bool(notes) == (union == "renderer@1.0.0 || 2.0.0")
    else:
        assert (pnpm_project / "package.json").read_bytes() == snapshot[0]
        for name, content in snapshot[1].items():
            assert (pnpm_project / name).read_bytes() == content
        assert "changed protected pnpm policy" in notes[0]


def test_pnpm_shared_workspace_is_rejected(pnpm_project):
    workspace = pnpm_project / "pnpm-workspace.yaml"
    policy = yaml.safe_load(workspace.read_text())
    policy["packages"] = [".", "../other"]
    workspace.write_text(yaml.safe_dump(policy))
    with pytest.raises(ValueError, match="one deployment"):
        prepare(pnpm_project)


@pytest.mark.parametrize("fixture_name", ["npm_project", "pnpm_project"])
@pytest.mark.parametrize("exit_code", [0, 1])
@pytest.mark.parametrize(
    "operation",
    ["initial-audit", "view", "stable-audit", "frozen", "build", "final-audit"],
)
@pytest.mark.parametrize("mutated_file", ["package.json", "lock", "competing-files"])
def test_nonmutating_commands_preserve_exact_package_files(
    request, monkeypatch, fixture_name, exit_code, operation, mutated_file
):
    project = request.getfixturevalue(fixture_name)
    pnpm = fixture_name == "pnpm_project"
    lock_name = "pnpm-lock.yaml" if pnpm else "package-lock.json"
    files = {
        name: (project / name).read_bytes()
        for name in (
            "package.json",
            lock_name,
            *(["pnpm-workspace.yaml"] if pnpm else []),
        )
    }
    audits = 0
    mutated = False

    def invoke(command, *, cwd, **kwargs):
        nonlocal audits, mutated
        args = command[5:] if pnpm else command[4:]
        stdout, boundary = "", None
        if args[:2] == ["audit", "--json"]:
            audits += 1
            boundary = ("initial-audit", "stable-audit", "final-audit")[audits - 1]
            stdout = json.dumps(
                {
                    "metadata": {"vulnerabilities": {"total": 0}},
                    "advisories" if pnpm else "vulnerabilities": {},
                }
            )
        elif args[0] == "view":
            boundary, stdout = "view", '"1.0.0"'
        elif args[0] == "ci" or args == ["install", "--frozen-lockfile"]:
            boundary = "frozen"
        elif args == ["run", "build"]:
            boundary = "build"
        if boundary == operation and not mutated:
            if mutated_file == "competing-files":
                for name in (
                    ["package-lock.json"]
                    if pnpm
                    else ["pnpm-lock.yaml", "pnpm-workspace.yaml"]
                ):
                    (project / name).write_text("{}")
            elif mutated_file == "package.json":
                manifest = json.loads((project / "package.json").read_bytes())
                manifest["dependencies"]["renderer"] = "9.9.9"
                (project / "package.json").write_text(json.dumps(manifest))
            elif pnpm:
                lock = yaml.safe_load((project / lock_name).read_bytes())
                lock["packages"] = {"renderer@9.9.9": {}}
                (project / lock_name).write_text(yaml.safe_dump(lock))
            else:
                (project / lock_name).write_text(
                    json.dumps(
                        {
                            "lockfileVersion": 3,
                            "packages": {"node_modules/renderer": {"version": "9.9.9"}},
                        }
                    )
                )
            mutated = True
            return subprocess.CompletedProcess(command, exit_code, stdout, "")
        return subprocess.CompletedProcess(command, 0, stdout, "")

    monkeypatch.setattr(subprocess, "run", invoke)
    validation = {}
    report = prepare(project, validation=validation)

    assert mutated
    for name, content in files.items():
        assert (project / name).read_bytes() == content
    assert audit_module["valid_snapshot"](project) is not None
    for name in ("package-lock.json", "pnpm-lock.yaml", "pnpm-workspace.yaml"):
        assert (project / name).exists() == (name in files)
    for name, content in files.items():
        assert f"- `{name}`: `{hashlib.sha256(content).hexdigest()}`" in report
    assert validation["passed"] == ("## Production build\n\nPassed." in report)
    assert "restored" in report
    if operation in {"frozen", "build"}:
        assert "## Production build\n\nPassed." not in report
    if operation == "final-audit":
        assert "## Remaining advisories\n\nAudit unavailable" in report


@pytest.mark.parametrize("fixture_name", ["npm_project", "pnpm_project"])
@pytest.mark.parametrize("container", [None, [], {}])
def test_audit_missing_or_inconsistent_advisory_evidence_is_unavailable(
    request, monkeypatch, fixture_name, container
):
    project = request.getfixturevalue(fixture_name)
    key = "advisories" if fixture_name == "pnpm_project" else "vulnerabilities"
    response = {"metadata": {"vulnerabilities": {"high": 1}}}
    if container is not None:
        response[key] = container

    def invoke(command, *, cwd, **kwargs):
        return subprocess.CompletedProcess(command, 1, json.dumps(response), "")

    monkeypatch.setattr(subprocess, "run", invoke)
    data = audit(project)
    assert isinstance(data, str) and "Audit unavailable" in data
    for formatter in (format_remaining_audit, format_audit):
        assert "Audit unavailable" in formatter(data, {})
        assert "No known vulnerabilities" not in formatter(data, {})


def test_pnpm_reference_policy_and_publisher_include_workspace():
    templates = Path(__file__).parents[1] / "runtime/templates"
    policy = yaml.safe_load((templates / "pnpm-workspace.yaml").read_text())
    assert policy["minimumReleaseAge"] == 14400
    assert policy["blockExoticSubdeps"] and policy["strictDepBuilds"]
    assert policy["allowBuilds"] == {
        "core-js": False,
        "core-js-pure": False,
        "fsevents": False,
    }
    workflow = load_workflow()
    assert "${{ env.NPM_PROJECT }}/pnpm-workspace.yaml" in json.dumps(workflow)
    assert (
        "for file in package-lock.json pnpm-lock.yaml pnpm-workspace.yaml"
        in workflow["jobs"]["pull-request"]["steps"][-1]["run"]
    )
    publisher = workflow["jobs"]["pull-request"]
    assert all("corepack" not in step.get("run", "") for step in publisher["steps"])


def test_attention_lists_all_blocking_pins_before_other_findings(security_findings):
    rows = [
        (
            "aaa-parent",
            "parent",
            "critical",
            "No patched version declared by the registry.",
        )
    ]
    for index in range(7):
        name = f"pinned-{index}"
        status = (
            f"Published patch: `{name}@1.2.0`. Blocked by retained override "
            f"`pnpm-workspace.yaml overrides.{name}` = `1.0.0`. "
            "Override preserved for manual compatibility review."
        )
        rows.append((name, str(index), "high", status))
    # Several advisories for a package must produce one decision row.
    rows.append(("pinned-0", "another", "moderate", rows[1][3]))
    data = security_findings(rows)
    result = audit_module["format_audit_summary"](data, data, "pnpm")
    assert "🔴 **Remaining:** 9 registry advisories" in result
    assert result.count("| Status | Package | Action / blocker |") == 1
    assert "Your attention" not in result and "Other blockers" not in result
    assert result.index("| `pinned-6`") < result.index("| `aaa-parent`")
    assert result.count("| `pinned-") == 7
    assert (
        "Pin `1.0.0` blocks fix `1.2.0`; review removing or updating the pin." in result
    )
    assert result.count("🟠 Review pin") == 7
    assert "safety unverified" not in result


def test_attention_does_not_invent_candidate_when_parents_also_block(security_findings):
    status = (
        "Published patches exist, but no single patch satisfies all checked parent constraints. "
        "Blocked by retained override `pnpm-workspace.yaml overrides.leaf` = `1.0.0`."
    )
    data = security_findings([("leaf", "one", "high", status)])
    result = audit_module["format_audit_summary"](data, data, "pnpm")
    assert "Pin `1.0.0` blocks fix `see advisory details`" in result
    assert "Parent constraints also block the fix" in result


def test_attention_escapes_disjunctive_pin_and_preserves_scoped_name(security_findings):
    status = (
        "Published patch: `@scope/leaf@2.0.1`. Blocked by retained override "
        "`pnpm-workspace.yaml overrides.@scope/leaf` = `1.0.0 || 2.0.0`."
    )
    data = security_findings([("@scope/leaf", "one", "high", status)])
    result = audit_module["format_audit_summary"](data, data, "pnpm")
    assert (
        "| 🟠 Review pin | `@scope/leaf` (1 high) | Pin `1.0.0 &#124;&#124; 2.0.0` blocks fix `2.0.1`"
        in result
    )


def test_attention_is_absent_when_no_blocking_pin_was_verified(security_findings):
    data = security_findings([("leaf", "one", "high", "Could not verify publication.")])
    result = audit_module["format_audit_summary"](data, data, "pnpm")
    assert "Your attention" not in result
    assert "🟠 Review fix" in result
    assert "No pins were changed" not in result


def test_single_table_keeps_other_advisories_for_a_pinned_package_visible(
    security_findings,
):
    pinned = "Published patch: `leaf@1.2.0`. Blocked by retained override `pnpm-workspace.yaml overrides.leaf` = `1.0.0`."
    data = security_findings(
        [
            ("leaf", "pin", "critical", pinned),
            (
                "leaf",
                "unpatched",
                "high",
                "No published stable patch matches registry range `>=2.0.0`.",
            ),
        ]
    )
    result = audit_module["format_audit_summary"](data, data, "pnpm")
    assert result.count("| 🟠 Review pin |") == 1
    assert "`leaf` (1 critical, 1 high)" in result
    assert "No published patch matches the fix range." in result
