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
            elif args[2] == "version" and "<1.3.0" in args[1]:
                stdout = json.dumps(["1.2.3", "1.2.4"])
            elif args[2] == "version" and ">=1.3.0" in args[1]:
                stdout = json.dumps(["1.3.0"])
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
            "renderer": {
                "severity": "high",
                "range": "<1.3.0",
                "nodes": [],
                "via": [
                    {
                        "url": "https://github.com/advisories/GHSA-test",
                        "title": "Test finding",
                        "severity": "high",
                        "range": "<1.3.0",
                        "patchedRange": ">=1.3.0",
                        "nodes": ["renderer@1.2.3"],
                    }
                ],
            }
        },
        "package_manager": "pnpm",
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
        snapshot = helper["valid_snapshot"](directory)
        helper["describe_pnpm_fixes"](
            directory,
            kwargs["before"],
            snapshot[1],
            args[1],
            float("inf"),
            args[2],
            collect_proof=True,
        )
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
        assert not any("--lockfile-only" in args for _, args in commands)
        assert any(args[0] == "view" for _, args in commands)
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
    "evidence", ["unchanged", "unavailable", "lost-at-final-audit"]
)
def test_security_only_rejects_lockfile_churn_without_confirmed_fixes(
    site, monkeypatch, evidence
):
    fake_commands(monkeypatch)
    original = helper["valid_snapshot"](site)
    finding = {
        "vulnerabilities": {
            "renderer": {
                "severity": "high",
                "range": "<1.3.0",
                "nodes": [],
                "via": [
                    {
                        "url": "https://github.com/advisories/GHSA-test",
                        "title": "Test finding",
                        "severity": "high",
                        "range": "<1.3.0",
                        "nodes": [],
                    }
                ],
            }
        },
        "metadata": {"vulnerabilities": {"high": 1, "total": 1}},
    }
    calls = 0

    def audit(*args, **kwargs):
        nonlocal calls
        calls += 1
        if evidence == "unavailable" and calls > 1:
            return "Audit unavailable: registry offline"
        if evidence == "lost-at-final-audit" and calls == 2:
            return {
                "vulnerabilities": {},
                "metadata": {"vulnerabilities": {"total": 0}},
            }
        return finding

    def churn(directory, *args, **kwargs):
        write_lock(directory, "1.2.4")
        return subprocess.CompletedProcess([], 0, "", "")

    monkeypatch.setitem(helper["prepare"].__globals__, "audit", audit)
    monkeypatch.setitem(helper["prepare"].__globals__, "fix_security", churn)
    report = helper["prepare"](site, maintenance_mode="security-only")
    assert helper["valid_snapshot"](site) == original
    assert "Discarded dependency changes" in report
    assert report.startswith("**0 dependency updates")


def test_clear_headline_reports_optional_updates_and_unfixed_security(
    site, monkeypatch
):
    fake_commands(monkeypatch)
    report = helper["prepare"](site)
    assert report.startswith(
        "**1 dependency update · 0 security fixes · 0 advisories remain · Build passed**"
    )


def test_registry_finding_removal_does_not_turn_unrelated_churn_into_a_security_fix(
    site, monkeypatch
):
    fake_commands(monkeypatch)
    lock_path = site / "pnpm-lock.yaml"
    lock = yaml.safe_load(lock_path.read_text())
    lock["packages"]["unrelated@1.0.0"] = {}
    lock["snapshots"] = {
        "renderer@1.2.3": {"dependencies": {"unrelated": "1.0.0"}},
        "unrelated@1.0.0": {},
    }
    lock_path.write_text(yaml.safe_dump(lock))
    original = helper["valid_snapshot"](site)
    finding = {
        "vulnerabilities": {
            "renderer": {
                "severity": "high",
                "range": "<1.3.0",
                "nodes": ["renderer@1.2.3"],
                "via": [
                    {
                        "url": "https://github.com/advisories/GHSA-test",
                        "title": "Test finding",
                        "severity": "high",
                        "range": "<1.3.0",
                        "nodes": ["renderer@1.2.3"],
                    }
                ],
            }
        },
        "metadata": {"vulnerabilities": {"high": 1, "total": 1}},
    }
    calls = 0

    def audit(*args, **kwargs):
        nonlocal calls
        calls += 1
        return (
            finding
            if calls == 1
            else {"vulnerabilities": {}, "metadata": {"vulnerabilities": {"total": 0}}}
        )

    def churn(directory, *args, **kwargs):
        value = yaml.safe_load(lock_path.read_text())
        value["packages"].pop("unrelated@1.0.0")
        value["packages"]["unrelated@1.1.0"] = {}
        value["snapshots"] = {
            "renderer@1.2.3": {"dependencies": {"unrelated": "1.1.0"}},
            "unrelated@1.1.0": {},
        }
        lock_path.write_text(yaml.safe_dump(value))
        return subprocess.CompletedProcess([], 0, "", "")

    monkeypatch.setitem(helper["prepare"].__globals__, "audit", audit)
    monkeypatch.setitem(helper["prepare"].__globals__, "fix_security", churn)
    report = helper["prepare"](site, maintenance_mode="security-only")
    assert helper["valid_snapshot"](site) == original
    assert report.startswith("**0 dependency updates · 0 security fixes")
    assert "**Fixes in" not in report


def _renderer_finding(*, second=False):
    via = [
        {
            "url": "https://github.com/advisories/GHSA-test"
            + ("-second" if second else ""),
            "title": "Test finding",
            "severity": "high",
            "range": "<1.3.0",
            "patchedRange": ">=1.3.0",
            "nodes": ["renderer@1.2.3"],
        }
    ]
    return {
        "package_manager": "pnpm",
        "vulnerabilities": {
            "renderer": {
                "severity": "high",
                "range": "<1.3.0",
                "nodes": ["renderer@1.2.3"],
                "via": via,
            }
        },
        "metadata": {"vulnerabilities": {"high": 1, "total": 1}},
    }


def _clear_finding():
    return {
        "package_manager": "pnpm",
        "vulnerabilities": {},
        "metadata": {"vulnerabilities": {"total": 0}},
    }


def _collect_renderer_proof(site, before, monkeypatch):
    def registry(directory, *args, **kwargs):
        package = args[1]
        versions = ["1.2.3", "1.2.4"] if "<1.3.0" in package else ["1.3.0"]
        return subprocess.CompletedProcess(args, 0, json.dumps(versions), "")

    monkeypatch.setitem(helper["describe_pnpm_fixes"].__globals__, "run", registry)
    snapshot = helper["valid_snapshot"](site)
    helper["describe_pnpm_fixes"](
        site, before, snapshot[1], [], float("inf"), {}, collect_proof=True
    )


@pytest.mark.parametrize(
    "version,expected",
    [
        ("1.2.4", set()),
        ("1.3.0", {"https://github.com/advisories/GHSA-test"}),
    ],
)
def test_confirmed_fixes_require_a_verified_patched_version(
    site, monkeypatch, version, expected
):
    before_snapshot = helper["valid_snapshot"](site)
    before = _renderer_finding()
    _collect_renderer_proof(site, before, monkeypatch)
    write_lock(site, version)
    after_snapshot = helper["valid_snapshot"](site)
    assert (
        helper["confirmed_fixes"](
            before, _clear_finding(), "pnpm", before_snapshot, after_snapshot
        )
        == expected
    )


def test_confirmed_fixes_tolerate_a_preexisting_safe_same_module_version(
    site, monkeypatch
):
    lock = yaml.safe_load((site / "pnpm-lock.yaml").read_text())
    lock["packages"]["renderer@1.3.0"] = {}
    lock["importers"]["."]["dependencies"]["renderer"]["version"] = "1.3.0"
    (site / "pnpm-lock.yaml").write_text(yaml.safe_dump(lock))
    before_snapshot = helper["valid_snapshot"](site)
    before = _renderer_finding()
    _collect_renderer_proof(site, before, monkeypatch)
    lock["packages"].pop("renderer@1.2.3")
    (site / "pnpm-lock.yaml").write_text(yaml.safe_dump(lock))
    after_snapshot = helper["valid_snapshot"](site)
    assert helper["confirmed_fixes"](
        before, _clear_finding(), "pnpm", before_snapshot, after_snapshot
    ) == {"https://github.com/advisories/GHSA-test"}


@pytest.mark.parametrize(
    "package_manager,selected,vulnerable_range,proof_status",
    [
        ("pnpm", "1.3.0", "<1.3.0", "safe"),
        ("npm", "1.3.0", "<1.3.0", "safe"),
        ("npm", "1.2.4", "<1.3.0", "vulnerable"),
        ("npm", "1.3.0", "<1.3.0", "unavailable"),
        ("npm", "1.3.0", "<1.3.0", "empty"),
        ("npm", "1.3.0", "<1.3.0", "wrong-no-match"),
        ("npm", "1.3.0", "<1.3.0 || >=2.0.0", "safe"),
        ("npm", "1.3.0", "<1.3.0 || >=1.3.0", "vulnerable-arm"),
    ],
)
def test_security_fix_requires_original_range_proof_before_validation(
    site, monkeypatch, package_manager, selected, vulnerable_range, proof_status
):
    if package_manager == "npm":
        (site / "pnpm-lock.yaml").unlink()
        (site / "pnpm-workspace.yaml").unlink()
        (site / "package.json").write_text(
            json.dumps(
                {
                    "packageManager": "npm@11.21.0",
                    "scripts": {"build": "site build"},
                    "dependencies": {"renderer": "^1.2.3"},
                }
            )
        )
        (site / "package-lock.json").write_text(
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "": {"dependencies": {"renderer": "^1.2.3"}},
                        "node_modules/renderer": {"version": "1.2.3"},
                    },
                }
            )
        )

    def write_fixed_lock():
        if package_manager == "pnpm":
            write_lock(site, selected)
        else:
            lock = json.loads((site / "package-lock.json").read_text())
            lock["packages"]["node_modules/renderer"]["version"] = selected
            (site / "package-lock.json").write_text(json.dumps(lock))

    def current_version():
        return next(
            iter(helper["direct_versions"](helper["valid_snapshot"](site)).values())
        )

    detail = {
        "title": "Test finding",
        "url": "https://github.com/advisories/GHSA-proof-handoff",
        "severity": "high",
        "range": vulnerable_range,
        "nodes": [
            "renderer@1.2.3" if package_manager == "pnpm" else "node_modules/renderer"
        ],
    }
    finding = {
        "vulnerabilities": {
            "renderer": {
                "severity": "high",
                "range": vulnerable_range,
                "nodes": detail["nodes"],
                "via": [detail],
                "fixAvailable": True,
            }
        },
        "metadata": {"vulnerabilities": {"high": 1, "total": 1}},
    }
    if package_manager == "pnpm":
        finding["package_manager"] = "pnpm"
        detail["patchedRange"] = ">=1.3.0"
    calls = []

    def audit(*args, **kwargs):
        return (
            finding
            if current_version() == (1, 2, 3)
            else {"vulnerabilities": {}, "metadata": {"vulnerabilities": {"total": 0}}}
        )

    def invoke(directory, *args, **kwargs):
        calls.append(args)
        if args[:2] in (
            ("audit", "--fix=update"),
            ("audit", "fix"),
        ):
            write_fixed_lock()
        elif args[0] == "view":
            specifier = args[1]
            if specifier.startswith(f"renderer@{selected} "):
                constraint = specifier.removeprefix("renderer@")
                arm = constraint.removeprefix(selected + " ")
                if proof_status == "vulnerable" or (
                    proof_status == "vulnerable-arm" and arm == ">=1.3.0"
                ):
                    return subprocess.CompletedProcess(
                        args, 0, json.dumps(selected), ""
                    )
                if proof_status == "empty":
                    return subprocess.CompletedProcess(args, 0, "[]", "")
                error = {
                    "code": "ETIMEDOUT" if proof_status == "unavailable" else "E404",
                    "summary": "No match found for version "
                    + (
                        "other range"
                        if proof_status == "wrong-no-match"
                        else constraint
                    ),
                }
                return subprocess.CompletedProcess(
                    args, 1, json.dumps({"error": error}), ""
                )
            # The full-range response deliberately omits the selected version.
            # It must not replace an exact-version/range check.
            versions = (
                ["1.2.3"] if specifier == f"renderer@{vulnerable_range}" else [selected]
            )
            return subprocess.CompletedProcess(args, 0, json.dumps(versions), "")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setitem(helper["prepare"].__globals__, "audit", audit)
    monkeypatch.setitem(helper["prepare"].__globals__, "run", invoke)
    report = helper["prepare"](site, maintenance_mode="security-only")
    install = next(
        index
        for index, args in enumerate(calls)
        if args[0] in ("ci", "install")
        and "--frozen-lockfile" in args
        or args[:2] == ("ci", "--no-audit")
    )
    assert any(args[0] == "view" for args in calls[:install])
    assert current_version() == ((1, 3, 0) if proof_status == "safe" else (1, 2, 3))
    assert ("1 security fix" in report) == (proof_status == "safe")


@pytest.mark.parametrize("vulnerable_range", ["<=1.2", "~1", "1.0 - 1.2"])
def test_registry_membership_proof_rejects_still_vulnerable_versions(
    site, monkeypatch, vulnerable_range
):
    before_snapshot = helper["valid_snapshot"](site)
    before = _renderer_finding()
    detail = before["vulnerabilities"]["renderer"]["via"][0]
    detail["range"] = vulnerable_range

    def registry(directory, *args, **kwargs):
        assert args[0] == "view"
        package = args[1]
        versions = (
            ["1.2.3", "1.2.4"]
            if "<=1.2" in package or "~1" in package or "1.0 - 1.2" in package
            else ["1.3.0"]
        )
        return subprocess.CompletedProcess(args, 0, json.dumps(versions), "")

    monkeypatch.setitem(helper["describe_pnpm_fixes"].__globals__, "run", registry)
    helper["describe_pnpm_fixes"](
        site, before, before_snapshot[1], [], float("inf"), {}, collect_proof=True
    )
    write_lock(site, "1.2.4")
    after_snapshot = helper["valid_snapshot"](site)
    assert (
        helper["confirmed_fixes"](
            before, _clear_finding(), "pnpm", before_snapshot, after_snapshot
        )
        == set()
    )


def test_unavailable_registry_membership_remains_unconfirmed(site, monkeypatch):
    before_snapshot = helper["valid_snapshot"](site)
    before = _renderer_finding()

    def malformed_registry(directory, *args, **kwargs):
        return subprocess.CompletedProcess(args, 0, "not JSON", "")

    monkeypatch.setitem(
        helper["describe_pnpm_fixes"].__globals__, "run", malformed_registry
    )
    helper["describe_pnpm_fixes"](
        site, before, before_snapshot[1], [], float("inf"), {}, collect_proof=True
    )
    write_lock(site, "1.3.0")
    after_snapshot = helper["valid_snapshot"](site)
    assert (
        helper["confirmed_fixes"](
            before, _clear_finding(), "pnpm", before_snapshot, after_snapshot
        )
        == set()
    )


@pytest.mark.parametrize("retained", [False, True])
def test_confirmed_fixes_classify_removed_and_retained_affected_paths(
    site, monkeypatch, retained
):
    before_snapshot = helper["valid_snapshot"](site)
    before = _renderer_finding()
    _collect_renderer_proof(site, before, monkeypatch)
    lock = yaml.safe_load((site / "pnpm-lock.yaml").read_text())
    if retained:
        lock["packages"] = {"renderer@1.2.4": {}}
        lock["importers"]["."]["dependencies"]["renderer"]["version"] = "1.2.4"
    else:
        lock["packages"] = {}
        lock["importers"]["."]["dependencies"] = {}
    (site / "pnpm-lock.yaml").write_text(yaml.safe_dump(lock))
    after_snapshot = helper["valid_snapshot"](site)
    expected = set() if retained else {"https://github.com/advisories/GHSA-test"}
    assert (
        helper["confirmed_fixes"](
            before, _clear_finding(), "pnpm", before_snapshot, after_snapshot
        )
        == expected
    )


def test_security_summary_keeps_disappeared_unconfirmed_advisory_visible():
    before = _renderer_finding()
    summary = helper["format_audit_summary"](
        before, _clear_finding(), "pnpm", fixed_ids=set()
    )
    assert "| ⚪\u00a0`renderer` | 1 unconfirmed |" in summary
    assert "No longer reported; fix could not be confirmed." in summary
    assert "Original affected range: `<1.3.0`." in summary
    assert "Resolved." not in summary


def test_security_summary_retains_confirmed_and_unconfirmed_advisories():
    before = _renderer_finding()
    before["vulnerabilities"]["renderer"]["via"].append(
        {
            "url": "https://github.com/advisories/GHSA-test-second",
            "title": "Second finding",
            "severity": "high",
            "range": "<1.3.0",
            "patchedRange": ">=1.3.0",
            "nodes": ["renderer@1.2.3"],
        }
    )
    summary = helper["format_audit_summary"](
        before,
        _clear_finding(),
        "pnpm",
        fixed_ids={"https://github.com/advisories/GHSA-test"},
    )
    assert "1 fixed · 1 unconfirmed" in summary
    assert "No longer reported; fix could not be confirmed." in summary
    assert "🟢\u00a0`renderer`" not in summary


def test_security_only_rejects_unseparable_independent_direct_upgrade(
    site, monkeypatch
):
    manifest = json.loads((site / "package.json").read_text())
    manifest["dependencies"]["unaffected"] = "^1.0.0"
    (site / "package.json").write_text(json.dumps(manifest))
    lock_path = site / "pnpm-lock.yaml"
    lock = yaml.safe_load(lock_path.read_text())
    lock["importers"]["."]["dependencies"]["unaffected"] = {
        "specifier": "^1.0.0",
        "version": "1.0.0",
    }
    lock["packages"]["unaffected@1.0.0"] = {}
    lock_path.write_text(yaml.safe_dump(lock))
    resolution_base = yaml.safe_load(yaml.safe_dump(lock))
    original = helper["valid_snapshot"](site)
    before = _renderer_finding()
    calls = []

    def invoke(directory, *args, **kwargs):
        calls.append(args)
        if args[:2] == ("audit", "--fix=update"):
            value = yaml.safe_load(lock_path.read_text())
            value["importers"]["."]["dependencies"]["renderer"]["version"] = "1.3.0"
            lock_path.write_text(yaml.safe_dump(value))
            return subprocess.CompletedProcess(args, 1, "", "")
        if args[0] == "install" and "--lockfile-only" in args:
            value = yaml.safe_load(yaml.safe_dump(resolution_base))
            value["importers"]["."]["dependencies"]["renderer"]["version"] = "1.3.0"
            value["importers"]["."]["dependencies"]["unaffected"]["version"] = "1.1.0"
            value["packages"].pop("renderer@1.2.3")
            value["packages"]["renderer@1.3.0"] = {}
            value["packages"].pop("unaffected@1.0.0")
            value["packages"]["unaffected@1.1.0"] = {}
            lock_path.write_text(yaml.safe_dump(value))
        return subprocess.CompletedProcess(args, 0, "", "")

    audit_calls = 0

    def audit(*args, **kwargs):
        nonlocal audit_calls
        audit_calls += 1
        return before if audit_calls == 1 else _clear_finding()

    monkeypatch.setitem(helper["prepare"].__globals__, "run", invoke)
    monkeypatch.setitem(helper["prepare"].__globals__, "audit", audit)
    monkeypatch.setitem(
        helper["prepare"].__globals__, "describe_pnpm_fixes", lambda *a, **k: None
    )
    report = helper["prepare"](site, maintenance_mode="security-only")
    final = helper["valid_snapshot"](site)
    assert helper["direct_versions"](final) == helper["direct_versions"](original)
    assert "resolved version changed during security-only maintenance" in report
    assert any(args[:2] == ("audit", "--fix=update") for args in calls)


@pytest.mark.parametrize("package_manager", ["pnpm", "npm"])
def test_security_only_rejects_an_affected_direct_without_a_confirmed_fix(
    site, monkeypatch, package_manager
):
    manifest = json.loads((site / "package.json").read_text())
    manifest["packageManager"] = f"{package_manager}@11.21.0"
    manifest["dependencies"] = {"fixed": "^1.0.0", "blocked": "^1.0.0"}
    (site / "package.json").write_text(json.dumps(manifest))
    if package_manager == "pnpm":
        (site / "pnpm-lock.yaml").write_text(
            yaml.safe_dump(
                {
                    "lockfileVersion": "9.0",
                    "importers": {
                        ".": {
                            "dependencies": {
                                name: {"specifier": "^1.0.0", "version": "1.0.0"}
                                for name in ("fixed", "blocked")
                            }
                        }
                    },
                    "packages": {f"{name}@1.0.0": {} for name in ("fixed", "blocked")},
                }
            )
        )
    else:
        (site / "pnpm-lock.yaml").unlink()
        (site / "pnpm-workspace.yaml").unlink()
        (site / "package-lock.json").write_text(
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "": {
                            "dependencies": {
                                name: "^1.0.0" for name in ("fixed", "blocked")
                            }
                        },
                        **{
                            f"node_modules/{name}": {"version": "1.0.0"}
                            for name in ("fixed", "blocked")
                        },
                    },
                }
            )
        )

    def finding(name, version, patched):
        detail = {
            "url": f"https://github.com/advisories/GHSA-{name}",
            "title": name,
            "severity": "high",
            "range": "<2.0.0" if name == "blocked" else "<1.1.0",
            "nodes": [
                f"{name}@{version}"
                if package_manager == "pnpm"
                else f"node_modules/{name}"
            ],
            "_verifiedVulnerableVersions": ["1.0.0"],
            "_verifiedPatchedVersions": patched,
        }
        if package_manager == "pnpm":
            detail["patchedRange"] = ">=1.1.0"
            return {
                "severity": "high",
                "range": detail["range"],
                "nodes": detail["nodes"],
                "via": [detail],
            }
        return {
            "severity": "high",
            "range": detail["range"],
            "nodes": detail["nodes"],
            "via": [],
            "fixAvailable": True,
            **{key: value for key, value in detail.items() if key.startswith("_")},
        }

    before = {
        "vulnerabilities": {
            "fixed": finding("fixed", "1.0.0", ["1.1.0"]),
            "blocked": finding("blocked", "1.0.0", []),
        },
        "metadata": {"vulnerabilities": {"high": 2, "total": 2}},
    }
    if package_manager == "pnpm":
        before["package_manager"] = "pnpm"
    after = {
        "vulnerabilities": {"blocked": finding("blocked", "1.1.0", [])},
        "metadata": {"vulnerabilities": {"high": 1, "total": 1}},
    }
    if package_manager == "pnpm":
        after["package_manager"] = "pnpm"
    calls = []

    def write_fixed_lock():
        if package_manager == "pnpm":
            lock = {
                "lockfileVersion": "9.0",
                "importers": {
                    ".": {
                        "dependencies": {
                            name: {"specifier": "^1.0.0", "version": "1.1.0"}
                            for name in ("fixed", "blocked")
                        }
                    }
                },
                "packages": {f"{name}@1.1.0": {} for name in ("fixed", "blocked")},
            }
            (site / "pnpm-lock.yaml").write_text(yaml.safe_dump(lock))
        else:
            lock = json.loads((site / "package-lock.json").read_text())
            for name in ("fixed", "blocked"):
                lock["packages"][f"node_modules/{name}"]["version"] = "1.1.0"
            (site / "package-lock.json").write_text(json.dumps(lock))

    audits = 0

    def audit(*args, **kwargs):
        nonlocal audits
        audits += 1
        return before if audits == 1 else after

    def invoke(directory, *args, **kwargs):
        calls.append(args)
        if args[:2] in (("audit", "--fix=update"), ("audit", "fix")):
            write_fixed_lock()
            return subprocess.CompletedProcess(
                args, 1 if package_manager == "pnpm" else 0, "", ""
            )
        if (
            package_manager == "pnpm"
            and args[0] == "install"
            and "--lockfile-only" in args
        ):
            write_fixed_lock()
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setitem(helper["prepare"].__globals__, "audit", audit)
    monkeypatch.setitem(helper["prepare"].__globals__, "run", invoke)
    monkeypatch.setitem(
        helper["prepare"].__globals__, "describe_pnpm_fixes", lambda *a, **k: None
    )
    monkeypatch.setitem(
        helper["prepare"].__globals__, "describe_npm_fixes", lambda *a, **k: None
    )
    original = helper["valid_snapshot"](site)
    report = helper["prepare"](site, maintenance_mode="security-only")
    final = helper["valid_snapshot"](site)
    assert helper["direct_versions"](final) == helper["direct_versions"](original)
    assert "without a confirmed security fix" in report
    assert any(args[0] in ("audit",) for args in calls)


@pytest.mark.parametrize(
    ("package_manager", "dependency_kind"),
    [
        ("pnpm", "dependencies"),
        ("npm", "dependencies"),
        ("npm", "optionalDependencies"),
    ],
)
def test_security_only_retains_a_required_direct_parent_for_a_confirmed_fix(
    site, monkeypatch, package_manager, dependency_kind
):
    manifest = json.loads((site / "package.json").read_text())
    manifest["packageManager"] = f"{package_manager}@11.21.0"
    manifest["dependencies"] = {"parent": "^1.0.0"}
    (site / "package.json").write_text(json.dumps(manifest))
    if package_manager == "pnpm":
        (site / "pnpm-lock.yaml").write_text(
            yaml.safe_dump(
                {
                    "lockfileVersion": "9.0",
                    "importers": {
                        ".": {
                            "dependencies": {
                                "parent": {"specifier": "^1.0.0", "version": "1.0.0"}
                            }
                        }
                    },
                    "packages": {"parent@1.0.0": {}, "child@1.0.0": {}},
                    "snapshots": {
                        "parent@1.0.0": {"dependencies": {"child": "1.0.0"}},
                        "child@1.0.0": {},
                    },
                }
            )
        )
    else:
        (site / "pnpm-lock.yaml").unlink()
        (site / "pnpm-workspace.yaml").unlink()
        (site / "package-lock.json").write_text(
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "": {"dependencies": {"parent": "^1.0.0"}},
                        "node_modules/parent": {
                            "version": "1.0.0",
                            dependency_kind: {"child": "^1.0.0"},
                        },
                        "node_modules/child": {"version": "1.0.0"},
                    },
                }
            )
        )

    detail = {
        "url": "https://github.com/advisories/GHSA-child",
        "title": "child",
        "severity": "high",
        "range": "<1.1.0",
        "nodes": ["child@1.0.0" if package_manager == "pnpm" else "node_modules/child"],
        "_verifiedVulnerableVersions": ["1.0.0"],
        "_verifiedPatchedVersions": ["1.1.0"],
    }
    vulnerability = {
        "severity": "high",
        "range": detail["range"],
        "nodes": detail["nodes"],
        "via": [detail],
        "_verifiedVulnerableVersions": ["1.0.0"],
        "_verifiedPatchedVersions": ["1.1.0"],
        **(
            {"fixAvailable": {"name": "parent", "version": "1.1.0"}}
            if package_manager == "npm"
            else {}
        ),
    }
    before = {
        "vulnerabilities": {"child": vulnerability},
        "metadata": {"vulnerabilities": {"high": 1, "total": 1}},
    }
    if package_manager == "pnpm":
        before["package_manager"] = "pnpm"
    after = {
        "vulnerabilities": {},
        "metadata": {"vulnerabilities": {"total": 0}},
    }
    if package_manager == "pnpm":
        after["package_manager"] = "pnpm"

    def write_fixed_lock():
        if package_manager == "pnpm":
            (site / "pnpm-lock.yaml").write_text(
                yaml.safe_dump(
                    {
                        "lockfileVersion": "9.0",
                        "importers": {
                            ".": {
                                "dependencies": {
                                    "parent": {
                                        "specifier": "^1.0.0",
                                        "version": "1.1.0",
                                    }
                                }
                            }
                        },
                        "packages": {"parent@1.1.0": {}, "child@1.1.0": {}},
                        "snapshots": {
                            "parent@1.1.0": {"dependencies": {"child": "1.1.0"}},
                            "child@1.1.0": {},
                        },
                    }
                )
            )
        else:
            (site / "package-lock.json").write_text(
                json.dumps(
                    {
                        "lockfileVersion": 3,
                        "packages": {
                            "": {"dependencies": {"parent": "^1.0.0"}},
                            "node_modules/parent": {
                                "version": "1.1.0",
                                dependency_kind: {"child": "^1.1.0"},
                            },
                            "node_modules/child": {"version": "1.1.0"},
                        },
                    }
                )
            )

    audits = 0

    def audit(*args, **kwargs):
        nonlocal audits
        audits += 1
        return before if audits == 1 else after

    def invoke(directory, *args, **kwargs):
        if args[:2] in (("audit", "--fix=update"), ("audit", "fix")):
            write_fixed_lock()
            return subprocess.CompletedProcess(
                args, 1 if package_manager == "pnpm" else 0, "", ""
            )
        if (
            package_manager == "pnpm"
            and args[0] == "install"
            and "--lockfile-only" in args
        ):
            write_fixed_lock()
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setitem(helper["prepare"].__globals__, "audit", audit)
    monkeypatch.setitem(helper["prepare"].__globals__, "run", invoke)
    monkeypatch.setitem(
        helper["prepare"].__globals__, "describe_pnpm_fixes", lambda *a, **k: None
    )
    monkeypatch.setitem(
        helper["prepare"].__globals__, "describe_npm_fixes", lambda *a, **k: None
    )
    report = helper["prepare"](site, maintenance_mode="security-only")
    final = helper["valid_snapshot"](site)
    assert helper["direct_versions"](final)[("dependencies", "parent")] == (1, 1, 0)
    assert "1 security fix" in report


def test_npm_parent_attribution_resolves_nested_child_before_hoisted_child(
    site,
):
    manifest = json.loads((site / "package.json").read_text())
    manifest["packageManager"] = "npm@11.21.0"
    manifest["dependencies"] = {"parent": "^1.0.0"}
    (site / "package.json").write_text(json.dumps(manifest))
    (site / "pnpm-lock.yaml").unlink()
    (site / "pnpm-workspace.yaml").unlink()

    def write_lock(parent_version, child_version):
        (site / "package-lock.json").write_text(
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "": {"dependencies": {"parent": "^1.0.0"}},
                        "node_modules/parent": {
                            "version": parent_version,
                            "dependencies": {"child": "^1.0.0"},
                        },
                        "node_modules/parent/node_modules/child": {
                            "version": child_version
                        },
                        "node_modules/child": {"version": "1.1.0"},
                    },
                }
            )
        )

    write_lock("1.0.0", "1.0.0")
    before_snapshot = helper["valid_snapshot"](site)
    write_lock("1.1.0", "1.1.0")
    after_snapshot = helper["valid_snapshot"](site)
    before = {
        "vulnerabilities": {
            "child": {
                "severity": "high",
                "range": "<1.1.0",
                "nodes": ["node_modules/parent/node_modules/child"],
                "fixAvailable": {"name": "parent", "version": "1.1.0"},
                "_verifiedVulnerableVersions": ["1.0.0"],
                "_verifiedPatchedVersions": ["1.1.0"],
            }
        },
        "metadata": {"vulnerabilities": {"high": 1, "total": 1}},
    }
    after = {"vulnerabilities": {}, "metadata": {"vulnerabilities": {"total": 0}}}
    assert helper["confirmed_fixes"](
        before, after, "npm", before_snapshot, after_snapshot
    ) == {"child"}
    assert (
        helper["security_only_direct_violation"](
            before_snapshot,
            after_snapshot,
            {"child"},
            confirmed_ids={"child"},
            audit_before=before,
            source="npm",
        )
        is None
    )


@pytest.mark.parametrize("direct_peer", ["1.0.0", "2.0.0"])
@pytest.mark.parametrize("reverse_snapshots", [False, True])
def test_pnpm_parent_attribution_preserves_peer_context(
    site, direct_peer, reverse_snapshots
):
    manifest = json.loads((site / "package.json").read_text())
    manifest["dependencies"] = {"parent": "^1.0.0", "carrier": "^1.0.0"}
    (site / "package.json").write_text(json.dumps(manifest))

    old_snapshots = {
        "parent@1.0.0(peer@2.0.0)": {"dependencies": {"child": "1.1.0"}},
        "parent@1.0.0(peer@1.0.0)": {"dependencies": {"child": "1.0.0"}},
        "carrier@1.0.0": {"dependencies": {"parent": "1.0.0(peer@1.0.0)"}},
        "child@1.0.0": {},
        "child@1.1.0": {},
    }
    if reverse_snapshots:
        old_snapshots = dict(reversed(list(old_snapshots.items())))
    old_lock = {
        "lockfileVersion": "9.0",
        "importers": {
            ".": {
                "dependencies": {
                    "parent": {
                        "specifier": "^1.0.0",
                        "version": f"1.0.0(peer@{direct_peer})",
                    },
                    "carrier": {"specifier": "^1.0.0", "version": "1.0.0"},
                }
            }
        },
        "packages": {key: {} for key in old_snapshots},
        "snapshots": old_snapshots,
    }
    new_snapshots = {
        f"parent@1.1.0(peer@{direct_peer})": {"dependencies": {"child": "1.1.0"}},
        "parent@1.0.0(peer@2.0.0)": {"dependencies": {"child": "1.1.0"}},
        "parent@1.0.0(peer@1.0.0)": {"dependencies": {"child": "1.1.0"}},
        "carrier@1.0.0": {"dependencies": {"parent": "1.0.0(peer@1.0.0)"}},
        "child@1.1.0": {},
    }
    if reverse_snapshots:
        new_snapshots = dict(reversed(list(new_snapshots.items())))
    new_lock = {
        "lockfileVersion": "9.0",
        "importers": {
            ".": {
                "dependencies": {
                    "parent": {
                        "specifier": "^1.0.0",
                        "version": f"1.1.0(peer@{direct_peer})",
                    },
                    "carrier": {"specifier": "^1.0.0", "version": "1.0.0"},
                }
            }
        },
        "packages": {key: {} for key in new_snapshots},
        "snapshots": new_snapshots,
    }
    (site / "pnpm-lock.yaml").write_text(yaml.safe_dump(old_lock, sort_keys=False))
    before_snapshot = helper["valid_snapshot"](site)
    (site / "pnpm-lock.yaml").write_text(yaml.safe_dump(new_lock, sort_keys=False))
    after_snapshot = helper["valid_snapshot"](site)
    detail = {
        "url": "https://github.com/advisories/GHSA-peer-child",
        "nodes": ["child@1.0.0"],
        "_verifiedVulnerableVersions": ["1.0.0"],
        "_verifiedPatchedVersions": ["1.1.0"],
    }
    before = {
        "package_manager": "pnpm",
        "vulnerabilities": {"child": {"via": [detail]}},
        "metadata": {"vulnerabilities": {"high": 1, "total": 1}},
    }
    after = {
        "package_manager": "pnpm",
        "vulnerabilities": {},
        "metadata": {"vulnerabilities": {"total": 0}},
    }
    assert helper["confirmed_fixes"](
        before, after, "pnpm", before_snapshot, after_snapshot
    ) == {detail["url"]}
    violation = helper["security_only_direct_violation"](
        before_snapshot,
        after_snapshot,
        {"child"},
        confirmed_ids={detail["url"]},
        audit_before=before,
        source="pnpm",
    )
    if direct_peer == "1.0.0":
        assert violation is None
    else:
        assert "dependencies.parent" in violation


@pytest.mark.parametrize("reverse_snapshots", [False, True])
def test_pnpm_parent_attribution_matches_plain_audit_to_reached_snapshot(
    site, reverse_snapshots
):
    manifest = json.loads((site / "package.json").read_text())
    manifest["dependencies"] = {"parent": "^1.0.0", "peer": "1.0.0"}
    (site / "package.json").write_text(json.dumps(manifest))

    def lock(parent_version, child_version, *, retain_other_context):
        snapshots = {
            f"parent@{parent_version}(peer@1.0.0)": {
                "dependencies": {
                    "child": f"{child_version}(peer@1.0.0)",
                    "peer": "1.0.0",
                }
            },
            f"child@{child_version}(peer@1.0.0)": {"dependencies": {"peer": "1.0.0"}},
            "child@1.0.0(peer@2.0.0)": {"dependencies": {"other-peer": "2.0.0"}},
            "peer@1.0.0": {},
            "other-peer@2.0.0": {},
        }
        if not retain_other_context:
            del snapshots["child@1.0.0(peer@2.0.0)"]
        if reverse_snapshots:
            snapshots = dict(reversed(list(snapshots.items())))
        package_versions = {
            f"parent@{parent_version}",
            "peer@1.0.0",
            "other-peer@2.0.0",
        }
        package_versions.add(f"child@{child_version}")
        if retain_other_context:
            package_versions.add("child@1.0.0")
        return {
            "lockfileVersion": "9.0",
            "importers": {
                ".": {
                    "dependencies": {
                        "parent": {
                            "specifier": "^1.0.0",
                            "version": f"{parent_version}(peer@1.0.0)",
                        },
                        "peer": {"specifier": "1.0.0", "version": "1.0.0"},
                    }
                }
            },
            "packages": {
                key: {"peerDependencies": {"peer": "*"}}
                if key.startswith(("parent@", "child@"))
                else {}
                for key in package_versions
            },
            "snapshots": snapshots,
        }

    old_lock = lock("1.0.0", "1.0.0", retain_other_context=True)
    new_lock = lock("1.1.0", "1.1.0", retain_other_context=False)
    (site / "pnpm-lock.yaml").write_text(yaml.safe_dump(old_lock, sort_keys=False))
    before_snapshot = helper["valid_snapshot"](site)
    (site / "pnpm-lock.yaml").write_text(yaml.safe_dump(new_lock, sort_keys=False))
    after_snapshot = helper["valid_snapshot"](site)
    detail = {
        "url": "https://github.com/advisories/GHSA-child",
        "nodes": ["child@1.0.0"],
        "_verifiedVulnerableVersions": ["1.0.0"],
        "_verifiedPatchedVersions": ["1.1.0"],
    }
    before = {
        "package_manager": "pnpm",
        "vulnerabilities": {"child": {"via": [detail]}},
        "metadata": {"vulnerabilities": {"high": 1, "total": 1}},
    }
    after = {
        "package_manager": "pnpm",
        "vulnerabilities": {},
        "metadata": {"vulnerabilities": {"total": 0}},
    }
    assert helper["_pnpm_dependency_reaches"](
        old_lock,
        "parent",
        "child",
        {"child@1.0.0"},
        {"1.0.0"},
    )
    assert helper["confirmed_fixes"](
        before, after, "pnpm", before_snapshot, after_snapshot
    ) == {detail["url"]}
    assert (
        helper["security_only_direct_violation"](
            before_snapshot,
            after_snapshot,
            {"child"},
            confirmed_ids={detail["url"]},
            audit_before=before,
            source="pnpm",
        )
        is None
    )


def test_security_only_allows_related_transitive_lockfile_changes(site):
    manifest = json.loads((site / "package.json").read_text())
    manifest["dependencies"]["unaffected"] = "^1.0.0"
    (site / "package.json").write_text(json.dumps(manifest))
    lock = yaml.safe_load((site / "pnpm-lock.yaml").read_text())
    lock["importers"]["."]["dependencies"]["unaffected"] = {
        "specifier": "^1.0.0",
        "version": "1.0.0",
    }
    lock["packages"].update({"unaffected@1.0.0": {}, "transitive@2.0.0": {}})
    (site / "pnpm-lock.yaml").write_text(yaml.safe_dump(lock))
    before = helper["valid_snapshot"](site)
    lock["packages"]["transitive@2.1.0"] = {}
    del lock["packages"]["transitive@2.0.0"]
    (site / "pnpm-lock.yaml").write_text(yaml.safe_dump(lock))
    after = helper["valid_snapshot"](site)
    assert helper["security_only_direct_violation"](before, after, {"renderer"}) is None


def test_security_only_discards_disjoint_transitive_regeneration(site, monkeypatch):
    manifest = json.loads((site / "package.json").read_text())
    manifest["dependencies"] = {"renderer": "^1.2.3", "carrier": "1.0.0"}
    (site / "package.json").write_text(json.dumps(manifest))

    def write_lock(fixed):
        renderer = "1.3.0" if fixed else "1.2.3"
        unrelated = "2.1.0" if fixed else "2.0.0"
        lock = {
            "lockfileVersion": "9.0",
            "importers": {
                ".": {
                    "dependencies": {
                        "renderer": {
                            "specifier": "^1.2.3",
                            "version": renderer,
                        },
                        "carrier": {"specifier": "1.0.0", "version": "1.0.0"},
                    }
                }
            },
            "packages": {
                f"renderer@{renderer}": {},
                "carrier@1.0.0": {},
                f"unrelated@{unrelated}": {},
            },
            "snapshots": {
                f"renderer@{renderer}": {},
                "carrier@1.0.0": {"dependencies": {"unrelated": unrelated}},
                f"unrelated@{unrelated}": {},
            },
        }
        (site / "pnpm-lock.yaml").write_text(yaml.safe_dump(lock))

    write_lock(False)
    commands = []

    def transport(directory, *args, **kwargs):
        commands.append(args)
        if args[:2] == ("audit", "--fix=update"):
            return subprocess.CompletedProcess(args, 1, "", "")
        if args[:2] == ("install", "--lockfile-only"):
            assert not (site / "pnpm-lock.yaml").exists()
            write_lock(True)
        if args[:2] == ("audit", "--json"):
            fixed = (
                "renderer@1.3.0"
                in yaml.safe_load((site / "pnpm-lock.yaml").read_text())["packages"]
            )
            advisories = (
                {}
                if fixed
                else {
                    "1": {
                        "module_name": "renderer",
                        "severity": "high",
                        "title": "Renderer issue",
                        "url": "https://example.invalid/advisory",
                        "vulnerable_versions": "<1.3.0",
                        "patched_versions": ">=1.3.0",
                        "findings": [{"version": "1.2.3", "paths": [".>renderer"]}],
                    }
                }
            )
            data = {
                "advisories": advisories,
                "metadata": {
                    "vulnerabilities": {
                        "high": 0 if fixed else 1,
                        "total": 0 if fixed else 1,
                    }
                },
            }
            return subprocess.CompletedProcess(
                args, 0 if fixed else 1, json.dumps(data), ""
            )
        if args[0] == "view":
            versions = ["1.2.3"] if args[1] == "renderer@<1.3.0" else ["1.3.0"]
            return subprocess.CompletedProcess(args, 0, json.dumps(versions), "")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setitem(helper["prepare"].__globals__, "run", transport)
    validation = {}
    report = helper["prepare"](
        site, maintenance_mode="security-only", validation=validation
    )
    lock = yaml.safe_load((site / "pnpm-lock.yaml").read_text())
    assert "unrelated@2.0.0" in lock["packages"]
    assert "unrelated@2.1.0" not in lock["packages"]
    assert validation["passed"]
    assert "Discarded dependency changes" in report
    assert any(args[:2] == ("install", "--lockfile-only") for args in commands)


@pytest.mark.parametrize("update_renderer_child", [False, True])
def test_security_only_rejects_disjoint_peer_context_transitive_regeneration(
    site, monkeypatch, update_renderer_child
):
    manifest = json.loads((site / "package.json").read_text())
    manifest["dependencies"] = {"renderer": "^1.2.3", "carrier": "1.0.0"}
    (site / "package.json").write_text(json.dumps(manifest))

    def write_lock(fixed):
        renderer = "1.3.0" if fixed else "1.2.3"
        child = "2.1.0" if fixed else "2.0.0"
        allowed_child = "1.1.0" if fixed and update_renderer_child else "1.0.0"
        packages = {
            f"renderer@{renderer}": {},
            "carrier@1.0.0": {},
            "intermediate@1.0.0": {"peerDependencies": {"peer": "*"}},
            "intermediate@2.0.0": {"peerDependencies": {"peer": "*"}},
            f"child@{allowed_child}": {},
            f"child@{child}": {},
            "peer@1.0.0": {},
            "peer@2.0.0": {},
        }
        snapshots = {
            f"renderer@{renderer}": {
                "dependencies": {
                    "intermediate": "1.0.0(peer@1.0.0)",
                    "peer": "1.0.0",
                }
            },
            "carrier@1.0.0": {
                "dependencies": {
                    "intermediate": "2.0.0(peer@2.0.0)",
                    "peer": "2.0.0",
                }
            },
            "intermediate@1.0.0(peer@1.0.0)": {
                "dependencies": {"child": allowed_child, "peer": "1.0.0"}
            },
            "intermediate@2.0.0(peer@2.0.0)": {
                "dependencies": {"child": child, "peer": "2.0.0"}
            },
            f"child@{allowed_child}": {},
            f"child@{child}": {},
            "peer@1.0.0": {},
            "peer@2.0.0": {},
        }
        lock = {
            "lockfileVersion": "9.0",
            "importers": {
                ".": {
                    "dependencies": {
                        "renderer": {
                            "specifier": "^1.2.3",
                            "version": renderer,
                        },
                        "carrier": {
                            "specifier": "1.0.0",
                            "version": "1.0.0",
                        },
                    }
                }
            },
            "packages": packages,
            "snapshots": snapshots,
        }
        (site / "pnpm-lock.yaml").write_text(yaml.safe_dump(lock))

    write_lock(False)
    commands = []

    def transport(directory, *args, **kwargs):
        commands.append(args)
        if args[:2] == ("audit", "--fix=update"):
            return subprocess.CompletedProcess(args, 1, "", "")
        if args[:2] == ("install", "--lockfile-only"):
            assert not (site / "pnpm-lock.yaml").exists()
            write_lock(True)
        if args[:2] == ("audit", "--json"):
            fixed = (
                "renderer@1.3.0"
                in yaml.safe_load((site / "pnpm-lock.yaml").read_text())["packages"]
            )
            advisories = (
                {}
                if fixed
                else {
                    "1": {
                        "module_name": "renderer",
                        "severity": "high",
                        "title": "Renderer issue",
                        "url": "https://example.invalid/renderer-fix",
                        "vulnerable_versions": "<1.3.0",
                        "patched_versions": ">=1.3.0",
                        "findings": [{"version": "1.2.3", "paths": [".>renderer"]}],
                    }
                }
            )
            data = {
                "advisories": advisories,
                "metadata": {
                    "vulnerabilities": {
                        "high": 0 if fixed else 1,
                        "total": 0 if fixed else 1,
                    }
                },
            }
            return subprocess.CompletedProcess(
                args, 0 if fixed else 1, json.dumps(data), ""
            )
        if args[0] == "view":
            versions = ["1.2.3"] if args[1] == "renderer@<1.3.0" else ["1.3.0"]
            return subprocess.CompletedProcess(args, 0, json.dumps(versions), "")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setitem(helper["prepare"].__globals__, "run", transport)
    validation = {}
    report = helper["prepare"](
        site, maintenance_mode="security-only", validation=validation
    )
    final = yaml.safe_load((site / "pnpm-lock.yaml").read_text())
    assert "child@2.0.0" in final["packages"]
    assert "child@2.1.0" not in final["packages"]
    assert "intermediate@2.0.0(peer@2.0.0)" in final["snapshots"]
    assert validation["passed"]
    assert "Discarded dependency changes" in report
    assert any(args[:2] == ("install", "--lockfile-only") for args in commands)


@pytest.mark.parametrize("nested", [False, True])
def test_npm_security_only_discards_disjoint_transitive_updates(
    site, monkeypatch, nested
):
    manifest = json.loads((site / "package.json").read_text())
    manifest["packageManager"] = "npm@11.4.2"
    manifest["dependencies"] = {"renderer": "^1.2.3", "carrier": "1.0.0"}
    (site / "package.json").write_text(json.dumps(manifest))
    (site / "pnpm-lock.yaml").unlink()
    (site / "pnpm-workspace.yaml").unlink()
    unrelated_node = (
        "node_modules/carrier/node_modules/unrelated"
        if nested
        else "node_modules/unrelated"
    )

    def write_lock(fixed):
        lock = {
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": manifest["dependencies"]},
                "node_modules/renderer": {"version": "1.3.0" if fixed else "1.2.3"},
                "node_modules/carrier": {
                    "version": "1.0.0",
                    "dependencies": {"unrelated": "^2.0.0"},
                },
                unrelated_node: {"version": "2.1.0" if fixed else "2.0.0"},
            },
        }
        (site / "package-lock.json").write_text(json.dumps(lock))

    write_lock(False)
    commands = []

    def transport(directory, *args, **kwargs):
        commands.append(args)
        if args[:2] == ("audit", "fix"):
            write_lock(True)
        if args[:2] == ("audit", "--json"):
            lock = json.loads((site / "package-lock.json").read_text())
            fixed = lock["packages"]["node_modules/renderer"]["version"] == "1.3.0"
            data = {
                "vulnerabilities": {}
                if fixed
                else {
                    "renderer": {
                        "name": "renderer",
                        "severity": "high",
                        "isDirect": True,
                        "via": [
                            {
                                "source": 1,
                                "name": "renderer",
                                "title": "Renderer issue",
                                "url": "https://example.invalid/renderer-fix",
                                "severity": "high",
                                "range": "<1.3.0",
                            }
                        ],
                        "effects": [],
                        "range": "<1.3.0",
                        "nodes": ["node_modules/renderer"],
                        "fixAvailable": True,
                    }
                },
                "metadata": {
                    "vulnerabilities": {
                        "high": 0 if fixed else 1,
                        "total": 0 if fixed else 1,
                    }
                },
            }
            return subprocess.CompletedProcess(
                args, 0 if fixed else 1, json.dumps(data), ""
            )
        if args[0] == "view":
            specifier = args[1]
            if specifier == "renderer@1.3.0 <1.3.0":
                error = {
                    "error": {
                        "code": "E404",
                        "summary": "No match found for version 1.3.0 <1.3.0",
                    }
                }
                return subprocess.CompletedProcess(args, 1, json.dumps(error), "")
            versions = ["1.3.0"] if specifier == "renderer@1.3.0" else ["1.2.3"]
            return subprocess.CompletedProcess(args, 0, json.dumps(versions), "")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setitem(helper["prepare"].__globals__, "run", transport)
    validation = {}
    report = helper["prepare"](
        site, maintenance_mode="security-only", validation=validation
    )
    final = json.loads((site / "package-lock.json").read_text())
    assert final["packages"][unrelated_node]["version"] == "2.0.0"
    assert "Discarded dependency changes" in report
    assert validation["passed"]
    assert any(args[:2] == ("audit", "fix") for args in commands)
    assert any(args[:2] == ("view", "renderer@1.3.0 <1.3.0") for args in commands)


def test_security_only_allows_required_nested_version_for_direct_name(site):
    manifest = json.loads((site / "package.json").read_text())
    manifest["dependencies"] = {"renderer": "^1.2.3", "shared": "1.0.0"}
    (site / "package.json").write_text(json.dumps(manifest))
    old_lock = {
        "lockfileVersion": "9.0",
        "importers": {
            ".": {
                "dependencies": {
                    "renderer": {"specifier": "^1.2.3", "version": "1.2.3"},
                    "shared": {"specifier": "1.0.0", "version": "1.0.0"},
                }
            }
        },
        "packages": {"renderer@1.2.3": {}, "shared@1.0.0": {}},
        "snapshots": {"renderer@1.2.3": {}, "shared@1.0.0": {}},
    }
    new_lock = {
        "lockfileVersion": "9.0",
        "importers": {
            ".": {
                "dependencies": {
                    "renderer": {"specifier": "^1.2.3", "version": "1.3.0"},
                    "shared": {"specifier": "1.0.0", "version": "1.0.0"},
                }
            }
        },
        "packages": {
            "renderer@1.3.0": {},
            "shared@1.0.0": {},
            "shared@2.0.0": {},
        },
        "snapshots": {
            "renderer@1.3.0": {"dependencies": {"shared": "2.0.0"}},
            "shared@1.0.0": {},
            "shared@2.0.0": {},
        },
    }
    (site / "pnpm-lock.yaml").write_text(yaml.safe_dump(old_lock, sort_keys=False))
    before_snapshot = helper["valid_snapshot"](site)
    (site / "pnpm-lock.yaml").write_text(yaml.safe_dump(new_lock, sort_keys=False))
    after_snapshot = helper["valid_snapshot"](site)
    detail = {
        "url": "https://example.invalid/renderer-advisory",
        "nodes": ["renderer@1.2.3"],
        "_verifiedVulnerableVersions": ["1.2.3"],
        "_verifiedPatchedVersions": ["1.3.0"],
    }
    before = {
        "package_manager": "pnpm",
        "vulnerabilities": {"renderer": {"via": [detail]}},
        "metadata": {"vulnerabilities": {"high": 1, "total": 1}},
    }
    after = {
        "package_manager": "pnpm",
        "vulnerabilities": {},
        "metadata": {"vulnerabilities": {"total": 0}},
    }
    assert helper["confirmed_fixes"](
        before, after, "pnpm", before_snapshot, after_snapshot
    ) == {detail["url"]}
    assert helper["direct_versions"](before_snapshot)[("dependencies", "shared")] == (
        1,
        0,
        0,
    )
    assert helper["direct_versions"](after_snapshot)[("dependencies", "shared")] == (
        1,
        0,
        0,
    )
    assert (
        helper["security_only_direct_violation"](
            before_snapshot,
            after_snapshot,
            {"renderer"},
            confirmed_ids={detail["url"]},
            audit_before=before,
            source="pnpm",
        )
        is None
    )


def test_upgrades_mode_can_retain_an_independent_direct_upgrade(site, monkeypatch):
    manifest = json.loads((site / "package.json").read_text())
    manifest["dependencies"]["unaffected"] = "^1.0.0"
    (site / "package.json").write_text(json.dumps(manifest))
    lock_path = site / "pnpm-lock.yaml"
    lock = yaml.safe_load(lock_path.read_text())
    lock["importers"]["."]["dependencies"]["unaffected"] = {
        "specifier": "^1.0.0",
        "version": "1.0.0",
    }
    lock["packages"]["unaffected@1.0.0"] = {}
    lock_path.write_text(yaml.safe_dump(lock))
    before = _renderer_finding()
    audit_calls = 0

    def audit(*args, **kwargs):
        nonlocal audit_calls
        audit_calls += 1
        return before if audit_calls == 1 else _clear_finding()

    def write_resolved_lock(directory):
        current = json.loads((directory / "package.json").read_text())
        resolved = {
            name: {
                "specifier": specifier,
                "version": specifier.lstrip("~^"),
            }
            for name, specifier in current["dependencies"].items()
        }
        value = {
            "lockfileVersion": "9.0",
            "importers": {".": {"dependencies": resolved}},
            "packages": {
                f"{name}@{entry['version']}": {} for name, entry in resolved.items()
            },
        }
        (directory / "pnpm-lock.yaml").write_text(yaml.safe_dump(value))

    def invoke(directory, *args, **kwargs):
        if args[0] == "view" and args[2] == "versions":
            return subprocess.CompletedProcess(
                args, 0, json.dumps(["1.2.4", "1.3.0"]), ""
            )
        if args[0] == "view" and args[2] == "time":
            return subprocess.CompletedProcess(
                args,
                0,
                json.dumps(
                    {
                        "1.2.4": "2020-01-01T00:00:00Z",
                        "1.3.0": "2020-01-01T00:00:00Z",
                    }
                ),
                "",
            )
        if args[0] == "install" and "--lockfile-only" in args:
            write_resolved_lock(directory)
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setitem(helper["prepare"].__globals__, "run", invoke)
    monkeypatch.setitem(helper["prepare"].__globals__, "audit", audit)
    monkeypatch.setitem(
        helper["prepare"].__globals__,
        "fix_security",
        lambda *a, **k: subprocess.CompletedProcess([], 0, "", ""),
    )
    monkeypatch.setitem(
        helper["prepare"].__globals__, "describe_pnpm_fixes", lambda *a, **k: None
    )
    helper["prepare"](
        site,
        maintenance_mode="security-and-maintenance",
        upgrade_scope="minor",
    )
    final = helper["valid_snapshot"](site)
    assert helper["direct_versions"](final)[("dependencies", "renderer")] == (1, 3, 0)
    assert helper["direct_versions"](final)[("dependencies", "unaffected")] == (1, 3, 0)


def test_headline_counts_advisories_and_critical_findings_not_packages(
    site, monkeypatch
):
    fake_commands(monkeypatch)
    findings = {
        "vulnerabilities": {},
        "metadata": {
            "vulnerabilities": {"critical": 2, "high": 1, "moderate": 1, "total": 4}
        },
    }
    for index, (name, severity) in enumerate(
        (
            ("worker", "critical"),
            ("worker", "critical"),
            ("parser", "high"),
            ("selector", "moderate"),
        )
    ):
        package = findings["vulnerabilities"].setdefault(
            name, {"severity": severity, "range": "*", "nodes": [], "via": []}
        )
        package["via"].append(
            {
                "url": f"https://github.com/advisories/GHSA-test-{index}",
                "title": "Test finding",
                "severity": severity,
                "range": "*",
                "nodes": [],
            }
        )
    monkeypatch.setitem(
        helper["prepare"].__globals__, "audit", lambda *a, **k: findings
    )
    report = helper["prepare"](site)
    assert report.startswith(
        "**1 dependency update · 0 security fixes · 4 advisories remain (2 critical) · Build passed**"
    )


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


@pytest.mark.parametrize(
    ("package_manager", "peer_context"),
    [("npm", ""), ("pnpm", ""), ("pnpm", "(peer@1.0.0)")],
)
@pytest.mark.parametrize(
    ("parent_changed", "sibling_changed"),
    [(False, False), (False, True), (True, True)],
)
def test_security_only_limits_unchanged_parent_to_remediation_path(
    site, package_manager, peer_context, parent_changed, sibling_changed
):
    manifest = json.loads((site / "package.json").read_text())
    manifest["packageManager"] = f"{package_manager}@11.21.0"
    manifest["dependencies"] = {"parent": "^1.0.0"}
    (site / "package.json").write_text(json.dumps(manifest))
    if package_manager == "npm":
        (site / "pnpm-lock.yaml").unlink()
        (site / "pnpm-workspace.yaml").unlink()

    def snapshot(fixed):
        versions = {
            "parent": "1.1.0" if fixed and parent_changed else "1.0.0",
            "child": "1.1.0" if fixed else "1.0.0",
            "sibling": "1.1.0" if fixed and sibling_changed else "1.0.0",
        }
        if package_manager == "npm":
            packages = {
                f"node_modules/{name}": {"version": version}
                for name, version in versions.items()
            }
            packages[""] = {"dependencies": manifest["dependencies"]}
            packages["node_modules/parent"]["dependencies"] = {
                "child": "^1.0.0",
                "sibling": "^1.0.0",
            }
            (site / "package-lock.json").write_text(
                json.dumps({"lockfileVersion": 3, "packages": packages})
            )
        else:
            references = {
                name: version + (peer_context if name == "child" else "")
                for name, version in versions.items()
            }
            snapshots = {
                f"{name}@{version}": {} for name, version in references.items()
            }
            snapshots[f"parent@{versions['parent']}"]["dependencies"] = {
                name: references[name] for name in ("child", "sibling")
            }
            lock = {
                "lockfileVersion": "9.0",
                "importers": {
                    ".": {
                        "dependencies": {
                            "parent": {
                                "specifier": "^1.0.0",
                                "version": versions["parent"],
                            }
                        }
                    }
                },
                "packages": {node: {} for node in snapshots},
                "snapshots": snapshots,
            }
            (site / "pnpm-lock.yaml").write_text(yaml.safe_dump(lock))
        return helper["valid_snapshot"](site)

    before_snapshot, after_snapshot = snapshot(False), snapshot(True)
    detail = {
        "url": "https://example.invalid/child-advisory",
        "nodes": ["child@1.0.0" if package_manager == "pnpm" else "node_modules/child"],
        "_verifiedVulnerableVersions": ["1.0.0"],
        "_verifiedPatchedVersions": ["1.1.0"],
    }
    vulnerability = {"via": [detail]} if package_manager == "pnpm" else detail
    before = {
        "package_manager": package_manager,
        "vulnerabilities": {"child": vulnerability},
    }
    confirmed = {detail["url"] if package_manager == "pnpm" else "child"}
    violation = helper["security_only_direct_violation"](
        before_snapshot,
        after_snapshot,
        {"child"},
        confirmed_ids=confirmed,
        audit_before=before,
        source=package_manager,
    )
    if sibling_changed and not parent_changed:
        assert violation and "sibling transitive dependency changed" in violation
    else:
        assert violation is None
