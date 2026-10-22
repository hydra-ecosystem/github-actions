"""Public standalone Node interface: no framework or build requirement."""

import json
import runpy
import subprocess
from pathlib import Path
from datetime import datetime, timedelta, timezone

import pytest

RUNTIME = Path(__file__).parents[1] / "runtime"
project = runpy.run_path(str(RUNTIME / "project.py"))
engine = runpy.run_path(str(RUNTIME / "templates/dependency_audit.py"))


@pytest.fixture(autouse=True)
def node_release_index(monkeypatch):
    monkeypatch.setitem(
        project["NODE_SECURITY"]["verify_node_security"].__globals__,
        "read_release_index",
        lambda: '[{"version":"v24.22.1","security":true}]',
    )


def make_project(root, directory=".", manager="npm", version="11.9.0"):
    path = root / directory
    path.mkdir(parents=True, exist_ok=True)
    (root / ".github").mkdir(exist_ok=True)
    (root / ".github/node-maintenance.json").write_text(
        json.dumps(
            {
                "directory": directory,
                "validationScript": "check",
                "maintenance": {"mode": "security-only"},
            }
        )
    )
    (path / ".nvmrc").write_text("24")
    manifest = {
        "name": "plain-library",
        "version": "1.0.0",
        "packageManager": f"{manager}@{version}",
        "scripts": {"check": "node --test"},
        "dependencies": {"is-number": "7.0.0"},
    }
    (path / "package.json").write_text(json.dumps(manifest))
    if manager == "npm":
        (path / "package-lock.json").write_text(
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "": manifest,
                        "node_modules/is-number": {"version": "7.0.0"},
                    },
                }
            )
        )
    else:
        (path / "pnpm-workspace.yaml").write_text(
            "packages: ['.']\nminimumReleaseAge: 14400\n"
        )
        (path / "pnpm-lock.yaml").write_text(
            "lockfileVersion: '9.0'\nimporters: {'.': {}}\npackages: {}\n"
        )
    return path


@pytest.mark.parametrize("directory", [".", "packages/standalone library"])
@pytest.mark.parametrize("manager,version", [("npm", "11.9.0"), ("pnpm", "11.21.0")])
def test_plain_node_preflight_without_docusaurus_or_build(
    tmp_path, monkeypatch, directory, manager, version
):
    path = make_project(tmp_path, directory, manager, version)
    commands = []

    def invoke(command, **kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(
            command, 0, "v24.22.1" if command[0] == "node" else version, ""
        )

    monkeypatch.setattr(subprocess, "run", invoke)
    selected_path, selected = project["project"](tmp_path)
    assert selected_path == path.resolve()
    assert selected["manager"] == manager and selected["validationScript"] == "check"
    project["verify_runtime"](path, selected)
    assert (
        ["npm", "--version"] if manager == "npm" else ["corepack", "pnpm", "--version"]
    ) in commands


@pytest.mark.parametrize("manager,version", [("npm", "11.9.0"), ("pnpm", "11.21.0")])
@pytest.mark.parametrize("kind", ["symlink", "dangling-symlink", "directory"])
def test_preflight_rejects_nonregular_manifest_without_touching_target(
    tmp_path, monkeypatch, manager, version, kind
):
    path = make_project(tmp_path, "app", manager, version)
    manifest = path / "package.json"
    original = manifest.read_bytes()
    manifest.unlink()
    outside = tmp_path / "shared-package.json"
    if kind == "directory":
        manifest.mkdir()
    else:
        if kind == "symlink":
            outside.write_bytes(original)
        manifest.symlink_to(outside)

    def unexpected_command(*args, **kwargs):
        pytest.fail("preflight must reject the manifest before running commands")

    monkeypatch.setattr(subprocess, "run", unexpected_command)
    with pytest.raises(ValueError, match="package.json.*regular"):
        project["project"](tmp_path)
    if kind == "symlink":
        assert outside.read_bytes() == original
    else:
        assert not outside.exists()


@pytest.mark.parametrize(
    "case",
    [
        "workspaces",
        "linked-package",
        "mixed-lockfiles",
        "npm-shrinkwrap",
        "npm-shrinkwrap-symlink",
        "npm-shrinkwrap-dangling-symlink",
        "wrong-lock-version",
        "wrong-runtime",
        "declaration-lock-mismatch",
    ],
)
def test_reject_unsupported_project_before_dependency_changes(
    tmp_path, monkeypatch, case
):
    path = make_project(tmp_path)
    manifest_path, lock_path = path / "package.json", path / "package-lock.json"
    manifest, lock = (
        json.loads(manifest_path.read_text()),
        json.loads(lock_path.read_text()),
    )
    if case == "workspaces":
        manifest["workspaces"] = ["packages/*"]
    elif case == "linked-package":
        lock["packages"]["node_modules/linked"] = {
            "link": True,
            "resolved": "packages/linked",
        }
    elif case in ("mixed-lockfiles", "declaration-lock-mismatch"):
        (path / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n")
        if case == "declaration-lock-mismatch":
            lock_path.unlink()
    elif case.startswith("npm-shrinkwrap"):
        shrinkwrap = path / "npm-shrinkwrap.json"
        if case == "npm-shrinkwrap":
            shrinkwrap.write_text("{}")
        else:
            target = path / "shrinkwrap-target"
            if case == "npm-shrinkwrap-symlink":
                target.write_text("{}")
            shrinkwrap.symlink_to(target)
    elif case == "wrong-lock-version":
        lock["lockfileVersion"] = 2
    manifest_path.write_text(json.dumps(manifest))
    if case != "declaration-lock-mismatch":
        lock_path.write_text(json.dumps(lock))
    before = {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(
            command,
            0,
            "v24.22.1"
            if command[0] == "node"
            else ("11.8.0" if case == "wrong-runtime" else "11.9.0"),
            "",
        ),
    )
    with pytest.raises((ValueError, OSError)) as error:
        _, selected = project["project"](tmp_path)
        project["verify_runtime"](path, selected)
    if case.startswith("npm-shrinkwrap"):
        assert "npm-shrinkwrap" in str(error.value)
    assert all(p.read_bytes() == data for p, data in before.items())


def test_npm_script_validation_and_security_resolution_use_cooldown(
    tmp_path, monkeypatch
):
    path = make_project(tmp_path)
    commands = []

    def invoke(directory, *args, **kwargs):
        commands.append(args)
        if args[0] == "audit":
            return subprocess.CompletedProcess(
                args,
                0,
                '{"vulnerabilities": {}, "metadata": {"vulnerabilities": {"total": 0}}}',
                "",
            )
        if args[0] == "view":
            return subprocess.CompletedProcess(args, 0, '"7.0.0"', "")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setitem(engine["prepare"].__globals__, "run", invoke)
    validation = {}
    report = engine["prepare"](
        path,
        validation=validation,
        validation_script="check",
        minimum_release_age_days=10,
    )
    assert validation["passed"] and "Project checks: passed." in report
    assert ("ci", "--no-audit") in commands and ("run", "check") in commands
    mutators = [c for c in commands if c[:2] == ("audit", "fix") or c[0] == "install"]
    assert mutators and all("--before" in c for c in mutators)
    cutoffs = {c[c.index("--before") + 1] for c in mutators}
    assert len(cutoffs) == 1
    assert (
        abs(
            (
                datetime.now(timezone.utc) - datetime.fromisoformat(cutoffs.pop())
            ).total_seconds()
            - 10 * 86400
        )
        < 10
    )


def test_npm_cooldown_selects_old_enough_release(tmp_path, monkeypatch):
    path = make_project(tmp_path)
    now = datetime.now(timezone.utc)
    metadata = {
        "8.0.0": (now - timedelta(days=20)).isoformat(),
        "9.0.0": (now - timedelta(days=1)).isoformat(),
    }
    monkeypatch.setitem(
        engine["eligible_version"].__globals__,
        "run",
        lambda *a, **kw: subprocess.CompletedProcess([], 0, json.dumps(metadata), ""),
    )
    assert (
        engine["eligible_version"](
            path,
            "is-number",
            "9.0.0",
            engine["valid_snapshot"](path),
            [],
            float("inf"),
            minimum_release_age=14400,
        )
        == "8.0.0"
    )


def test_npm_publication_cutoff_does_not_allow_locked_downgrade(tmp_path):
    path = make_project(tmp_path)
    before = engine["valid_snapshot"](path)
    lock_path = path / "package-lock.json"
    lock = json.loads(lock_path.read_text())
    lock["packages"]["node_modules/is-number"]["version"] = "6.0.0"
    lock_path.write_text(json.dumps(lock))
    notes = []
    assert engine["restore_invalid_state"](path, before, notes, "Cooldown resolution")
    assert engine["valid_snapshot"](path) == before and "lowered" in notes[0]


def test_reject_ancestor_workspace(tmp_path):
    make_project(tmp_path, "packages/library")
    (tmp_path / "package.json").write_text(json.dumps({"workspaces": ["packages/*"]}))
    with pytest.raises(ValueError, match="ancestor workspace"):
        project["project"](tmp_path)


def test_npm_integrity_suffix_is_not_silently_ignored(tmp_path):
    path = make_project(tmp_path)
    manifest_path = path / "package.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["packageManager"] = "npm@11.9.0+sha512." + "a" * 128
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="npm integrity suffix"):
        project["project"](tmp_path)
