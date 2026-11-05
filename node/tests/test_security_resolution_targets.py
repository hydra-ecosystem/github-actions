import copy
import runpy
import subprocess
from pathlib import Path

import pytest
import yaml
from test_dependency_audit_repairs import project as project

engine = runpy.run_path(
    str(Path(__file__).parents[1] / "runtime/templates/dependency_audit.py")
)


@pytest.mark.parametrize("name", ["child", "@scope/child"])
@pytest.mark.parametrize("failure", [None, "exit", "invalid"])
@pytest.mark.parametrize("already_patched", [False, True])
def test_verified_target_refresh_preserves_lock_and_rolls_back_failures(
    project, monkeypatch, name, failure, already_patched
):
    lockfile = project / "pnpm-lock.yaml"
    lock = yaml.safe_load(lockfile.read_bytes())
    lock["packages"].pop("child@1.0.0")
    lock["packages"][name + "@1.0.0"] = {}
    lock.setdefault("snapshots", {})[name + "@1.0.0"] = {}
    lock["snapshots"][name + "@1.0.0(peer@2.0.0)"] = {"optional": True}
    lock["packages"]["unrelated@2.0.0"] = {"resolution": {"integrity": "keep"}}
    lock["snapshots"]["unrelated@2.0.0"] = {}
    lock["snapshots"]["parent@1.0.0"]["dependencies"] = {name: "1.0.0"}
    lockfile.write_text(yaml.safe_dump(lock))
    initial = engine["valid_snapshot"](project)
    preceding = copy.deepcopy(lock)
    if already_patched:
        preceding["packages"][name + "@1.0.1"] = {"resolution": {"integrity": "keep"}}
        preceding["snapshots"][name + "@1.0.1"] = {}
    preceding_bytes = yaml.safe_dump(preceding).encode()
    commands = []
    checkpoints = []

    def invoke(directory, *args, **kwargs):
        commands.append(args)
        if args[0] == "audit":
            lockfile.write_bytes(preceding_bytes)
            return subprocess.CompletedProcess(args, 1, "remaining findings", "")
        assert args[:2] == ("update", "--no-save")
        checkpoints.append((project / "pnpm-workspace.yaml").read_bytes())
        assert args[2] == name and "--ignore-scripts" in args
        retained = yaml.safe_load(lockfile.read_bytes())
        expected = copy.deepcopy(preceding)
        for section in ("packages", "snapshots"):
            expected[section].pop(name + "@1.0.0")
        expected["snapshots"].pop(name + "@1.0.0(peer@2.0.0)")
        assert retained == expected
        modules = next(
            a.split("=", 1)[1] for a in args if a.startswith("--config.modules-dir=")
        )
        assert Path(modules) != project / "node_modules"
        assert f"--config.virtual-store-dir={Path(modules) / '.pnpm'}" in args
        proposed = copy.deepcopy(preceding)
        proposed["packages"].pop(name + "@1.0.0")
        proposed["packages"][name + "@1.0.1"] = {}
        proposed["snapshots"].pop(name + "@1.0.0")
        proposed["snapshots"].pop(name + "@1.0.0(peer@2.0.0)")
        proposed["snapshots"][name + "@1.0.1"] = {}
        proposed["snapshots"]["parent@1.0.0"]["dependencies"][name] = "1.0.1"
        lockfile.write_text("[" if failure == "invalid" else yaml.safe_dump(proposed))
        return subprocess.CompletedProcess(args, 2 if failure == "exit" else 0, "", "")

    def describe(directory, data, *args, **kwargs):
        for finding in data["vulnerabilities"].values():
            for detail in finding["via"]:
                detail.update(fixVersion="1.0.1", _verifiedVulnerableVersions=["1.0.0"])

    monkeypatch.setitem(engine["fix_security"].__globals__, "run", invoke)
    monkeypatch.setitem(
        engine["fix_security"].__globals__, "describe_pnpm_fixes", describe
    )
    notes = []
    before = {"package_manager": "pnpm", "vulnerabilities": {name: {"via": [{}]}}}
    engine["fix_security"](project, float("inf"), notes, before=before)
    assert len(commands) == 2
    if failure:
        assert lockfile.read_bytes() == preceding_bytes
        assert (project / "package.json").read_bytes() == initial[0]
        assert (project / "pnpm-workspace.yaml").read_bytes() == checkpoints[0]
        assert "refresh failed" in notes[-1]
    else:
        final = engine["valid_snapshot"](project)
        assert name + "@1.0.1" in final[3]["packages"]
        assert (
            yaml.safe_load(final[1]["pnpm-lock.yaml"])["snapshots"]["parent@1.0.0"][
                "dependencies"
            ][name]
            == "1.0.1"
        )
        assert (project / "package.json").read_bytes() == initial[0]


@pytest.mark.parametrize("reason", ["mixed-versions", "no-proof", "option-name"])
def test_unverified_or_mixed_targets_never_trigger_broad_refresh(
    project, monkeypatch, reason
):
    name = "--latest" if reason == "option-name" else "child"
    lockfile = project / "pnpm-lock.yaml"
    lock = yaml.safe_load(lockfile.read_bytes())
    if reason == "mixed-versions":
        lock["packages"]["child@2.0.0"] = {}
    elif reason == "option-name":
        lock["packages"].pop("child@1.0.0")
        lock["packages"]["--latest@1.0.0"] = {}
    lockfile.write_text(yaml.safe_dump(lock))
    initial = engine["valid_snapshot"](project)

    def invoke(directory, *args, **kwargs):
        assert args[:2] == ("audit", "--fix=update")
        return subprocess.CompletedProcess(args, 1, "remaining findings", "")

    def describe(directory, data, *args, **kwargs):
        for finding in data["vulnerabilities"].values():
            for detail in finding["via"]:
                if reason != "no-proof":
                    detail.update(
                        fixVersion="1.0.1", _verifiedVulnerableVersions=["1.0.0"]
                    )

    monkeypatch.setitem(engine["fix_security"].__globals__, "run", invoke)
    monkeypatch.setitem(
        engine["fix_security"].__globals__, "describe_pnpm_fixes", describe
    )
    before = {"package_manager": "pnpm", "vulnerabilities": {name: {"via": [{}]}}}
    result = engine["fix_security"](project, float("inf"), before=before)
    assert result.returncode == 1
    assert (project / "package.json").read_bytes() == initial[0]
    assert lockfile.read_bytes() == initial[1]["pnpm-lock.yaml"]
