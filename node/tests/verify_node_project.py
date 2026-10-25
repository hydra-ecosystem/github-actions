"""Run real dependency maintenance and validation on a standalone Node library."""

import argparse
import json
import os
import runpy
import shutil
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch

import yaml

ROOT = Path(__file__).parents[1]


def check_pnpm_repair(project, command, version):
    """Exercise real hooks and selected resolution through production primitives."""
    repair = runpy.run_path(str(ROOT / "runtime/repair.py"))
    engine = repair["ENGINE"]
    fixture = project.parent / "repair"
    fixture.mkdir()
    markers = {
        kind: fixture / f"{kind}-executed" for kind in ("local", "global", "lifecycle")
    }
    for kind in ("local", "global"):
        hook = fixture / (".pnpmfile.cjs" if kind == "local" else "global-pnpmfile.cjs")
        hook.write_text(
            "require('node:fs').writeFileSync("
            + json.dumps(str(markers[kind]))
            + ", 'executed');\nmodule.exports = {};\n"
        )
    policy = yaml.safe_load(
        (ROOT / "runtime/templates/pnpm-workspace.yaml").read_text()
    )
    policy.update(
        overrides={"semver": "7.5.1"},
        globalPnpmfile=str(fixture / "global-pnpmfile.cjs"),
    )
    workspace = fixture / "pnpm-workspace.yaml"
    workspace.write_text(yaml.safe_dump(policy))
    (fixture / "package.json").write_text(
        json.dumps(
            {
                "name": "repair-hook-fixture",
                "private": True,
                "version": "1.0.0",
                "packageManager": f"pnpm@{version}",
                "dependencies": {
                    "semver": "^7.5.1",
                    "react": "18.2.0",
                    "react-dom": "18.2.0",
                },
                "scripts": {
                    "preinstall": "node -e "
                    + json.dumps(
                        "require('node:fs').writeFileSync("
                        + json.dumps(str(markers["lifecycle"]))
                        + ", 'executed')"
                    )
                },
            }
        )
    )
    subprocess.run(
        [*command, "install", "--lockfile-only", "--ignore-scripts"],
        cwd=fixture,
        check=True,
        timeout=180,
    )
    assert markers["local"].exists() and markers["global"].exists(), (
        "Unsafe metadata resolution must reproduce both hooks"
    )
    assert not markers["lifecycle"].exists()
    markers["local"].unlink()
    markers["global"].unlink()
    before = engine["valid_snapshot"](fixture)
    assert before is not None
    items = [{"name": "semver", "from": "7.5.1", "to": "7.5.2"}]
    with repair["suppress_hooks"]():
        for arguments in [
            ("view", "semver@7.5.2", "version", "--json"),
            ("audit", "--json"),
        ]:
            result = engine["run"](fixture, *arguments)
            assert result.returncode in (0, 1), result.stderr
            if arguments[0] == "view":
                assert result.returncode == 0 and json.loads(result.stdout) == "7.5.2"
        workspace.write_text(repair["update_policy"](workspace.read_text(), items))
        result = engine["run"](fixture, *repair["CANDIDATE_INSTALL"])
        assert result.returncode == 0, result.stderr
        repair["check_scope"](before, engine["valid_snapshot"](fixture), items)
    assert not any(path.exists() for path in markers.values()), (
        "Preparation executed a project hook"
    )
    for snapshot in (before, engine["valid_snapshot"](fixture)):
        lock = yaml.safe_load(snapshot[1]["pnpm-lock.yaml"])
        assert (
            lock["importers"]["."]["dependencies"]["react-dom"]["version"]
            == "18.2.0(react@18.2.0)"
        )
    return "passed (real local/global hooks, view/audit/install, selected direct pin and unrelated peer suffix)"


def check_npm_policy(version):
    """Prove real security repair and complete coverage under inherited config."""
    with tempfile.TemporaryDirectory(prefix="npm-policy-") as temporary:
        root = Path(temporary)
        user_config = root / "user.npmrc"
        global_config = root / "global.npmrc"
        user_config.write_text("")
        global_config.write_text("")
        environment = {
            key: value
            for key, value in os.environ.items()
            if not key.lower().startswith("npm_config_") and key != "NODE_ENV"
        }
        environment.update(
            npm_config_userconfig=str(user_config),
            npm_config_globalconfig=str(global_config),
            npm_config_cache=str(root / "cache"),
        )
        with patch.dict(os.environ, environment, clear=True):
            baseline = root / "baseline"
            baseline.mkdir()
            manifest = {
                "name": "npm-policy-integration-fixture",
                "version": "1.0.0",
                "private": True,
                "packageManager": f"npm@{version}",
                "dependencies": {"lodash": "^3.10.1"},
                "devDependencies": {"minimist": "^1.2.5"},
                "scripts": {
                    "check": "node -e \"require('node:assert/strict').equal("
                    "require('lodash').map([1], x => x + 1)[0], 2)\""
                },
            }
            (baseline / "package.json").write_text(json.dumps(manifest))
            # Resolve real vulnerable versions without depending on registry latest.
            subprocess.run(
                [
                    "npm",
                    "install",
                    "--package-lock-only",
                    "--ignore-scripts",
                    "--no-audit",
                    "--no-force",
                    "--before=2021-03-01",
                ],
                cwd=baseline,
                check=True,
                timeout=180,
            )
            engine = runpy.run_path(str(ROOT / "runtime/templates/dependency_audit.py"))
            policy = "force=true\nomit[]=dev\nomit[]=optional\nomit[]=peer\n"
            for source in ("project", "user", "environment"):
                project = root / source
                shutil.copytree(baseline, project)
                user_config.write_text(policy if source == "user" else "")
                (project / ".npmrc").write_text(policy if source == "project" else "")
                inherited = {"NODE_ENV": "production"}
                if source == "environment":
                    inherited.update(npm_config_force="true", npm_config_omit="dev")
                with patch.dict(os.environ, inherited):
                    before_manifest = (project / "package.json").read_bytes()
                    before_lock = json.loads(
                        (project / "package-lock.json").read_text()
                    )
                    assert (
                        before_lock["packages"]["node_modules/minimist"]["version"]
                        == "1.2.5"
                    )
                    assert (
                        before_lock["packages"]["node_modules/lodash"]["version"]
                        == "3.10.1"
                    )
                    inherited_audit = subprocess.run(
                        ["npm", "audit", "--json", "--audit", "--package-lock-only"],
                        cwd=project,
                        capture_output=True,
                        text=True,
                        timeout=180,
                    )
                    filtered = json.loads(inherited_audit.stdout)
                    assert "lodash" in filtered["vulnerabilities"], filtered
                    assert "minimist" not in filtered["vulnerabilities"], filtered
                    before = engine["audit"](project)
                    assert isinstance(before, dict), before
                    assert {"minimist", "lodash"} <= before["vulnerabilities"].keys(), (
                        before
                    )
                    validation = {}
                    report = engine["prepare"](
                        project,
                        validation=validation,
                        validation_script="check",
                        maintenance_mode="security-only",
                    )
                    assert validation["passed"], report
                    assert (project / "package.json").read_bytes() == before_manifest, (
                        report
                    )
                    after_lock = json.loads((project / "package-lock.json").read_text())
                    assert (
                        after_lock["packages"]["node_modules/lodash"]["version"]
                        == "3.10.1"
                    ), report
                    assert (
                        after_lock["packages"]["node_modules/minimist"]["version"]
                        != "1.2.5"
                    ), report
                    after = engine["audit"](project)
                    assert isinstance(after, dict), after
                    assert "minimist" not in after["vulnerabilities"], after
                    assert "lodash" in after["vulnerabilities"], after
            return "passed (project, user and environment configuration)"


def check(node, manager, version):
    with tempfile.TemporaryDirectory(prefix="node-maintenance-") as temporary:
        root = Path(temporary)
        project = root / "library"
        project.mkdir()
        (root / ".github").mkdir()
        (root / ".github/node-maintenance.json").write_text(
            json.dumps({"directory": "library", "validationScript": "check"})
        )
        (project / ".nvmrc").write_text(node)
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "node-audit-integration-fixture",
                    "version": "1.0.0",
                    "private": True,
                    "packageManager": f"{manager}@{version}",
                    "scripts": {"check": "node --test"},
                    "dependencies": {"is-number": "6.0.0"},
                }
            )
        )
        (project / "library.test.cjs").write_text(
            "const {test}=require('node:test');\n"
            "const assert=require('node:assert/strict');\n"
            "const isNumber=require('is-number');\n"
            "test('library dependency works',()=>assert.equal(isNumber(42),true));\n"
        )
        if manager == "pnpm":
            (project / "pnpm-workspace.yaml").write_bytes(
                (ROOT / "runtime/templates/pnpm-workspace.yaml").read_bytes()
            )
        command = ["corepack", "pnpm"] if manager == "pnpm" else ["npm"]
        subprocess.run(
            [*command, "install", "--lockfile-only", "--ignore-scripts"],
            cwd=project,
            check=True,
            timeout=180,
        )
        preflight = runpy.run_path(str(ROOT / "runtime/project.py"))
        plan_path = root / "node-update.json"
        directory, selected = preflight["resolve_for_run"](
            root,
            root / "resolved.json",
            [],
            node_update_path=plan_path,
            propose_node=True,
        )
        node_plan = preflight["NODE_PROPOSAL"]["read_plan"](plan_path)
        assert node_plan["changes"]
        assert (project / ".nvmrc").read_text().strip() == selected["node"]
        preflight["verify_runtime"](directory, selected)
        audit = runpy.run_path(str(ROOT / "runtime/templates/dependency_audit.py"))
        platform = audit["NODE_RELEASES"]["collect"](node_plan)
        assert all(release["cves"] for release in platform["releases"]), platform
        assert selected["node"] in audit["format_platform_security"](platform, True)
        before = {p.name: p.read_bytes() for p in project.glob("*") if p.is_file()}
        validation = {}
        report = audit["prepare"](
            directory,
            validation=validation,
            validation_script="check",
            maintenance_mode="security-only",
        )
        assert validation["passed"], report
        assert not validation["audit_errors"], report
        assert "Project checks: passed." in report, report
        assert all(
            (project / name).read_bytes() == data for name, data in before.items()
        )
        report = audit["prepare"](
            directory,
            validation=validation,
            validation_script="check",
            validate_only=True,
        )
        assert validation["passed"] and not validation["audit_errors"], report
        assert all(
            (project / name).read_bytes() == data for name, data in before.items()
        ), report
        # A library with no build script also exercises the routine path, including
        # release-time lookup and the native npm publication cutoff.
        report = audit["prepare"](
            directory,
            validation=validation,
            validation_script="check",
            maintenance_mode="security-and-maintenance",
        )
        assert validation["passed"], report
        assert (
            json.loads((project / "package.json").read_text())["dependencies"][
                "is-number"
            ]
            == "7.0.0"
        ), report
        result = {
            "node": subprocess.check_output(["node", "--version"], text=True).strip(),
            "manager": manager,
            "version": selected[manager],
            "standalone_library": "passed",
            "node_security_proposal": "passed (persistent pin and real runtime validation)",
            "security_and_upgrades": "passed",
            "frozen_install_and_tests": "passed",
            "committed_state_validation": "passed without dependency changes",
        }
        if manager == "pnpm":
            result["selected_repair_preparation"] = check_pnpm_repair(
                project, command, version
            )
        if manager == "npm":
            result["inherited_npm_security_policy"] = check_npm_policy(version)
        return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", required=True)
    parser.add_argument("--manager", choices=("npm", "pnpm"), required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    print(json.dumps(check(args.node, args.manager, args.version), indent=2))
