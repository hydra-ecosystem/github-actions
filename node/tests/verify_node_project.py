"""Run real dependency maintenance and validation on a standalone Node library."""

import argparse
import json
import runpy
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).parents[1]


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
        directory, selected = preflight["project"](root)
        preflight["verify_runtime"](directory, selected)
        audit = runpy.run_path(str(ROOT / "runtime/templates/dependency_audit.py"))
        before = {p.name: p.read_bytes() for p in project.glob("*") if p.is_file()}
        validation = {}
        report = audit["prepare"](
            directory,
            validation=validation,
            validation_script="check",
            maintenance_mode="security-only",
        )
        assert validation["passed"], report
        assert "Project checks: passed." in report, report
        assert all(
            (project / name).read_bytes() == data for name, data in before.items()
        )
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
        return {
            "node": subprocess.check_output(["node", "--version"], text=True).strip(),
            "manager": manager,
            "version": selected[manager],
            "standalone_library": "passed",
            "security_and_upgrades": "passed",
            "frozen_install_and_tests": "passed",
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", required=True)
    parser.add_argument("--manager", choices=("npm", "pnpm"), required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    print(json.dumps(check(args.node, args.manager, args.version), indent=2))
