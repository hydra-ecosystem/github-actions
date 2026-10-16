"""Exercise the supported toolchain with a real Docusaurus website."""

import argparse
import json
import runpy
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).parents[1]


def check(node, pnpm):
    with tempfile.TemporaryDirectory(prefix="docusaurus-toolchain-") as temporary:
        root = Path(temporary)
        site = root / "website"
        site.mkdir()
        (root / ".github").mkdir()
        (root / ".github/docusaurus.json").write_text(
            json.dumps({"directory": "website", "toolchain": {}})
        )
        (site / ".nvmrc").write_text(node)
        (site / "package.json").write_text(
            json.dumps(
                {
                    "private": True,
                    "packageManager": f"pnpm@{pnpm}",
                    "engines": {"node": ">=22.13"},
                    "scripts": {"build": "docusaurus build"},
                    "dependencies": {
                        "@docusaurus/core": "3.10.2",
                        "@docusaurus/preset-classic": "3.10.2",
                        "react": "19.3.0",
                        "react-dom": "19.3.0",
                    },
                }
            )
        )
        (site / "pnpm-workspace.yaml").write_bytes(
            (ROOT / "runtime/templates/pnpm-workspace.yaml").read_bytes()
        )
        (site / "docusaurus.config.js").write_text(
            "module.exports = {title:'Toolchain check',url:'https://example.com',baseUrl:'/',presets:[['classic',{docs:{routeBasePath:'/'},blog:false}]]};\n"
        )
        (site / "docs").mkdir()
        (site / "docs/index.md").write_text(
            "---\nslug: /\n---\n# Toolchain check\nA real production build.\n"
        )

        def run(*args, allowed=(0,)):
            result = subprocess.run(
                ["corepack", "pnpm", *args],
                cwd=site,
                text=True,
                capture_output=True,
                timeout=600,
            )
            if result.returncode not in allowed:
                raise RuntimeError(
                    f"pnpm {' '.join(args)} failed ({result.returncode})\n{result.stdout}\n{result.stderr}"
                )
            return result

        run("install", "--lockfile-only", "--ignore-scripts")
        project = runpy.run_path(str(ROOT / "runtime/project.py"))
        directory, selected = project["project"](root)
        project["verify_runtime"](directory, selected)
        audit = runpy.run_path(str(ROOT / "runtime/templates/dependency_audit.py"))
        findings = audit["audit"](site)
        assert isinstance(findings, dict), findings
        fixed = run(
            "audit",
            "--fix=update",
            "--audit-level",
            "info",
            "--ignore-scripts",
            allowed=(0, 1),
        )
        diagnostics = fixed.stdout + fixed.stderr
        assert "ERR_PNPM" not in diagnostics and "Unknown option" not in diagnostics, (
            diagnostics
        )
        run("install", "--frozen-lockfile")
        run("run", "build")
        assert (site / "build/index.html").is_file()
        return {
            "node": subprocess.check_output(["node", "--version"], text=True).strip(),
            "pnpm": run("--version").stdout.strip(),
            "audit_parser": "passed",
            "audit_fix_update": "passed",
            "frozen_install": "passed",
            "production_build": "passed",
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", required=True)
    parser.add_argument("--pnpm", required=True)
    args = parser.parse_args()
    print(json.dumps(check(args.node, args.pnpm), indent=2))
