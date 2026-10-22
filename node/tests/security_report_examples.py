"""Render illustrative evidence through the production report functions."""

import argparse
import copy
import json
import runpy
from pathlib import Path

ENGINE = runpy.run_path(
    str(Path(__file__).parents[1] / "runtime/templates/dependency_audit.py")
)
RELEASES = ENGINE["NODE_RELEASES"]
EXAMPLE_CVES = {
    "24.18.1": [
        "CVE-2026-56846",
        "CVE-2026-56848",
        "CVE-2026-58043",
        "CVE-2026-56850",
        "CVE-2026-58040",
        "CVE-2026-58041",
        "CVE-2026-58042",
        "CVE-2026-58045",
        "CVE-2026-56847",
        "CVE-2026-58039",
        "CVE-2026-58044",
    ],
    "24.22.1": [
        "CVE-2026-106069",
        "CVE-2026-106072",
        "CVE-2026-105482",
        "CVE-2026-105483",
        "CVE-2026-111497",
        "CVE-2026-105481",
        "CVE-2026-106074",
        "CVE-2026-106073",
    ],
}


def release_index():
    return json.dumps(
        [{"version": "v" + version, "security": True} for version in EXAMPLE_CVES]
    )


def release_notes(version):
    # Minimal release-note fixtures: real IDs, synthetic descriptions for parser tests.
    return (
        f"## 2026-01-01, Version {version}\n\n### Notable Changes\n"
        + "\n".join(f"- ({cve}) security fix – High" for cve in EXAMPLE_CVES[version])
        + "\n### Commits\n"
    )


def node_plan(previous="24.18.0"):
    return {
        "schema_version": 1,
        "directory": "website",
        "version": "24.22.1",
        "changes": [
            {"path": "website/.nvmrc", "before": previous + "\n", "after": "24.22.1\n"}
        ],
        "message": "",
    }


def package_evidence():
    def detail(name, severity):
        return {
            "url": f"https://example.invalid/advisories/{name}",
            "severity": severity,
            "fixStatus": (
                "Published patch: `package-b@2.0.2`. Blocked by retained override "
                "`pnpm-workspace.yaml overrides.package-b` = `2.0.0`."
                if name == "package-b"
                else ""
            ),
        }

    before = {
        "metadata": {"vulnerabilities": {"critical": 1, "high": 1}},
        "vulnerabilities": {
            "package-a": {"via": [detail("package-a", "critical")]},
            "package-b": {"via": [detail("package-b", "high")]},
        },
    }
    after = copy.deepcopy(before)
    del after["vulnerabilities"]["package-a"]
    after["metadata"]["vulnerabilities"] = {"high": 1}
    locks = [
        {
            "packages": {
                "node_modules/package-a": {"version": version},
                "node_modules/package-b": {"version": "2.0.0"},
            }
        }
        for version in ("1.0.0", "1.0.1")
    ]
    return before, after, locks


def render_examples(output_directory, *, live_platform=False):
    output_directory.mkdir(parents=True, exist_ok=True)
    platform = RELEASES["collect"](
        node_plan(),
        **(
            {}
            if live_platform
            else {"read_index": release_index, "read_notes": release_notes}
        ),
    )
    result = {}
    for name, use_platform, use_packages in (
        ("platform-only", True, False),
        ("packages-only", False, True),
        ("platform-and-packages", True, True),
    ):
        before, after, locks = package_evidence()
        if not use_packages:
            before = after = {
                "metadata": {"vulnerabilities": {}},
                "vulnerabilities": {},
            }
        metrics = {}
        report = ENGINE["format_audit_summary"](
            before, after, "pnpm", locks=locks, summary=metrics
        )
        text = ENGINE["format_security_overview"](
            platform=platform if use_platform else None,
            package_report=report,
            package_fixes=int(use_packages),
            package_updates=int(use_packages),
            review_count=metrics["review_count"],
            passed=True,
        ) + ENGINE["format_validation"]("Passed.", "Passed.")
        text += (
            "---\n\n*Generated preview. Package and validation evidence is illustrative; "
            "example.invalid advisory links are placeholders. Platform release evidence "
            + (
                "was read from official Node.js sources."
                if live_platform
                else "uses offline release-note fixtures."
            )
            + "*\n"
        )
        path = output_directory / f"{name}.md"
        path.write_text(text)
        result[name] = text
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--live-platform", action="store_true")
    args = parser.parse_args()
    render_examples(args.output_directory, live_platform=args.live_platform)
    print(args.output_directory)
