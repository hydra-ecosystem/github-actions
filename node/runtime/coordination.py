"""Plan independent proposals from one observed default-branch revision."""

import argparse
import json
import os
import runpy
import subprocess
from pathlib import Path

PROJECT = runpy.run_path(str(Path(__file__).with_name("project.py")))
BRANCHES = {
    "security": "maintenance/node-security",
    "upgrades": "maintenance/node-upgrades",
}
PUSH_PATHS = [
    "**/pnpm-lock.yaml",
    "**/package-lock.json",
    ".github/node-maintenance.json",
    "**/.nvmrc",
    "**/.node-version",
]


def plan(
    root,
    config,
    selected,
    event_name,
    event,
    requested,
    pull_requests,
    *,
    changed_paths=None,
    directory=".",
):
    if event_name not in ("push", "schedule", "workflow_dispatch"):
        raise ValueError("Unsupported maintenance event")
    default = event["repository"]["default_branch"]
    if event_name != "schedule" and event.get("ref") != f"refs/heads/{default}":
        raise ValueError("Maintenance must target the default branch")
    mode = PROJECT["SCHEDULING"]["select_mode"](
        root, config, selected["maintenance"]["mode"], requested, event_name, event
    )
    relevant = {
        ".github/node-maintenance.json",
        *[
            (Path(directory) / name).as_posix()
            for name in ("pnpm-lock.yaml", "package-lock.json")
        ],
    }
    for parent in (root / directory, *(root / directory).parents):
        if not parent.is_relative_to(root):
            break
        declarations = [parent / name for name in (".nvmrc", ".node-version")]
        relevant.update(path.relative_to(root).as_posix() for path in declarations)
        if any(path.exists() for path in declarations):
            break
    validate_main = event_name == "push" and (
        changed_paths is None or bool(relevant.intersection(changed_paths))
    )
    result = {"refresh_only": event_name == "push", "validate_main": validate_main}
    for kind, branch in BRANCHES.items():
        matches = [
            pr
            for pr in pull_requests
            if pr["headRefName"] == branch and not pr["isCrossRepository"]
        ]
        if len(matches) > 1:
            raise ValueError(
                f"Multiple open proposals on {branch}; reconcile them first"
            )
        result[kind + "_pr"] = str(matches[0]["number"]) if matches else ""
        result[kind] = (
            bool(matches) and validate_main
            if event_name == "push"
            else ((kind == "security") == (mode == "security-only"))
        )
    # The old combined branch needs an explicit disposition before adoption.
    if any(
        pr["headRefName"] == "maintenance/dependency-audit"
        and not pr["isCrossRepository"]
        for pr in pull_requests
    ):
        raise ValueError(
            "Merge or close the legacy maintenance/dependency-audit PR before adopting coordinated maintenance"
        )
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--github-output", type=Path, required=True)
    parser.add_argument("--configuration-report", type=Path)
    args = parser.parse_args()
    root = Path.cwd().resolve()
    sources = []
    selected = None
    try:
        config = PROJECT["CONFIGURATION"]["load_configuration"](root, sources)
        directory, selected = PROJECT["project"](root, config=config)
        event = PROJECT["SCHEDULING"]["event_payload"](os.environ["GITHUB_EVENT_PATH"])
        event["ref"] = os.environ.get("GITHUB_REF", event.get("ref"))
        repo = event["repository"]["full_name"]
        # Do not execute project code in this credentialed planning job.
        prs = json.loads(
            subprocess.check_output(
                [
                    "gh",
                    "pr",
                    "list",
                    "--repo",
                    repo,
                    "--state",
                    "open",
                    "--limit",
                    "1000",
                    "--json",
                    "number,headRefName,isCrossRepository",
                ],
                text=True,
            )
        )
        before = event.get("before")
        changed_paths = None
        if os.environ["GITHUB_EVENT_NAME"] == "push" and before and before != "0" * 40:
            changed_paths = subprocess.check_output(
                [
                    "git",
                    "diff",
                    "--name-only",
                    "-z",
                    before,
                    "HEAD",
                ],
                text=True,
            ).split("\0")
        result = plan(
            root,
            config,
            selected,
            os.environ["GITHUB_EVENT_NAME"],
            event,
            os.environ.get("AUDIT_KIND", "auto"),
            prs,
            changed_paths=changed_paths,
            directory=directory.relative_to(root).as_posix(),
        )
        result["sha"] = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True
        ).strip()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        PROJECT["write_configuration_report"](
            args.configuration_report, "error", str(error), sources, selected
        )
        parser.exit(2, str(error) + "\n")
    with args.github_output.open("a") as output:
        for key, value in result.items():
            output.write(
                f"{key}={str(value).lower() if isinstance(value, bool) else value}\n"
            )


if __name__ == "__main__":
    main()
