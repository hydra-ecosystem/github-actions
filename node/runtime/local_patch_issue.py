"""Notify about published fixes for declared local patches using data only."""

import argparse
import json
import os
import re
import runpy
import urllib.error
from pathlib import Path

ISSUES = runpy.run_path(str(Path(__file__).with_name("configuration_issue.py")))
PATCHES = runpy.run_path(str(Path(__file__).with_name("local_patches.py")))
MARKER = "<!-- node-audit-local-patches:v1 -->"
TITLE = "Node local patches: official fixes available"


def update_issue(repository, report, run_url, request=ISSUES["github_request"]):
    PATCHES["validate_report"](report)
    available = any(item["status"] == "fix-available" for item in report["patches"])
    if not available and (
        not report["complete"]
        or any(item["status"] == "unverified" for item in report["patches"])
    ):
        return {"operation": "skipped", "reason": "official fix evidence is incomplete"}
    preview = PATCHES["render"](report)
    if len(preview.encode()) > 48_000:
        preview = preview.encode()[:48_000].decode(errors="ignore").rsplit("\n", 1)[0]
        preview += (
            "\n\nTable preview truncated. The workflow run's "
            "`node-audit-local-patches` artifact contains all entries and comments.\n\n"
        )
    body = (
        MARKER
        + "\n\n"
        + (
            "Published official fixes are available for maintainer-declared local patches.\n\n"
            if available
            else "No declared local patch currently has a verified newer official fix requiring this notification.\n\n"
        )
        + preview
        + (
            "The full security audit did not complete. This notification records verified release availability only.\n\n"
            if not report["complete"]
            else ""
        )
        + "Review the upstream fix, project constraints, and release cooldown. Upgrade manually and remove a patch only after checking everything it changes. Remove obsolete localPatches declarations and any corresponding audit-ignore entries, then rerun maintenance.\n\n"
        + "Availability does not prove compatibility or certify the local patch. This reporter does not change patch files or project policy.\n\n"
        + f"[Workflow run]({run_url})\n\n"
        + "This repository reuses one issue for local-patch notifications. Unavailable audit or registry evidence does not close it."
    )
    return ISSUES["maintain_issue"](
        repository,
        marker=MARKER,
        title=TITLE,
        body=body,
        failing=available,
        request=request,
        resolution_comment=(
            "Local-patch notification resolved.\n\n"
            + (
                "No local patch declarations remain in the project configuration.\n\n"
                if not report["patches"]
                else "The latest complete audit has no declared local patch with a verified newer official fix requiring notification.\n\n"
                + preview
            )
            + "The original findings above are preserved as history. This does not certify local patches or resolve unrelated security findings.\n\n"
            + f"[Verification run]({run_url})"
        ),
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    try:
        repository = os.environ.get("GITHUB_REPOSITORY", "")
        run_id = os.environ.get("GITHUB_RUN_ID", "")
        if (
            not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository)
            or any(part in {".", ".."} for part in repository.split("/"))
            or not run_id.isdecimal()
        ):
            raise ValueError(
                "Local patch reporter requires the current repository and run ID"
            )
        with args.report.open("rb") as stream:
            raw = stream.read(PATCHES["MAX_REPORT_BYTES"] + 1)
        if len(raw) > PATCHES["MAX_REPORT_BYTES"]:
            raise ValueError("Local patch report exceeds its size limit")
        result = update_issue(
            repository,
            json.loads(raw),
            f"https://github.com/{repository}/actions/runs/{run_id}",
        )
        print(json.dumps(result))
    except (OSError, ValueError, urllib.error.URLError) as error:
        parser.exit(1, f"Local patch issue: {error}\n")


if __name__ == "__main__":
    main()
