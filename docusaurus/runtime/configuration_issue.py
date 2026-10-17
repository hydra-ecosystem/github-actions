"""Maintain one bot-owned configuration issue using a data-only audit report."""

import argparse
import html
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

MARKER = "<!-- docusaurus-configuration:v1 -->"
TITLE = "Docusaurus configuration"
BOT = "github-actions[bot]"
MAX_BYTES = 1_048_576
MAX_ISSUE_BYTES = 65536


def validate_report(report):
    if (
        not isinstance(report, dict)
        or report.get("schema_version") != 1
        or report.get("status") not in ("error", "pending", "ok")
        or not isinstance(report.get("message"), str)
        or len(report["message"]) > 8000
        or not isinstance(report.get("sources"), list)
        or len(report["sources"]) > 8
        or not isinstance(report.get("required"), dict)
    ):
        raise ValueError("invalid configuration report")
    for source in report["sources"]:
        if (
            not isinstance(source, dict)
            or set(source) != {"repository", "path", "ref", "commit"}
            or any(not isinstance(v, str) or len(v) > 2048 for v in source.values())
        ):
            raise ValueError("invalid defaults source in configuration report")


def issue_body(report, run_url):
    def display(value, limit):
        text = value if len(value) <= limit else value[:limit] + "… [truncated]"
        return "<pre>" + html.escape(text) + "</pre>"

    state = (
        "Validation failed before dependency changes."
        if report["status"] == "error"
        else "Configuration validation now passes."
    )
    lines = [MARKER, "", state, "", display(report["message"], 4000)]
    if report["sources"]:
        lines.extend(["", "Defaults sources used by this run:"])
        for source in report["sources"]:
            value = f"{source['repository']}/{source['path']} @ {source['ref']}"
            lines.append(display(value, 512))
            lines.append(display("Resolved commit: " + source["commit"], 64))
    else:
        lines.extend(
            [
                "",
                "Configuration: `.github/docusaurus.json` and the local project declarations.",
            ]
        )
    if report["required"]:
        lines.extend(
            [
                "",
                "Resolved requirements:",
                display(json.dumps(report["required"], sort_keys=True), 1000),
            ]
        )
    if report["status"] == "error":
        lines.extend(
            [
                "",
                "Align the named project declarations, or explicitly override the inherited settings in `.github/docusaurus.json`, then rerun **Docusaurus dependency audit**. No project files were rewritten.",
            ]
        )
    lines.extend(
        [
            "",
            f"[Workflow run]({run_url})",
            "Full diagnostics and source references are in the workflow's configuration artifact.",
            "",
            "This issue is reused for configuration failures. A successful preflight closes it; a later failure reopens the same issue.",
        ]
    )
    body = "\n".join(lines)
    if len(body.encode()) > MAX_ISSUE_BYTES:
        raise ValueError("configuration issue body exceeds its size limit")
    return body


def github_request(method, path, payload=None):
    token = os.environ.get("GH_TOKEN", "")
    if not token:
        raise ValueError("configuration reporting requires GH_TOKEN with issues: write")
    request = urllib.request.Request(
        "https://api.github.com/" + path,
        data=json.dumps(payload).encode() if payload is not None else None,
        method=method,
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "User-Agent": "docusaurus-configuration-issue",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            data = response.read(2_000_001)
    except urllib.error.HTTPError as error:
        raise ValueError(
            f"Configuration issue API returned HTTP {error.code}; check that issues "
            "are enabled and the reporting job has issues: write"
        ) from error
    if len(data) > 2_000_000:
        raise ValueError("configuration issue API response exceeds its size limit")
    return json.loads(data)


def existing_issue(repository, request):
    matches = []
    for page in range(1, 101):
        query = urllib.parse.urlencode(
            {"state": "all", "creator": BOT, "per_page": 100, "page": page}
        )
        issues = request("GET", f"repos/{repository}/issues?{query}")
        if not isinstance(issues, list):
            raise ValueError("GitHub did not return an issue list; no issue created")
        for issue in issues:
            if not isinstance(issue, dict):
                raise ValueError("GitHub returned an invalid issue; no issue created")
            author = issue.get("user", {})
            if (
                not issue.get("pull_request")
                and author.get("login") == BOT
                and author.get("type") == "Bot"
                and isinstance(issue.get("body"), str)
                and issue["body"].startswith(MARKER + "\n")
            ):
                if (
                    type(issue.get("number")) is not int
                    or issue["number"] <= 0
                    or issue.get("state") not in ("open", "closed")
                ):
                    raise ValueError("GitHub returned an invalid marked issue")
                matches.append(issue)
        if len(issues) < 100:
            break
    else:
        raise ValueError(
            "Cannot prove complete configuration issue history; no issue created"
        )
    if len(matches) > 1:
        raise ValueError(
            "Multiple bot-owned configuration issues found; reconcile duplicates before rerunning"
        )
    return matches[0] if matches else None


def update_issue(repository, report, run_url, request=github_request):
    validate_report(report)
    if report["status"] == "pending":
        return {"operation": "skipped", "reason": "preflight did not finish"}
    issue = existing_issue(repository, request)
    if report["status"] == "ok" and (issue is None or issue["state"] == "closed"):
        return {"operation": "unchanged", "number": issue["number"] if issue else None}
    body = issue_body(report, run_url)
    if issue is None:
        result = request(
            "POST", f"repos/{repository}/issues", {"title": TITLE, "body": body}
        )
        operation = "created"
    else:
        state = "open" if report["status"] == "error" else "closed"
        if issue["state"] == state and issue["body"] == body:
            return {"operation": "unchanged", "number": issue["number"]}
        result = request(
            "PATCH",
            f"repos/{repository}/issues/{issue['number']}",
            {"body": body, "state": state},
        )
        operation = (
            "closed"
            if state == "closed"
            else "reopened"
            if issue["state"] == "closed"
            else "updated"
        )
        if not isinstance(result, dict) or result.get("number") != issue["number"]:
            raise ValueError(
                "Issue update identity changed; no additional issue created"
            )
    if (
        not isinstance(result, dict)
        or type(result.get("number")) is not int
        or result["number"] <= 0
    ):
        raise ValueError(
            "GitHub did not return a configuration issue identity; inspect the run before retrying"
        )
    return {"operation": operation, "number": result["number"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    try:
        repository = os.environ.get("GITHUB_REPOSITORY", "")
        run_id = os.environ.get("GITHUB_RUN_ID", "")
        if (
            not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository)
            or not run_id.isdecimal()
        ):
            raise ValueError(
                "configuration reporter requires the current GitHub repository and run ID"
            )
        with args.report.open("rb") as stream:
            data = stream.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise ValueError("configuration report exceeds its size limit")
        report = json.loads(data)
        result = update_issue(
            repository, report, f"https://github.com/{repository}/actions/runs/{run_id}"
        )
        print(json.dumps(result))
    except (OSError, ValueError, urllib.error.URLError) as error:
        message = (
            str(error).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        )
        print(f"::error title=Docusaurus configuration issue::{message}")
        parser.exit(
            2,
            "Configuration issue reporting failed; inspect this run before retrying.\n",
        )


if __name__ == "__main__":
    main()
