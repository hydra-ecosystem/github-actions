"""Maintain one setup issue per failure episode, without touching consumers."""

import argparse
import hashlib
import html
import json
import os
import re
import runpy
import urllib.parse
from pathlib import Path

ISSUES = runpy.run_path(str(Path(__file__).with_name("configuration_issue.py")))
CONFIGURATION = runpy.run_path(str(Path(__file__).with_name("configuration.py")))
MAX_ISSUE_BYTES = ISSUES["MAX_ISSUE_BYTES"]
DIAGNOSTIC_LIMIT = 1000
TRUNCATION_SUFFIX = "… [truncated]"
RESOLVED = "<!-- node-fleet-incident:v1:resolved -->"
ACTIVE = "<!-- node-fleet-incident:v1:active -->"


def validate_report(report):
    if (
        not isinstance(report, dict)
        or set(report)
        != {"schema_version", "inventory", "results", "status", "diagnostic"}
        or report["schema_version"] != 1
    ):
        raise ValueError("Invalid fleet report schema")
    source = report["inventory"]
    if not isinstance(source, dict) or set(source) != {
        "repository",
        "path",
        "ref",
        "commit",
    }:
        raise ValueError("Invalid inventory identity")
    CONFIGURATION["validate_source"](
        {
            key: source[key] or "HEAD" if key == "ref" else source[key]
            for key in ("repository", "path", "ref")
        }
    )
    if source["commit"] is not None and (
        not isinstance(source["commit"], str)
        or not re.fullmatch(r"[0-9a-f]{40}", source["commit"])
    ):
        raise ValueError("Invalid inventory commit")
    results = report["results"]
    if (
        not isinstance(results, list)
        or len(results) > 25
        or report["status"] not in ("ok", "failed", "unverified")
    ):
        raise ValueError("Invalid fleet results")
    if not isinstance(report["diagnostic"], str) or len(report["diagnostic"]) > 4000:
        raise ValueError("Invalid fleet diagnostic")
    names = set()
    for item in results:
        if not isinstance(item, dict) or set(item) != {
            "repository",
            "commit",
            "status",
            "diagnostic",
        }:
            raise ValueError("Invalid repository result")
        repository, _, _ = CONFIGURATION["validate_source"](
            {"repository": item["repository"], "path": "inventory.json", "ref": "main"}
        )
        if (
            repository in names
            or item["status"] not in ("ok", "failed", "unverified")
            or not isinstance(item["diagnostic"], str)
            or len(item["diagnostic"]) > 4000
        ):
            raise ValueError("Invalid repository status")
        names.add(repository)
        if item["commit"] is not None and (
            not isinstance(item["commit"], str)
            or not re.fullmatch(r"[0-9a-f]{40}", item["commit"])
        ):
            raise ValueError("Invalid repository commit")
        if item["status"] == "ok" and item["commit"] is None:
            raise ValueError("A healthy repository requires its checked commit")
    if report["status"] == "ok" and (
        not results
        or source["commit"] is None
        or report["diagnostic"]
        or any(item["status"] != "ok" for item in results)
    ):
        raise ValueError("A healthy report must verify every listed repository")


def marker(source):
    identity = source["repository"].lower() + "/" + source["path"]
    return (
        "<!-- node-fleet-setup:v1:"
        + hashlib.sha256(identity.encode()).hexdigest()
        + " -->"
    )


def latest_issue(repository, identity, request):
    """Stop at the newest matching bot issue; older incidents are historical."""
    for page in range(1, 101):
        query = urllib.parse.urlencode(
            {
                "state": "all",
                "creator": ISSUES["BOT"],
                "sort": "created",
                "direction": "desc",
                "per_page": 100,
                "page": page,
            }
        )
        issues = request("GET", f"repos/{repository}/issues?{query}")
        if not isinstance(issues, list):
            raise ValueError("GitHub did not return an issue list; no issue created")
        for issue in issues:
            if not isinstance(issue, dict):
                raise ValueError("GitHub returned an invalid issue; no issue created")
            author = issue.get("user")
            if (
                "pull_request" not in issue
                and isinstance(author, dict)
                and author.get("login") == ISSUES["BOT"]
                and author.get("type") == "Bot"
                and isinstance(issue.get("body"), str)
                and issue["body"].startswith(identity + "\n")
            ):
                if (
                    type(issue.get("number")) is not int
                    or issue["number"] <= 0
                    or issue.get("state") not in ("open", "closed")
                ):
                    raise ValueError("GitHub returned an invalid marked fleet issue")
                return issue
        if len(issues) < 100:
            return None
    raise ValueError(
        "Cannot find latest fleet issue within lookup limit; no issue created"
    )


def maintain_incident(repository, *, identity, title, body, failing, request):
    if not body.startswith(identity + "\n") or len(body.encode()) > MAX_ISSUE_BYTES:
        raise ValueError("invalid marked fleet issue body")
    issue = latest_issue(repository, identity, request)
    recovered = issue is not None and issue["body"].startswith(
        identity + "\n" + RESOLVED + "\n"
    )
    if not failing and (issue is None or (recovered and issue["state"] == "closed")):
        return {"operation": "unchanged", "number": issue["number"] if issue else None}
    if issue is None or (failing and recovered):
        result = request(
            "POST", f"repos/{repository}/issues", {"title": title, "body": body}
        )
        operation = "created"
    else:
        state = "open" if failing else "closed"
        if issue["state"] == state and issue["body"] == body:
            return {"operation": "unchanged", "number": issue["number"]}
        result = request(
            "PATCH",
            f"repos/{repository}/issues/{issue['number']}",
            {"body": body, "state": state},
        )
        operation = (
            "closed"
            if not failing
            else "reopened"
            if issue["state"] == "closed"
            else "updated"
        )
        if not isinstance(result, dict) or result.get("number") != issue["number"]:
            raise ValueError(
                "Fleet issue update identity changed; no additional issue created"
            )
    if (
        not isinstance(result, dict)
        or type(result.get("number")) is not int
        or result["number"] <= 0
    ):
        raise ValueError(
            "GitHub did not return a fleet issue identity; inspect the run before retrying"
        )
    return {"operation": operation, "number": result["number"]}


def update_issue(repository, report, run_url, request=ISSUES["github_request"]):
    validate_report(report)
    source = report["inventory"]

    def render(limit):
        truncated = False

        def text(value):
            return html.escape(str(value))

        def diagnostic(value):
            nonlocal truncated
            value = str(value)
            if len(value) <= limit:
                return html.escape(value)
            truncated = True
            return html.escape(value[:limit] + TRUNCATION_SUFFIX)

        def cell(value):
            return (
                re.sub(
                    r"[\\`*_\[\]~!|]",
                    lambda match: f"&#{ord(match[0])};",
                    value,
                )
                .replace("\r\n", "\n")
                .replace("\r", "\n")
                .replace("\n", "<br>")
            )

        counts = {
            status: sum(item["status"] == status for item in report["results"])
            for status in ("ok", "failed", "unverified")
        }
        statuses = {
            "ok": "✅ Passed",
            "failed": "⚠️ Needs attention",
            "unverified": "❔ Unverified",
        }
        headline = (
            " · ".join(
                f"{counts[status]} {label}"
                for status, label in (
                    ("failed", "need attention"),
                    ("ok", "passed"),
                    ("unverified", "unverified"),
                )
                if counts[status]
            )
            or "No repositories verified"
        )
        lines = [
            marker(source),
            RESOLVED if report["status"] == "ok" else ACTIVE,
            "",
            "## Node maintenance setup check",
            "",
            f"**{headline}**",
            "",
            f"Inventory: <code>{text(source['repository'])}/{text(source['path'])}</code>",
            "",
        ]
        if report["diagnostic"]:
            lines.extend(["<pre>" + diagnostic(report["diagnostic"]) + "</pre>", ""])
        lines.extend(["| Repository | Setup | Detail |", "| --- | --- | --- |"])
        for item in report["results"]:
            lines.append(
                f"| [{cell(text(item['repository']))}](https://github.com/{item['repository']}) | {statuses[item['status']]} | {cell(diagnostic(item['diagnostic']))} |"
            )
        lines.extend(
            [
                "",
                "<details>",
                "<summary>Checked revisions</summary>",
                "",
                f"Inventory: <code>{text(source['ref'])} @ {text(source['commit'] or 'unverified')}</code>",
                "",
                "| Repository | Commit |",
                "| --- | --- |",
            ]
        )
        for item in report["results"]:
            lines.append(
                f"| {cell(text(item['repository']))} | <code>{text(item['commit'] or 'unverified')}</code> |"
            )
        lines.extend(["", "</details>", ""])
        if truncated:
            lines.extend(
                [
                    "",
                    f"Some diagnostic text was truncated to fit the {MAX_ISSUE_BYTES}-byte issue limit. Full diagnostics remain in the workflow run's node-fleet-report artifact.",
                ]
            )
        lines.extend(
            [
                "Installed tools, credential contents, publication access, dependencies, and builds were not tested.",
                "",
                f"[Workflow run]({run_url})",
                "",
                "This issue tracks one failure episode for this inventory. A fully passing scan closes it; a later regression creates a new issue. Closing it manually while problems persist causes it to reopen on the next scan.",
            ]
        )
        return "\n".join(lines)

    body = render(DIAGNOSTIC_LIMIT)
    if len(body.encode()) > MAX_ISSUE_BYTES:
        low, high = 0, DIAGNOSTIC_LIMIT - 1
        best = None
        while low <= high:
            limit = (low + high) // 2
            candidate = render(limit)
            if len(candidate.encode()) <= MAX_ISSUE_BYTES:
                best = candidate
                low = limit + 1
            else:
                high = limit - 1
        if best is None:
            raise ValueError(
                "fleet issue body exceeds its fixed identity and status budget"
            )
        body = best
    return maintain_incident(
        repository,
        identity=marker(source),
        title="Node maintenance setup check: " + source["path"][:180],
        body=body,
        failing=report["status"] != "ok",
        request=request,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    run = os.environ.get("GITHUB_RUN_ID", "")
    if (
        not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository)
        or not run.isdecimal()
    ):
        parser.error("Fleet reporting requires the host GitHub repository and run ID")
    with args.report.open("rb") as stream:
        data = stream.read(1_000_001)
    if len(data) > 1_000_000:
        parser.error("Fleet report exceeds its size limit")
    print(
        json.dumps(
            update_issue(
                repository,
                json.loads(data),
                f"https://github.com/{repository}/actions/runs/{run}",
            )
        )
    )


if __name__ == "__main__":
    main()
