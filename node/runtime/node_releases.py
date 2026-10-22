"""Collect release-level Node CVE evidence without inferring baseline exposure."""

import json
import re
import runpy
import time
from pathlib import Path

SECURITY = runpy.run_path(str(Path(__file__).with_name("node_security.py")))
NOTES_SOURCE = "https://raw.githubusercontent.com/nodejs/nodejs.org/main/apps/site/pages/en/blog/release/v{}.md"
SEVERITIES = ("critical", "high", "medium", "low", "info")
MAX_NOTES_BYTES = 262144
MAX_RELEASES = 32


def parse_notes(version, data):
    SECURITY["version_tuple"](version)
    text = data.decode("utf-8") if isinstance(data, bytes) else data
    if not re.search(rf"^## .*\bVersion {re.escape(version)}\b", text, re.M):
        raise ValueError("Release notes do not identify the requested version")
    section = re.search(
        r"^### Notable Changes\s*\n(.*?)(?=^#{1,3} |\Z)", text, re.M | re.S
    )
    if section is None:
        raise ValueError("Release notes have no notable changes section")
    cves, severities = set(), set()
    severity_complete = True
    for line in section[1].splitlines():
        ids = re.findall(r"\bCVE-\d{4}-\d{4,}\b", line)
        if not ids:
            continue
        cves.update(ids)
        match = re.search(
            r"[–—-]\s*(Critical|High|Medium|Moderate|Low|Info)\s*$", line, re.I
        )
        if match:
            severities.add(match[1].lower().replace("moderate", "medium"))
        else:
            severity_complete = False
    if not cves:
        raise ValueError("No named CVEs could be read from these release notes")
    return {
        "version": version,
        "cves": sorted(cves),
        "severity": next((level for level in SEVERITIES if level in severities), None)
        if severity_complete
        else None,
        "message": "",
    }


def previous_declaration(plan):
    values = []
    for change in plan["changes"]:
        value = (
            json.loads(change["before"])["toolchain"]["node"]
            if change["path"] == ".github/node-maintenance.json"
            else change["before"].strip()
        ).removeprefix("v")
        if re.fullmatch(r"\d+\.\d+\.\d+", value):
            SECURITY["version_tuple"](value)
            values.append(value)
    if values:
        if len(set(values)) != 1:
            raise ValueError("Conflicting starting Node versions in proposal")
        return values[0]
    return None


def collect(plan, *, read_index=None, read_notes=None):
    if not plan:
        return None
    if not plan["changes"]:
        return (
            {
                "previous": None,
                "target": None,
                "releases": [],
                "message": plan["message"],
            }
            if plan["message"]
            else None
        )
    target = plan["version"]
    end = SECURITY["version_tuple"](target)
    previous = previous_declaration(plan)
    start = SECURITY["version_tuple"](previous) if previous else None
    if start and (start[0] != end[0] or start >= end):
        raise ValueError("Invalid Node security report version interval")
    result = {"previous": previous, "target": target, "releases": [], "message": ""}
    versions = [target]
    if start:
        try:
            versions = [
                version
                for version in SECURITY["security_releases"](end[0], read=read_index)
                if start < SECURITY["version_tuple"](version) <= end
            ]
            if target not in versions:
                raise ValueError("Target is absent from the security release index")
        except ValueError:
            versions = [target]
            result["message"] = (
                "Security release history unavailable; only the target release is shown."
            )
    else:
        result["message"] = (
            "The previous exact Node version was not pinned. Only the target release is shown."
        )
    if len(versions) > MAX_RELEASES:
        versions = versions[-MAX_RELEASES:]
        result["message"] = (
            "Release history is truncated to the latest 32 security releases in this upgrade."
        )
    deadline = time.monotonic() + 45
    for version in versions:
        try:
            if time.monotonic() >= deadline:
                raise ValueError("Release-note lookup time budget exhausted")
            data = (
                read_notes(version)
                if read_notes is not None
                else SECURITY["read_public"](
                    NOTES_SOURCE.format(version),
                    max_bytes=MAX_NOTES_BYTES,
                    timeout=min(10, deadline - time.monotonic()),
                )
            )
            release = parse_notes(version, data)
        except (ValueError, UnicodeError, OSError):
            release = {
                "version": version,
                "cves": None,
                "severity": None,
                "message": "CVE details unavailable; read the release notes.",
            }
        result["releases"].append(release)
    return result
