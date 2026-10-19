"""Track advisory assertions and optional comments without certifying local patches."""

import html
import json
import re

MAX_PATCHES = 32
MAX_ROWS = 256
MAX_REPORT_BYTES = 8 * 1024 * 1024
VERSION = r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
PACKAGE = r"(?:@[a-z0-9_.~-]+/)?[a-z0-9_.~-]+"


def validate_declarations(values):
    """Normalize an advisory ID or [advisory ID, comment] into internal records."""
    if not isinstance(values, list) or len(values) > MAX_PATCHES:
        raise ValueError("localPatches must be a list of at most 32 assertions")
    result, seen = [], set()
    for value in values:
        if isinstance(value, str):
            advisory, comment = value, ""
        elif isinstance(value, list) and len(value) == 2:
            advisory, comment = value
        else:
            raise ValueError(
                "localPatches entries must be an advisory ID or [advisory ID, comment]"
            )
        if not isinstance(advisory, str) or not re.fullmatch(
            r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", advisory
        ):
            raise ValueError("localPatches requires a GHSA identifier")
        if (
            not isinstance(comment, str)
            or len(comment) > 2048
            or any(ord(c) < 32 for c in comment)
            or any(0xD800 <= ord(c) <= 0xDFFF for c in comment)
        ):
            raise ValueError(
                "localPatches comments must be valid Unicode single-line strings of at most 2048 characters"
            )
        if advisory in seen:
            raise ValueError("Duplicate localPatches advisory assertion")
        seen.add(advisory)
        result.append({"advisory": advisory, "comment": comment})
    return result


def fixed_versions(data, item, published):
    """Use advisory and registry evidence; availability is not compatibility."""
    source = data.get("package_manager", "npm")
    vulnerability = data.get("vulnerabilities", {}).get(item["package"], {})
    details = [
        v
        for v in vulnerability.get("via", [])
        if isinstance(v, dict)
        and v.get("url") == "https://github.com/advisories/" + item["advisory"]
        and v.get("name", item["package"]) == item["package"]
    ]
    if source == "pnpm":
        details = [
            detail
            for detail in details
            if f"{item['package']}@{item['version']}" in detail.get("nodes", [])
        ]
    if not details:
        return "not-reported", []
    if source != "pnpm":
        vulnerable = set()
        for detail in details:
            affected = published(f"{item['package']}@{detail['range']}")
            if affected is None:
                return "unverified", []
            vulnerable.update(affected)
        if item["version"] not in vulnerable:
            return "not-reported", []
        if not vulnerability.get("fixAvailable"):
            return "no-fix", []
        versions = published(item["package"], all_versions=True)
        if versions is None:
            return "unverified", []
        ordered = sorted(
            (
                v
                for v in versions - vulnerable
                if tuple(map(int, v.split(".")))
                > tuple(map(int, item["version"].split(".")))
            ),
            key=lambda value: tuple(map(int, value.split("."))),
        )
        return ("fix-available" if ordered else "no-fix"), ordered[:10]
    candidates = set()
    for detail in details:
        expression = detail.get("patchedRange")
        if expression in (None, "", "<0.0.0"):
            continue
        versions = published(f"{item['package']}@{expression}")
        if versions is None:
            return "unverified", []
        candidates.update(
            v
            for v in versions
            if tuple(map(int, v.split(".")))
            > tuple(map(int, item["version"].split(".")))
        )
    ordered = sorted(candidates, key=lambda value: tuple(map(int, value.split("."))))
    return ("fix-available" if ordered else "no-fix"), ordered[:10]


def assess(declared, before, after, published, lock):
    rows = []
    evidence = before if isinstance(before, dict) else after
    for assertion in declared:
        found = []
        if isinstance(evidence, dict):
            for name, vulnerability in evidence.get("vulnerabilities", {}).items():
                details = [
                    detail
                    for detail in vulnerability.get("via", [])
                    if isinstance(detail, dict)
                    and detail.get("url")
                    == "https://github.com/advisories/" + assertion["advisory"]
                    and detail.get("name", name) == name
                ]
                if not details:
                    continue
                if evidence.get("package_manager") == "pnpm":
                    versions = {
                        node[len(name) + 1 :].split("(", 1)[0]
                        for detail in details
                        for node in detail.get("nodes", [])
                        if isinstance(node, str) and node.startswith(name + "@")
                    }
                else:
                    versions = {
                        package.get("version")
                        for node in vulnerability.get("nodes", [])
                        if isinstance(
                            package := lock.get("packages", {}).get(node), dict
                        )
                        and (package.get("name") or node.rsplit("node_modules/", 1)[-1])
                        == name
                    }
                versions = sorted(
                    version
                    for version in versions
                    if isinstance(version, str) and re.fullmatch(VERSION, version)
                )
                if not versions:
                    found.append(
                        {
                            **assertion,
                            "package": name,
                            "version": "",
                            "status": "unverified",
                            "fixedVersions": [],
                        }
                    )
                for version in versions:
                    item = {**assertion, "package": name, "version": version}
                    status, fixes = fixed_versions(evidence, item, published)
                    if status != "not-reported":
                        found.append({**item, "status": status, "fixedVersions": fixes})
        if not found:
            found.append(
                {
                    **assertion,
                    "package": "",
                    "version": "",
                    "status": "not-reported"
                    if isinstance(evidence, dict)
                    else "unverified",
                    "fixedVersions": [],
                }
            )
        rows.extend(found)
        if len(rows) > MAX_ROWS:
            raise ValueError(
                "Local patch audit report exceeds 256 affected package versions"
            )
    return {
        "schema_version": 1,
        "complete": isinstance(before, dict) and isinstance(after, dict),
        "patches": rows,
    }


def render(report):
    if not report["patches"]:
        return ""
    labels = {
        "fix-available": "Official fix available; review patch removal",
        "no-fix": "No newer stable official fix verified",
        "not-reported": "Advisory not reported; assertion retained",
        "unverified": "Official fix availability unverified",
    }

    def cell(value):
        return re.sub(
            r"[\\`*_\[\]~!|]", lambda match: f"&#{ord(match[0])};", html.escape(value)
        )

    lines = [
        "## Maintainer-declared local patches",
        "",
        "These are maintainer assertions, not independently verified security fixes. Raw registry findings remain visible. No patch is removed automatically.",
        "",
        "| Advisory | Affected package | Comment | Official fix |",
        "| --- | --- | --- | --- |",
    ]
    for item in report["patches"]:
        status = labels[item["status"]]
        if item["fixedVersions"]:
            status += ": " + item["fixedVersions"][0]
        package = item["package"] or "Not identified"
        if item["version"]:
            package += "@" + item["version"]
        lines.append(
            "| "
            + " | ".join(
                map(cell, (item["advisory"], package, item["comment"] or "—", status))
            )
            + " |"
        )
    return "\n".join(lines) + "\n\n"


def validate_report(report):
    if (
        not isinstance(report, dict)
        or set(report) != {"schema_version", "complete", "patches"}
        or type(report["schema_version"]) is not int
        or report["schema_version"] != 1
        or type(report["complete"]) is not bool
    ):
        raise ValueError("Invalid local patch report")
    rows = report["patches"]
    if not isinstance(rows, list) or len(rows) > MAX_ROWS:
        raise ValueError("Invalid local patch rows")
    assertions, seen = {}, set()
    for item in rows:
        if not isinstance(item, dict) or set(item) != {
            "advisory",
            "comment",
            "package",
            "version",
            "status",
            "fixedVersions",
        }:
            raise ValueError("Invalid local patch report entry")
        if not isinstance(item["advisory"], str) or not isinstance(
            item["comment"], str
        ):
            raise ValueError("Invalid local patch assertion")
        if (
            item["advisory"] in assertions
            and assertions[item["advisory"]] != item["comment"]
        ):
            raise ValueError("Inconsistent local patch comments")
        assertions[item["advisory"]] = item["comment"]
        if (
            not isinstance(item["package"], str)
            or (item["package"] and not re.fullmatch(PACKAGE, item["package"]))
            or not isinstance(item["version"], str)
            or (
                item["version"]
                and (not item["package"] or not re.fullmatch(VERSION, item["version"]))
            )
        ):
            raise ValueError("Invalid inferred local patch package/version")
        identity = (item["advisory"], item["package"], item["version"])
        if identity in seen:
            raise ValueError("Duplicate local patch report entry")
        seen.add(identity)
        if (
            not isinstance(item["status"], str)
            or item["status"]
            not in {"fix-available", "no-fix", "not-reported", "unverified"}
            or (
                not item["version"]
                and item["status"] not in {"not-reported", "unverified"}
            )
        ):
            raise ValueError("Invalid local patch status")
        versions = item["fixedVersions"]
        if (
            not isinstance(versions, list)
            or len(versions) > 10
            or any(
                not isinstance(v, str) or not re.fullmatch(VERSION, v) for v in versions
            )
            or bool(versions) != (item["status"] == "fix-available")
        ):
            raise ValueError("Invalid local patch official fix versions")
        if any(
            tuple(map(int, v.split("."))) <= tuple(map(int, item["version"].split(".")))
            for v in versions
        ):
            raise ValueError(
                "Official fix versions must be newer than the affected version"
            )
    validate_declarations([[key, value] for key, value in assertions.items()])


def serialize_report(report):
    """Serialize the full report within the reporter's bounded transport."""
    validate_report(report)
    data = (json.dumps(report, indent=2) + "\n").encode()
    if len(data) > MAX_REPORT_BYTES:
        raise ValueError("Local patch report exceeds its size limit")
    return data
