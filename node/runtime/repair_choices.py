"""Bounded repair choices shared by the report and App consent contract."""

import hashlib
import json
import re

START = "<!-- node-repair:selection:v1 -->"
END = "<!-- /node-repair:selection -->"
PACKAGE = r"(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*"
VERSION = r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
SHA = r"[a-f0-9]{40}"
LINE = re.compile(
    rf"- \[([ xX])\] Allow `({PACKAGE})` `({VERSION}) → ({VERSION})` by updating its explicit pin\."
)


def _version_tuple(value):
    if not isinstance(value, str) or not re.fullmatch(VERSION, value):
        return None
    return tuple(value.split("."))


def _patch_key(version):
    return len(version[2]), version[2]


def validate(items):
    """Return canonical sorted items; an empty selection is valid."""
    if not isinstance(items, list) or len(items) > 20:
        raise ValueError("Select at most twenty fixes")
    result, names = [], set()
    for item in items:
        if not isinstance(item, dict) or set(item) != {"name", "from", "to"}:
            raise ValueError("Invalid selection fields")
        name = item["name"]
        if (
            not isinstance(name, str)
            or not re.fullmatch(PACKAGE, name)
            or len(name) > 214
            or name in {"node_modules", "favicon.ico"}
            or name in names
        ):
            raise ValueError("Invalid or duplicate package")
        if any(
            not isinstance(item[key], str) or not re.fullmatch(VERSION, item[key])
            for key in ("from", "to")
        ):
            raise ValueError("Versions must be exact stable versions")
        old, new = (item[key].split(".") for key in ("from", "to"))
        if old[:2] != new[:2] or (len(old[2]), old[2]) >= (len(new[2]), new[2]):
            raise ValueError("Only increasing same-minor patches are allowed")
        names.add(name)
        result.append({"name": name, "from": item["from"], "to": item["to"]})
    return sorted(result, key=lambda item: item["name"])


def parse(body):
    if not isinstance(body, str) or body.count(START) != 1 or body.count(END) != 1:
        raise ValueError("Expected one selection block")
    lines = re.split(r"\r?\n", body)
    try:
        start, end = lines.index(START), lines.index(END)
    except ValueError as error:
        raise ValueError("Selection markers must occupy their own lines") from error
    if end <= start:
        raise ValueError("Selection markers are out of order")
    all_items, selected = [], []
    for line in lines[start + 1 : end]:
        match = LINE.fullmatch(line)
        if match is None:
            raise ValueError("Invalid selection line")
        item = dict(zip(("name", "from", "to"), match.groups()[1:]))
        all_items.append(item)
        if match[1].lower() == "x":
            selected.append(item)
    # App validation covers unchecked entries and duplicates too. Only checked
    # entries count against the twenty-selection limit.
    names = set()
    for item in all_items:
        validate([item])
        if item["name"] in names:
            raise ValueError("Duplicate package")
        names.add(item["name"])
    return validate(selected)


def revision_marker(head, base):
    if any(
        not isinstance(value, str) or not re.fullmatch(SHA, value)
        for value in (head, base)
    ):
        raise ValueError("Exact head and base revisions are required")
    return f"<!-- node-repair:revision:v1 {head} {base} -->"


def fingerprint(pr, head, base, items):
    if type(pr) is not int or not 0 < pr <= 9_007_199_254_740_991:
        raise ValueError("Invalid PR number")
    revision_marker(head, base)
    payload = json.dumps(
        [pr, head, base, validate(items)], separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def candidates(data):
    """Use the audit engine's verified evidence, never a parsed status label."""
    if not isinstance(data, dict) or data.get("package_manager") != "pnpm":
        return []
    result = []
    for name, finding in sorted(data.get("vulnerabilities", {}).items()):
        details = finding.get("via", [])
        if not details or not all(isinstance(detail, dict) for detail in details):
            continue
        # The audit engine retains an eligible version set for every advisory.
        # Intersect those sets before choosing one patch so a lower version from
        # one advisory cannot hide a later patch that satisfies all advisories.
        if any("_verifiedPatchedVersions" in detail for detail in details):
            evidence = []
            repair_from = []
            for detail in details:
                versions = detail.get("_verifiedRepairVersions")
                source = detail.get("_repairFrom")
                if not isinstance(versions, list) or not versions:
                    evidence = []
                    break
                parsed = {_version_tuple(version) for version in versions}
                if None in parsed:
                    evidence = []
                    break
                if _version_tuple(source) is None:
                    evidence = []
                    break
                evidence.append(set(versions))
                repair_from.append(source)
            if not evidence or len(set(repair_from)) != 1:
                continue
            common = set.intersection(*evidence)
            old_version = _version_tuple(repair_from[0])
            eligible = [
                version
                for version in common
                if (parsed_version := _version_tuple(version)) is not None
                and parsed_version[:2] == old_version[:2]
                and _patch_key(parsed_version) > _patch_key(old_version)
            ]
            if not eligible:
                continue
            try:
                items = validate(
                    [
                        {
                            "name": name,
                            "from": repair_from[0],
                            "to": min(
                                eligible,
                                key=lambda version: _patch_key(_version_tuple(version)),
                            ),
                        }
                    ]
                )
            except ValueError:
                continue
            result.extend(items)
            continue
    return result[:20]


def render(items, *, head, base):
    """Render consent only with the exact revisions of the published PR."""
    items = validate(items)
    marker = revision_marker(head, base)
    if not items:
        return ""
    return (
        "\n## Choose fixes to try\n\n"
        "These patches appear compatible with the checked parent constraints. "
        "Repair validation has not run. Selecting a fix permits one attempt; "
        "it does not approve merging.\n\n"
        + START
        + "\n"
        + "\n".join(
            f"- [ ] Allow `{item['name']}` `{item['from']} → {item['to']}` by updating its explicit pin."
            for item in items
        )
        + "\n"
        + END
        + "\n"
        + marker
        + "\n\n### Run selected fixes\n\n"
        "Select the fixes above, then post a **new comment** containing only "
        "`/repair selected` and click GitHub's **Comment** button. "
        "The bot acknowledges the request and updates the same reply with the result. "
        "Checkbox edits alone start no work. Nothing merges automatically.\n"
    )
