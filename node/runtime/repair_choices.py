"""The PR's editable consent list; it grants a bounded attempt, not a merge."""

import re

START = "<!-- node-repair:selection:v1 -->"
END = "<!-- /node-repair:selection -->"
NAME = r"(?:@[a-z0-9._-]+/)?[a-z0-9][a-z0-9._-]*"
VERSION = r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
LINE = re.compile(
    rf"- \[([ xX])\] Allow `({NAME})` `({VERSION}) → ({VERSION})` by updating its explicit pin\."
)


def validate(items):
    if not isinstance(items, list) or not 1 <= len(items) <= 20:
        raise ValueError("Select between one and twenty fixes")
    names = set()
    for item in items:
        if not isinstance(item, dict) or set(item) != {"name", "from", "to"}:
            raise ValueError("Invalid repair selection")
        if not isinstance(item["name"], str) or not re.fullmatch(NAME, item["name"]):
            raise ValueError("Invalid package name")
        if any(
            not isinstance(item[key], str) or not re.fullmatch(VERSION, item[key])
            for key in ("from", "to")
        ):
            raise ValueError("Repair versions must be exact stable versions")
        old, new = (tuple(map(int, item[key].split("."))) for key in ("from", "to"))
        if old[:2] != new[:2] or new <= old or item["name"] in names:
            raise ValueError("Only distinct, same-minor patch upgrades are supported")
        names.add(item["name"])
    return sorted(items, key=lambda item: item["name"])


def parse(body):
    if body.count(START) != 1 or body.count(END) != 1:
        raise ValueError("Missing or duplicate repair selection block")
    block = body.split(START)[1].split(END)[0]
    items = []
    for line in block.strip().splitlines():
        match = LINE.fullmatch(line)
        if match is None:
            raise ValueError("The repair selection block was changed; rerun the audit")
        if match[1].lower() == "x":
            items.append(dict(zip(("name", "from", "to"), match.groups()[1:])))
    return validate(items)


def candidates(data):
    """Offer only exact pin patch attempts with verified published compatibility.

    Registry status supplies a feasibility hint. The repair runner independently
    verifies every advisory, parent constraint and release age before changing it.
    """
    if not isinstance(data, dict) or data.get("package_manager") != "pnpm":
        return []
    result = []
    for name, finding in sorted(data.get("vulnerabilities", {}).items()):
        choices = set()
        for detail in finding.get("via", []):
            status = detail.get("fixStatus", "") if isinstance(detail, dict) else ""
            match = re.fullmatch(
                rf"Published patch: `{re.escape(name)}@({VERSION})`\. "
                rf"Blocked by retained override `pnpm-workspace\.yaml overrides\.{re.escape(name)}` = `({VERSION})`\. "
                r"Override preserved for manual compatibility review\.",
                status,
            )
            if match is None:
                break
            choices.add((match[2], match[1]))
        else:
            if len(choices) == 1:
                old, new = choices.pop()
                try:
                    result.extend(validate([{"name": name, "from": old, "to": new}]))
                except ValueError:
                    pass
    return result[:20]


def render(items):
    if not items:
        return ""
    return (
        "\n## Choose fixes to try\n\n"
        "These published patches appear compatible with checked parent constraints. "
        "The pin changes have not been tested in this run. Selecting them permits "
        "one repair attempt; it does not approve merging.\n\n"
        + START
        + "\n"
        + "\n".join(
            f"- [ ] Allow `{item['name']}` `{item['from']} → {item['to']}` by updating its explicit pin."
            for item in items
        )
        + "\n"
        + END
        + "\n\nWith the repair App and workflow installed, open **Checks → Dependency repair** "
        "and click **Run selected fixes**. The check shows the selected versions. "
        "Checkboxes alone do not start a run. Failed validation leaves this PR's files "
        "unchanged. See the repository's repair setup guide for installation.\n"
    )
