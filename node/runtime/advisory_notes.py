"""Display project-local context without changing advisory evidence or decisions."""

import html
import re
import unicodedata

GHSA = r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}"


def validate(value):
    if not isinstance(value, dict) or len(value) > 32:
        raise ValueError("advisoryNotes must be an object of at most 32 notes")
    for advisory, text in value.items():
        if not isinstance(advisory, str) or not re.fullmatch(GHSA, advisory):
            raise ValueError("advisoryNotes requires a GHSA identifier")
        if (
            not isinstance(text, str)
            or not text.strip()
            or len(text) > 2048
            or any(unicodedata.category(c) in {"Cc", "Cs", "Zl", "Zp"} for c in text)
        ):
            raise ValueError(
                "advisoryNotes values must be nonempty single-line Unicode text of at most 2048 characters"
            )
    return value


def render(data, notes):
    """Match exact GitHub advisory URLs and show each active note once."""
    validate(notes)
    if not notes or not isinstance(data, dict):
        return ""
    reported = {
        detail.get("url")
        for vulnerability in data.get("vulnerabilities", {}).values()
        for detail in vulnerability.get("via", [])
        if isinstance(detail, dict)
    }
    rows = []
    for advisory, text in sorted(notes.items()):
        if "https://github.com/advisories/" + advisory not in reported:
            continue
        # Encode formatting as text, including table separators and task markers.
        escaped = re.sub(
            r"[\\`*_\[\]~!|]",
            lambda match: f"&#{ord(match[0])};",
            html.escape(text),
        )
        rows.append(f"- **{advisory}**: {escaped}")
    if not rows:
        return ""
    return (
        "**Maintainer notes**\n\n"
        "Project context only. Findings, severity and repair eligibility are unchanged.\n\n"
        + "\n".join(rows)
        + "\n\n"
    )
