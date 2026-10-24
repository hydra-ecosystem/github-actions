import json
import os
import subprocess

import pytest
from security_report_examples import (
    ENGINE,
    RELEASES,
    node_plan,
    package_evidence,
    release_index,
    release_notes,
    render_examples,
)


def test_release_history_excludes_starting_release_and_other_majors():
    data = json.loads(release_index()) + [
        {"version": "v24.18.0", "security": True},
        {"version": "v24.20.0", "security": False},
        {"version": "v26.12.1", "security": True},
    ]
    report = RELEASES["collect"](
        node_plan(), read_index=lambda: json.dumps(data), read_notes=release_notes
    )
    assert [r["version"] for r in report["releases"]] == ["24.18.1", "24.22.1"]
    assert [len(r["cves"]) for r in report["releases"]] == [11, 8]
    assert all(r["severity"] == "high" for r in report["releases"])


def test_major_only_declaration_does_not_invent_a_previous_patch_or_history():
    report = RELEASES["collect"](
        node_plan("24"),
        read_index=lambda: pytest.fail("unknown starting patch"),
        read_notes=release_notes,
    )
    assert report["previous"] is None
    assert [r["version"] for r in report["releases"]] == ["24.22.1"]
    assert "not pinned" in report["message"]


@pytest.mark.parametrize(
    "problem", ["network", "wrong-version", "no-cves", "malformed"]
)
def test_missing_cve_evidence_is_unavailable_and_never_zero(problem):
    def notes(version):
        if problem == "network":
            raise ValueError("offline")
        if problem == "wrong-version":
            return release_notes("24.18.1")
        if problem == "no-cves":
            return (
                "## 2026-01-01, Version 24.22.1\n### Notable Changes\n- deps: update\n"
            )
        return b"\xff"

    platform = RELEASES["collect"](node_plan("24"), read_notes=notes)
    text = ENGINE["format_platform_security"](platform, True)
    assert "Unavailable" in text and "CVE details unavailable" in text
    assert "0 named CVEs" not in text


def test_missing_history_shows_target_and_explicit_coverage_limit():
    def offline():
        raise ValueError("offline")

    platform = RELEASES["collect"](
        node_plan(), read_index=offline, read_notes=release_notes
    )
    assert "history unavailable" in platform["message"]
    assert [r["version"] for r in platform["releases"]] == ["24.22.1"]


def test_untrusted_versions_cannot_choose_an_arbitrary_release_note_url():
    plan = node_plan()
    plan["version"] = "../../injected"
    with pytest.raises(ValueError):
        RELEASES["collect"](plan, read_notes=lambda v: pytest.fail("untrusted URL"))


def test_release_parser_counts_unique_ids_only_in_notable_changes():
    notes = release_notes("24.22.1") + "- CVE-2026-999999 – Critical\n"
    notes = notes.replace(
        "### Commits", "- (CVE-2026-111497) duplicate fix – High\n### Commits"
    )
    result = RELEASES["parse_notes"]("24.22.1", notes)
    assert len(result["cves"]) == 8 and result["severity"] == "high"


def test_package_severity_is_independent_from_review_status_and_versions():
    before, after, locks = package_evidence()
    summary = {}
    text = ENGINE["format_audit_summary"](
        before, after, "pnpm", locks=locks, summary=summary
    )
    assert (
        "| `package-a` | `1.0.0` → `1.0.1` | Critical | 1 fixed | ✅ Fix proposed."
        in text
    )
    assert (
        "| `package-b` | `2.0.0` (unchanged) | High | 1 pending | 🟡 Needs review."
        in text
    )
    assert summary == {"fixed_packages": 1, "review_count": 1}
    assert "Pin `2.0.0` blocks fix `2.0.2`" in text


def test_unconfirmed_package_finding_retains_the_initial_advisory_link():
    before, after, locks = package_evidence()
    text = ENGINE["format_audit_summary"](
        before, after, "pnpm", locks=locks, fixed_ids=set()
    )
    row = next(line for line in text.splitlines() if line.startswith("| `package-a`"))
    assert "unconfirmed" in row
    assert "https://example.invalid/advisories/package-a" in row
    assert "Not supplied" not in row


def test_missing_local_node_declaration_notice_is_not_a_proposed_update():
    plan = node_plan()
    plan["changes"] = []
    plan["message"] = "Node security update needs a local Node declaration."
    platform = RELEASES["collect"](plan)
    text = ENGINE["format_security_overview"](
        platform=platform,
        package_report="",
        package_fixes=0,
        package_updates=0,
        review_count=0,
        passed=True,
    )
    assert plan["message"] in text
    assert text.startswith("**0 platform security updates")
    assert "Upgrade validated" not in text


def test_production_renderer_generates_all_three_scenarios(tmp_path):
    examples = render_examples(tmp_path)
    assert examples["platform-only"].startswith(
        "**1 platform security update · 0 package security fixes · Validation passed**"
    )
    assert "0 platform security updates" in examples["packages-only"].splitlines()[0]
    assert "| Security release |" not in examples["packages-only"]
    assert "1 package security fix" in examples["platform-and-packages"].splitlines()[0]
    assert (
        "1 package needs your review"
        in examples["platform-and-packages"].splitlines()[0]
    )
    assert all(
        "## Platform security" in text and "## Package security" in text
        for text in examples.values()
    )
    assert (
        "`24.18.1`" in examples["platform-only"]
        and "`24.22.1`" in examples["platform-only"]
    )


def test_failed_validation_is_not_rendered_as_a_successful_upgrade():
    platform = RELEASES["collect"](
        node_plan(), read_index=release_index, read_notes=release_notes
    )
    text = ENGINE["format_security_overview"](
        platform=platform,
        package_report="",
        package_fixes=0,
        package_updates=0,
        review_count=0,
        passed=False,
    )
    assert "Validation failed or unavailable" in text
    assert "Upgrade validated" not in text
    assert "Upgrade validation failed or unavailable" in text


def test_partially_missing_severity_does_not_understate_the_highest_severity():
    data = release_notes("24.22.1").replace(" – High", "", 1)
    report = RELEASES["parse_notes"]("24.22.1", data)
    assert report["severity"] is None
    assert len(report["cves"]) == 8


def test_node22_parenthesized_release_severities_are_available():
    # Node22.13.1 uses this format, including a bundled dependency advisory.
    notes = (
        "## 2025-01-21, Version 22.13.1 'Jod' (LTS)\n\n### Notable Changes\n"
        "- CVE-2025-23083: security fix (High)\n"
        "- CVE-2025-23085: security fix (Medium)\n"
        "- CVE-2025-23084: security fix (Medium)\n\nDependency update:\n"
        "- CVE-2025-22150: dependency fix (Medium)\n### Commits\n"
    )
    report = RELEASES["parse_notes"]("22.13.1", notes)
    assert report["severity"] == "high"
    assert len(report["cves"]) == 4


@pytest.mark.parametrize(
    "updates,fixes,routine,expected",
    [
        (3, 2, False, "Node: 3 dependency updates, 2 security fixes"),
        (1, 1, False, "Node: 1 dependency update, 1 security fix"),
        (2, 0, True, "Node: 2 routine dependency updates, no security fixes"),
        (0, None, False, "Node: 0 dependency updates, security fixes unconfirmed"),
    ],
)
def test_publisher_titles_read_actual_renderer_summaries(
    tmp_path, updates, fixes, routine, expected
):
    from workflow_source import load_workflow

    body = ENGINE["format_security_overview"](
        platform=None,
        package_report="",
        package_fixes=fixes,
        package_updates=updates,
        review_count=1,
        passed=True,
        routine_only=routine,
    )
    path = tmp_path / "report.md"
    path.write_text(body)
    script = load_workflow()["jobs"]["pull-request"]["steps"][-1]["run"]
    functions = script.split("git config user.name", 1)[0]
    result = subprocess.run(
        ["bash", "-c", functions + '\nproposal_title "$REPORT"'],
        env={**os.environ, "REPORT": str(path), "NODE_UPDATE_VERSION": ""},
        text=True,
        capture_output=True,
        check=True,
    )
    assert result.stdout.strip() == expected
