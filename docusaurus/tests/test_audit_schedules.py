import json
import os
import runpy
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parents[2]
runtime = ROOT / "docusaurus/runtime"
policy = runpy.run_path(str(runtime / "scheduling.py"))
reader = runpy.run_path(str(runtime / "project.py"))
WEEKLY = "0 2 * * 1"
QUARTERLY = "0 2 1 */3 *"


def setup(tmp_path, schedule, mode="security-and-maintenance"):
    (tmp_path / ".github/workflows").mkdir(parents=True)
    config = {
        "directory": "website",
        "schedule": schedule,
        "maintenance": {"mode": mode},
    }
    (tmp_path / ".github/docusaurus.json").write_text(json.dumps(config))
    template = (ROOT / "docusaurus/caller.yml").read_text()
    entries = policy["cron_entries"](schedule)
    replacement = (
        yaml.safe_dump({"schedule": [{"cron": c} for c in entries]}, sort_keys=False)
        if entries
        else ""
    )
    from textwrap import indent

    template = template.replace(
        "  schedule: []  # Rendered from the consumer project configuration.\n",
        indent(replacement, "  "),
    )
    (tmp_path / ".github/workflows/dependency-audit.yml").write_text(template)
    return config


@pytest.mark.parametrize(
    "cron,expected",
    [(WEEKLY, "security-only"), (QUARTERLY, "security-and-maintenance")],
)
def test_independent_weekly_and_quarterly_cadences(tmp_path, cron, expected):
    config = setup(tmp_path, {"security": [WEEKLY], "upgrades": [QUARTERLY]})
    assert (
        policy["select_mode"](
            tmp_path,
            config,
            "security-and-maintenance",
            "auto",
            "schedule",
            {"schedule": cron},
        )
        == expected
    )


@pytest.mark.parametrize(
    "kind,expected",
    [
        ("security", "security-only"),
        ("upgrades", "security-and-maintenance"),
        ("auto", "security-only"),
    ],
)
def test_manual_request_with_automatic_upgrades_disabled(tmp_path, kind, expected):
    config = setup(tmp_path, {"security": [WEEKLY], "upgrades": []}, "security-only")
    assert (
        policy["select_mode"](
            tmp_path, config, "security-only", kind, "workflow_dispatch", {}
        )
        == expected
    )


def test_valid_github_caller_can_use_an_unquoted_on_key(tmp_path):
    config = setup(tmp_path, {"security": [WEEKLY], "upgrades": []}, "security-only")
    path = tmp_path / ".github/workflows/dependency-audit.yml"
    path.write_text(path.read_text().replace("'on':", "on:"))
    assert (
        policy["select_mode"](
            tmp_path, config, "security-only", "auto", "schedule", {"schedule": WEEKLY}
        )
        == "security-only"
    )


def test_matching_entries_select_one_combined_audit(tmp_path):
    config = setup(tmp_path, {"security": [WEEKLY], "upgrades": [WEEKLY]})
    workflow = yaml.safe_load(
        (tmp_path / ".github/workflows/dependency-audit.yml").read_text()
    )
    assert workflow["on"]["schedule"] == [{"cron": WEEKLY}]
    assert (
        policy["select_mode"](
            tmp_path,
            config,
            "security-and-maintenance",
            "auto",
            "schedule",
            {"schedule": WEEKLY},
        )
        == "security-and-maintenance"
    )


@pytest.mark.parametrize("schedule", [{}, {"security": [], "upgrades": []}])
def test_manual_only_installation_has_no_scheduled_events(tmp_path, schedule):
    config = setup(tmp_path, schedule, "security-only")
    workflow = yaml.safe_load(
        (tmp_path / ".github/workflows/dependency-audit.yml").read_text()
    )
    assert "schedule" not in workflow["on"]
    assert (
        policy["select_mode"](
            tmp_path, config, "security-only", "upgrades", "workflow_dispatch", {}
        )
        == "security-and-maintenance"
    )


@pytest.mark.parametrize("mode", ["security-only", "security-and-maintenance"])
def test_legacy_schedule_and_omitted_schedule_retain_their_mode(tmp_path, mode):
    for config in ({"schedule": [WEEKLY]}, {}):
        assert (
            policy["select_mode"](
                tmp_path, config, mode, "auto", "schedule", {"schedule": WEEKLY}
            )
            == mode
        )


@pytest.mark.parametrize(
    "change,match",
    [
        ("caller", "differ"),
        ("event", "does not match"),
        ("mode", "requires maintenance.mode"),
        ("request", "only for manual"),
    ],
)
def test_invalid_selection_fails_before_dependency_commands(tmp_path, change, match):
    config = setup(tmp_path, {"security": [WEEKLY], "upgrades": [QUARTERLY]})
    mode, request, cron = "security-and-maintenance", "auto", WEEKLY
    if change == "caller":
        path = tmp_path / ".github/workflows/dependency-audit.yml"
        path.write_text(path.read_text().replace(WEEKLY, "30 2 * * 1"))
    elif change == "event":
        cron = "0 5 * * 2"
    elif change == "mode":
        mode = "security-only"
    else:
        request = "upgrades"
    with pytest.raises(ValueError, match=match):
        policy["select_mode"](
            tmp_path, config, mode, request, "schedule", {"schedule": cron}
        )


@pytest.mark.parametrize(
    "schedule",
    [
        None,
        True,
        {"typo": []},
        {"upgrades": "weekly"},
        {"security": ["weekly"]},
        {"security": ["0 2 * * 1\n"]},
        {"upgrades": [42]},
    ],
)
def test_invalid_schedule_is_rejected(schedule):
    with pytest.raises(ValueError, match="schedule"):
        reader["CONFIGURATION"]["validate_settings"]({"schedule": schedule}, "test")


@pytest.mark.parametrize(
    "cron,kind,expected",
    [
        (WEEKLY, "auto", "security-only"),
        (QUARTERLY, "auto", "security-and-maintenance"),
        (WEEKLY, "upgrades", "security-and-maintenance"),
    ],
)
def test_real_project_cli_applies_selection_on_both_preflight_steps(
    tmp_path, cron, kind, expected
):
    setup(tmp_path, {"security": [WEEKLY], "upgrades": [QUARTERLY]})
    site = tmp_path / "website"
    site.mkdir()
    (site / "package.json").write_text(
        json.dumps(
            {
                "packageManager": "pnpm@11.21.0",
                "dependencies": {"@docusaurus/core": "3.10.2"},
                "scripts": {"build": "site build"},
            }
        )
    )
    (site / "pnpm-workspace.yaml").write_text("minimumReleaseAge: 14400\n")
    (site / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n")
    binary = tmp_path / "bin"
    binary.mkdir()
    for name, version in (("node", "v24.14.0"), ("corepack", "11.21.0")):
        executable = binary / name
        executable.write_text(f"#!/bin/sh\necho '{version}'\n")
        executable.chmod(0o755)
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"schedule": cron}))
    env = {
        **os.environ,
        "PATH": str(binary) + os.pathsep + os.environ["PATH"],
        "GITHUB_EVENT_NAME": "schedule" if kind == "auto" else "workflow_dispatch",
        "GITHUB_EVENT_PATH": str(event),
    }
    args = [
        sys.executable,
        str(runtime / "project.py"),
        "--root",
        str(tmp_path),
        "--resolved-config",
        str(tmp_path / "resolved.json"),
        "--configuration-report",
        str(tmp_path / "status.json"),
        "--audit-kind",
        kind,
    ]
    for extra in ([], ["--verify-runtime"]):
        result = subprocess.run(
            args + extra, env=env, capture_output=True, text=True, check=True
        )
        assert f"DOCUSAURUS_MAINTENANCE_MODE={expected}\n" in result.stdout
    assert (
        json.loads((tmp_path / "resolved.json").read_text())["configuration"][
            "maintenance"
        ]["mode"]
        == "security-and-maintenance"
    )


def test_caller_forwards_manual_choice_and_publisher_is_serialized():
    caller = yaml.safe_load((ROOT / "docusaurus/caller.yml").read_text())
    assert (
        caller["on"]["workflow_dispatch"]["inputs"]["audit-kind"]["default"]
        == "security"
    )
    assert "inputs.audit-kind" in caller["jobs"]["audit"]["with"]["audit-kind"]
    publisher = yaml.safe_load(
        (ROOT / ".github/workflows/docusaurus-publish.yml").read_text()
    )
    assert (
        publisher["jobs"]["pull-request"]["concurrency"]["cancel-in-progress"] is False
    )
