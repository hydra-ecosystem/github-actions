"""Select audit work from local GitHub schedules or a manual request."""

import json
import re
from pathlib import Path


def validate_schedule(schedule):
    if isinstance(schedule, list):
        if not schedule or any(
            not isinstance(value, str) or not value.strip() for value in schedule
        ):
            raise ValueError("schedule must be a nonempty list of cron expressions")
        return
    if not isinstance(schedule, dict) or not set(schedule) <= {"security", "upgrades"}:
        raise ValueError(
            "schedule must be a cron list or an object with security and upgrades lists"
        )
    for kind, values in schedule.items():
        if not isinstance(values, list):
            raise ValueError(f"schedule.{kind} must be a list of cron expressions")
        for value in values:
            if (
                not isinstance(value, str)
                or len(value.split()) != 5
                or "\n" in value
                or "\r" in value
            ):
                raise ValueError(
                    f"schedule.{kind} requires five-field cron expressions"
                )
            # GitHub validates the cron grammar in the caller workflow. Keep the
            # spelling unchanged: event.schedule identifies the exact entry.
            if not re.fullmatch(r"[A-Za-z0-9*,/ \-]+", value):
                raise ValueError(f"schedule.{kind} contains an invalid cron expression")


def cron_entries(schedule):
    validate_schedule(schedule)
    if isinstance(schedule, list):
        return schedule
    return list(
        dict.fromkeys(schedule.get("security", []) + schedule.get("upgrades", []))
    )


def select_mode(root, config, configured_mode, requested, event_name, event):
    if requested not in ("auto", "security", "upgrades"):
        raise ValueError("audit-kind must be auto, security or upgrades")
    schedule = config.get("schedule")
    if isinstance(schedule, dict):
        import yaml

        path = root / ".github/workflows/dependency-audit.yml"
        if not path.resolve().is_relative_to(root):
            raise ValueError("audit workflow resolves outside the repository")
        try:
            workflow = yaml.safe_load(path.read_text())
            events = (
                workflow.get("on", workflow.get(True))
                if isinstance(workflow, dict)
                else None
            )
            if not isinstance(events, dict):
                raise ValueError("Caller requires an on mapping")
            entries = events.get("schedule", [])
            if not isinstance(entries, list) or any(
                not isinstance(entry, dict) for entry in entries
            ):
                raise ValueError("Caller requires cron entries")
            actual = [entry["cron"] for entry in entries]
            if any(not isinstance(value, str) for value in actual):
                raise ValueError("Caller cron entries must be strings")
        except (OSError, ValueError, TypeError, KeyError, yaml.YAMLError) as error:
            raise ValueError("Cannot read the caller workflow schedules") from error
        if sorted(actual) != sorted(cron_entries(schedule)):
            raise ValueError(
                "Caller cron entries differ from the resolved schedule "
                f"{json.dumps(schedule, sort_keys=True)}; update the caller workflow "
                "or override schedule in .github/docusaurus.json"
            )
        if schedule.get("upgrades") and configured_mode == "security-only":
            raise ValueError(
                "schedule.upgrades requires maintenance.mode=security-and-maintenance; use an empty upgrades list for manual-only upgrades"
            )
    if event_name == "workflow_dispatch" and requested != "auto":
        return (
            "security-only" if requested == "security" else "security-and-maintenance"
        )
    if requested != "auto":
        raise ValueError("An explicit audit-kind is supported only for manual dispatch")
    if not isinstance(schedule, dict):
        return configured_mode  # Legacy callers and cron lists retain their policy.
    if event_name != "schedule":
        return "security-only"
    cron = event.get("schedule")
    if cron in schedule.get("upgrades", []):
        return "security-and-maintenance"  # An upgrade audit also checks security.
    if cron in schedule.get("security", []):
        return "security-only"
    raise ValueError(
        "Scheduled event does not match a configured security or upgrades cadence"
    )


def event_payload(path):
    if not path:
        return {}
    value = json.loads(Path(path).read_text())
    if not isinstance(value, dict):
        raise ValueError("GitHub event must be an object")
    return value
