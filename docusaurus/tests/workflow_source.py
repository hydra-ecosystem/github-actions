"""Inspect the runnable workflow and action sources for behavior tests."""

import copy
from pathlib import Path

import yaml

ROOT = Path(__file__).parents[2]


def expanded_steps(steps):
    result = []
    for step in steps:
        reference = step.get("uses", "")
        if not reference.startswith("$/"):
            result.append(copy.deepcopy(step))
            continue
        directory = ROOT / reference[2:]
        action = yaml.safe_load((directory / "action.yml").read_text())
        assert action["runs"]["using"] == "composite"
        nested = expanded_steps(action["runs"]["steps"])
        if (directory / "publish.sh").exists():
            assert nested[-1]["run"] == 'bash "$GITHUB_ACTION_PATH/publish.sh"'
            nested[-1]["run"] = (directory / "publish.sh").read_text()
        nested[-1].update({key: value for key, value in step.items() if key != "uses"})
        result.extend(nested)
    return result


def load_workflow():
    audit = yaml.safe_load(
        (ROOT / ".github/workflows/docusaurus-audit.yml").read_text()
    )
    publisher = yaml.safe_load(
        (ROOT / ".github/workflows/docusaurus-publish.yml").read_text()
    )
    for value in (audit, publisher):
        assert "workflow_call" in value.get("on", value.get(True))
        for job in value["jobs"].values():
            job["steps"] = expanded_steps(job["steps"])
    audit["jobs"].update(publisher["jobs"])
    return audit
