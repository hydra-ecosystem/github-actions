import json
import re
from pathlib import Path
from textwrap import indent

import yaml

ROOT = Path(__file__).parents[2]


def test_caller_separates_audit_and_publisher_authority():
    caller = yaml.safe_load((ROOT / "node/caller.yml").read_text())
    audit = caller["jobs"]["audit"]
    publisher = caller["jobs"]["pull-request"]
    assert audit["permissions"] == {"contents": "read", "issues": "write"}
    shared = yaml.safe_load((ROOT / ".github/workflows/node-audit.yml").read_text())
    assert shared["jobs"]["audit"]["permissions"] == {"contents": "read"}
    assert shared["jobs"]["configuration-issue"]["permissions"] == {"issues": "write"}
    assert "secrets" not in audit
    assert publisher["permissions"] == {"contents": "write", "pull-requests": "write"}
    assert set(publisher["secrets"]) == {"app-private-key"}
    assert publisher["needs"] == "audit"
    assert audit["uses"].endswith("@__CENTRAL_REVISION__")
    assert publisher["uses"].endswith("@__CENTRAL_REVISION__")


def test_reusable_workflows_bind_sibling_actions_to_their_own_commit():
    actions = set()
    for name in ("node-audit", "node-publish"):
        workflow = yaml.safe_load((ROOT / f".github/workflows/{name}.yml").read_text())
        assert "workflow_call" in workflow["on"]
        for job in workflow["jobs"].values():
            for step in job["steps"]:
                reference = step.get("uses", "")
                if reference.startswith("$/"):
                    actions.add(reference)
                    assert (ROOT / reference[2:] / "action.yml").is_file()
    assert actions == {
        "$/node/audit",
        "$/node/project",
        "$/node/publish",
        "$/node/configuration-issue",
        "$/node/local-patch-issue",
    }


def test_auditor_never_declares_publisher_secrets():
    auditor = (ROOT / ".github/workflows/node-audit.yml").read_text()
    action = (ROOT / "node/audit/action.yml").read_text()
    assert "secrets." not in auditor + action
    assert "app-private-key" not in auditor + action


def test_public_contract_identifies_the_consumer_interface():
    contract = json.loads((ROOT / "node/contract.json").read_text())
    assert contract["schema_version"] == 1
    assert contract["integration_version"] == 6
    assert contract["component"] == "node"
    assert (ROOT / contract["caller_template"]).is_file()
    assert contract["consumer_config"] == ".github/node-maintenance.json"
    assert contract["validation_script_default"] == "build"
    assert contract["maintenance_defaults"] == {
        "mode": "security-only",
        "upgradeScope": "major",
    }
    assert contract["shared_defaults"]["local_overrides_win"] is True
    assert (ROOT / contract["shared_defaults"]["recommended_file"]).is_file()
    assert contract["minimum_release_age_days_default"] == 10
    assert contract["configuration_issue"]["reuse_closed_issue"] is True
    assert contract["audit_schedules"]["new_installation"] == {
        "security": ["0 2 * * 1"],
        "upgrades": [],
    }


def test_setup_guide_uses_the_current_caller_and_standalone_schedule():
    document = (ROOT / "docs/node-maintenance.md").read_text()
    config = next(
        json.loads(block)
        for block in re.findall(r"```json\n(.*?)\n```", document, re.S)
        if '"directory"' in block
    )
    assert config["schedule"] == {"security": ["0 2 * * 1"], "upgrades": []}
    assert config["maintenance"]["mode"] == "security-only"
    caller = next(
        yaml.safe_load(block)
        for block in re.findall(r"```yaml\n(.*?)\n```", document, re.S)
        if "jobs:" in block
    )
    expected = (
        (ROOT / "node/caller.yml")
        .read_text()
        .replace("__CENTRAL_REPOSITORY__", "hydra-ecosystem/github-actions")
        .replace("__CENTRAL_REVISION__", "REVIEWED_FULL_COMMIT_SHA")
    )
    schedule = yaml.safe_dump({"schedule": [{"cron": "0 2 * * 1"}]}, sort_keys=False)
    expected = expected.replace(
        "  schedule: []  # Rendered from the consumer project configuration.\n",
        indent(schedule, "  "),
    )
    assert caller == yaml.safe_load(expected)
    assert "9135994afb455c04c4010b3ee98742dce6e6c9af" not in document


def test_toolchain_defaults_and_pre_mutation_enforcement():
    contract = json.loads((ROOT / "node/contract.json").read_text())
    assert contract["toolchain_defaults"] == {
        "node": "project",
        "npm": "project",
        "pnpm": "project",
    }
    steps = yaml.safe_load((ROOT / "node/audit/action.yml").read_text())["runs"][
        "steps"
    ]
    verify = next(
        i for i, step in enumerate(steps) if "--verify-runtime" in step.get("run", "")
    )
    proposal = next(i for i, step in enumerate(steps) if step.get("id") == "proposal")
    assert verify < proposal


def test_ci_exercises_every_advertised_combination():
    supported = json.loads((ROOT / "node/runtime/toolchain.json").read_text())[
        "supported"
    ]
    workflow = yaml.safe_load((ROOT / ".github/workflows/validate.yml").read_text())
    assert workflow["jobs"]["toolchain"]["strategy"]["matrix"]["include"] == [
        {"node": node, "manager": manager, "version": version}
        for node in supported["node"]
        for manager in ("npm", "pnpm")
        for version in supported[manager]
    ]
