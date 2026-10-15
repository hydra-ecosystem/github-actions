import json
from pathlib import Path

import yaml

ROOT = Path(__file__).parents[2]


def test_caller_separates_audit_and_publisher_authority():
    caller = yaml.safe_load((ROOT / "docusaurus/caller.yml").read_text())
    audit = caller["jobs"]["audit"]
    publisher = caller["jobs"]["pull-request"]
    assert audit["permissions"] == {"contents": "read"}
    assert "secrets" not in audit
    assert publisher["permissions"] == {"contents": "write", "pull-requests": "write"}
    assert set(publisher["secrets"]) == {"app-private-key"}
    assert publisher["needs"] == "audit"
    assert audit["uses"].endswith("@__CENTRAL_REVISION__")
    assert publisher["uses"].endswith("@__CENTRAL_REVISION__")


def test_reusable_workflows_bind_sibling_actions_to_their_own_commit():
    actions = set()
    for name in ("docusaurus-audit", "docusaurus-publish"):
        workflow = yaml.safe_load((ROOT / f".github/workflows/{name}.yml").read_text())
        assert "workflow_call" in workflow["on"]
        for job in workflow["jobs"].values():
            for step in job["steps"]:
                reference = step.get("uses", "")
                if reference.startswith("$/"):
                    actions.add(reference)
                    assert (ROOT / reference[2:] / "action.yml").is_file()
    assert actions == {
        "$/docusaurus/audit",
        "$/docusaurus/project",
        "$/docusaurus/publish",
    }


def test_auditor_never_declares_publisher_secrets():
    auditor = (ROOT / ".github/workflows/docusaurus-audit.yml").read_text()
    action = (ROOT / "docusaurus/audit/action.yml").read_text()
    assert "secrets." not in auditor + action
    assert "app-private-key" not in auditor + action


def test_public_contract_identifies_the_consumer_interface():
    contract = json.loads((ROOT / "docusaurus/contract.json").read_text())
    assert contract["schema_version"] == 1
    assert contract["integration_version"] == 1
    assert contract["component"] == "docusaurus"
    assert (ROOT / contract["caller_template"]).is_file()
    assert contract["consumer_config"] == ".github/docusaurus.json"
