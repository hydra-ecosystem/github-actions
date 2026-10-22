"""Node-only security proposals must survive validation and reach a real PR branch."""

import copy
import json
import os
import runpy
import subprocess
import sys
from pathlib import Path

import pytest
from workflow_source import load_workflow

ROOT = Path(__file__).parents[2]
PROJECT = runpy.run_path(str(ROOT / "node/runtime/project.py"))
PROPOSAL = PROJECT["NODE_PROPOSAL"]
ENGINE = runpy.run_path(str(ROOT / "node/runtime/templates/dependency_audit.py"))
PUBLISH = load_workflow()["jobs"]["pull-request"]["steps"][-1]


@pytest.fixture(autouse=True)
def release_index(monkeypatch):
    monkeypatch.setitem(
        PROPOSAL["SECURITY"]["latest_security_release"].__globals__,
        "read_release_index",
        lambda: '[{"version":"v24.22.1","security":true}]',
    )


def site(root, declaration="24\n"):
    directory = root / "website"
    directory.mkdir(parents=True)
    (root / ".github").mkdir()
    (root / ".github/node-maintenance.json").write_text(
        json.dumps({"directory": "website", "validationScript": "check"})
    )
    (directory / ".nvmrc").write_text(declaration)
    manifest = {
        "name": "node-proposal-test",
        "version": "1.0.0",
        "private": True,
        "packageManager": "npm@11.9.0",
        "engines": {"node": ">=24"},
        "scripts": {"check": "node --test"},
    }
    (directory / "package.json").write_text(json.dumps(manifest))
    (directory / "package-lock.json").write_text(
        json.dumps({"lockfileVersion": 3, "packages": {"": manifest}})
    )
    return directory


@pytest.mark.parametrize("declaration", ["24\n", "24.21.0\n", "v24\n"])
def test_security_candidate_is_persisted_before_configuration_freezes(
    tmp_path, declaration
):
    directory = site(tmp_path, declaration)
    snapshot, plan = tmp_path / "resolved.json", tmp_path / "node-update.json"
    _, selected = PROJECT["resolve_for_run"](
        tmp_path, snapshot, [], node_update_path=plan, propose_node=True
    )
    assert selected["node"] == "24.22.1"
    assert (directory / ".nvmrc").read_text().strip().removeprefix("v") == "24.22.1"
    data = PROPOSAL["read_plan"](plan)
    assert data["changes"][0]["before"] == declaration
    assert data["changes"][0]["path"] == "website/.nvmrc"
    assert PROJECT["resolve_for_run"](tmp_path, snapshot, [])[1] == selected


@pytest.mark.parametrize("declared", ["24.22.1", "24.23.0"])
def test_current_or_newer_exact_pins_are_not_changed(tmp_path, declared):
    directory = site(tmp_path, declared + "\n")
    plan = PROPOSAL["prepare"](tmp_path, directory, {"node": declared}, enabled=True)
    assert not plan["changes"]


def test_root_and_paired_declarations_and_owned_configuration_align(tmp_path):
    directory = site(tmp_path, "24.21.0\n")
    (directory / ".nvmrc").unlink()
    (tmp_path / ".nvmrc").write_text("24.21.0\n")
    (tmp_path / ".node-version").write_text("24.21.0\n")
    config = tmp_path / ".github/node-maintenance.json"
    data = json.loads(config.read_text())
    data["toolchain"] = {"node": "24.21.0"}
    config.write_text(json.dumps(data))
    _, selected = PROJECT["resolve_for_run"](
        tmp_path,
        tmp_path / "resolved.json",
        [],
        node_update_path=tmp_path / "plan.json",
        propose_node=True,
    )
    assert selected["node"] == "24.22.1"
    assert (tmp_path / ".nvmrc").read_text() == "24.22.1\n"
    assert (tmp_path / ".node-version").read_text() == "24.22.1\n"
    assert json.loads(config.read_text())["toolchain"]["node"] == "24.22.1"
    assert json.loads(config.read_text())["validationScript"] == "check"


def test_incompatible_inherited_pin_is_not_overridden_and_edits_are_restored(
    tmp_path, monkeypatch
):
    directory = site(tmp_path)
    inherited = {
        "directory": "website",
        "validationScript": "check",
        "toolchain": {"node": "24.21.0"},
    }
    monkeypatch.setitem(
        PROJECT["CONFIGURATION"], "load_configuration", lambda root, sources: inherited
    )
    with pytest.raises(ValueError, match="Conflicting Node declarations"):
        PROJECT["resolve_for_run"](
            tmp_path,
            tmp_path / "resolved.json",
            [],
            node_update_path=tmp_path / "plan.json",
            propose_node=True,
        )
    assert (directory / ".nvmrc").read_text() == "24\n"
    assert "toolchain" not in json.loads(
        (tmp_path / ".github/node-maintenance.json").read_text()
    )
    assert not (tmp_path / "plan.json").exists()


def test_validation_and_upgrades_channel_can_disable_proposals(tmp_path, monkeypatch):
    directory = site(tmp_path)
    monkeypatch.setitem(
        PROPOSAL["SECURITY"],
        "latest_security_release",
        lambda major: pytest.fail("must not plan a runtime update"),
    )
    plan = PROPOSAL["prepare"](tmp_path, directory, {"node": "24"}, enabled=False)
    assert not plan["changes"]
    assert (directory / ".nvmrc").read_text() == "24\n"


@pytest.mark.parametrize(
    "problem",
    ["path", "before", "after", "major", "stale-base", "new-release", "symlink"],
)
def test_publisher_rejects_untrusted_or_stale_node_edits(
    tmp_path, monkeypatch, problem
):
    directory = site(tmp_path)
    plan = PROPOSAL["prepare"](tmp_path, directory, {"node": "24"}, enabled=True)
    plan = copy.deepcopy(plan)
    if problem == "path":
        plan["changes"][0]["path"] = ".github/workflows/injected.yml"
    elif problem == "before":
        plan["changes"][0]["before"] = "24.21.0\n"
    elif problem == "after":
        plan["changes"][0]["after"] = "26.12.1\n"
    elif problem == "major":
        plan["version"] = "26.12.1"
    elif problem == "stale-base":
        (directory / ".nvmrc").write_text("24.21.0\n")
    elif problem == "new-release":
        monkeypatch.setitem(
            PROPOSAL["SECURITY"], "latest_security_release", lambda major: "24.23.1"
        )
    elif problem == "symlink":
        (directory / ".nvmrc").unlink()
        (directory / "other").write_text("24\n")
        (directory / ".nvmrc").symlink_to("other")
    before = {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: pytest.fail("must not stage an invalid artifact"),
    )
    with pytest.raises(ValueError):
        PROPOSAL["publish"](tmp_path, plan)
    assert all(path.read_bytes() == content for path, content in before.items())


@pytest.mark.parametrize("failed_check", [False, True])
def test_node_only_update_reaches_a_real_publisher_branch(
    tmp_path, monkeypatch, failed_check
):
    remote, audit_root, publisher = (
        tmp_path / "remote.git",
        tmp_path / "audit",
        tmp_path / "publisher",
    )

    def git(*args, cwd=audit_root):
        return subprocess.check_output(["git", *args], cwd=cwd, text=True).strip()

    subprocess.run(
        ["git", "init", "--bare", str(remote)], check=True, capture_output=True
    )
    git("clone", str(remote), str(audit_root), cwd=tmp_path)
    site(audit_root)
    git("config", "user.name", "Test")
    git("config", "user.email", "test@example.org")
    git("checkout", "-b", "main")
    git("add", ".")
    git("commit", "-m", "baseline")
    git("push", "origin", "main")
    original = git("rev-parse", "HEAD")
    plan_path, snapshot, report = (
        tmp_path / "node-audit-node-update.json",
        tmp_path / "resolved.json",
        tmp_path / "dependency-audit-pr.md",
    )
    PROJECT["resolve_for_run"](
        audit_root, snapshot, [], node_update_path=plan_path, propose_node=True
    )
    audit_data = {
        "auditReportVersion": 2,
        "metadata": {"vulnerabilities": {"total": 0}},
        "vulnerabilities": {},
    }

    def run(directory, *args, **kwargs):
        output = json.dumps(audit_data) if args[:2] == ("audit", "--json") else ""
        status = int(failed_check and args[:2] == ("run", "check"))
        return subprocess.CompletedProcess(args, status, output, "")

    with monkeypatch.context() as patch:
        patch.chdir(audit_root)
        patch.setitem(ENGINE["prepare"].__globals__, "run", run)
        patch.setattr(
            sys,
            "argv",
            [
                "dependency_audit.py",
                "--directory",
                "website",
                "--report",
                str(report),
                "--validation-script",
                "check",
                "--maintenance-mode",
                "security-only",
                "--resolved-config",
                str(snapshot),
                "--node-update",
                str(plan_path),
            ],
        )
        ENGINE["main"]()
    assert "Node runtime security update to 24.22.1" in report.read_text()
    assert "0 security fixes" in report.read_text()
    git("clone", "--branch", "main", str(remote), str(publisher), cwd=tmp_path)
    target = PROPOSAL["publish"](publisher, PROPOSAL["read_plan"](plan_path))
    binary = tmp_path / "bin"
    binary.mkdir()
    gh = binary / "gh"
    gh.write_text(
        f"#!{sys.executable}\nimport json,sys\nfrom pathlib import Path\n"
        f"path=Path({str(tmp_path / 'gh-commands.jsonl')!r})\n"
        "with path.open('a') as stream: stream.write(json.dumps(sys.argv[1:])+'\\n')\n"
    )
    gh.chmod(0o755)
    result = subprocess.run(
        ["bash", "-c", PUBLISH["run"]],
        cwd=publisher,
        env={
            **os.environ,
            "PATH": str(binary) + os.pathsep + os.environ["PATH"],
            "NPM_PROJECT": "website",
            "BASE_BRANCH": "main",
            "PR_BRANCH": "unused",
            "PROPOSAL_KIND": "security",
            "AUDIT_SHA": original,
            "VALIDATION_PASSED": str(not failed_check).lower(),
            "RUNNER_TEMP": str(tmp_path),
            "NODE_UPDATE_VERSION": target,
            "PR_FOOTER": "Sample run",
        },
        capture_output=True,
        text=True,
    )
    assert result.returncode == int(failed_check), result.stdout + result.stderr
    branch = "refs/heads/maintenance/node-security"
    assert (
        git("--git-dir", str(remote), "show", f"{branch}:website/.nvmrc", cwd=tmp_path)
        == "24.22.1"
    )
    assert (
        git(
            "--git-dir",
            str(remote),
            "diff",
            "--name-only",
            original,
            branch,
            cwd=tmp_path,
        )
        == "website/.nvmrc"
    )
    commands = [
        json.loads(line)
        for line in (tmp_path / "gh-commands.jsonl").read_text().splitlines()
    ]
    create = next(command for command in commands if command[:2] == ["pr", "create"])
    assert ("--draft" in create) == failed_check
    assert (
        create[create.index("--title") + 1]
        == "Node security: runtime security update to 24.22.1"
    )
