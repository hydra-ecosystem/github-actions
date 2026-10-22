"""Exercise channel selection, main validation, and real branch lifecycles."""

import json
import os
import runpy
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from test_audit_schedules import setup
from test_node_standard import audit_module, fake_npm
from test_node_standard import npm_project as npm_project
from test_node_standard import pnpm_project as pnpm_project

ROOT = Path(__file__).parents[2]
COORDINATION = runpy.run_path(str(ROOT / "node/runtime/coordination.py"))
BRANCHES = COORDINATION["BRANCHES"]


@pytest.mark.parametrize(
    "security,upgrades", [(False, False), (True, False), (False, True), (True, True)]
)
@pytest.mark.parametrize("changed", [True, False])
def test_push_validates_main_and_refreshes_only_relevant_open_channels(
    tmp_path, security, upgrades, changed
):
    config = setup(
        tmp_path, {"security": ["0 2 * * 1"], "upgrades": []}, "security-only"
    )
    prs = [
        {"number": i + 1, "headRefName": BRANCHES[kind], "isCrossRepository": False}
        for i, (kind, enabled) in enumerate(
            (("security", security), ("upgrades", upgrades))
        )
        if enabled
    ]
    result = COORDINATION["plan"](
        tmp_path,
        config,
        {"maintenance": {"mode": "security-only"}},
        "push",
        {"repository": {"default_branch": "main"}, "ref": "refs/heads/main"},
        "auto",
        prs,
        changed_paths=["app/pnpm-lock.yaml" if changed else "other/pnpm-lock.yaml"],
        directory="app",
    )
    assert result["validate_main"] == changed
    assert result["security"] == (security and changed)
    assert result["upgrades"] == (upgrades and changed)
    assert result["refresh_only"] is True


@pytest.mark.parametrize("kind", ["security", "upgrades"])
def test_manual_requests_create_only_their_own_channel(tmp_path, kind):
    config = setup(tmp_path, {"security": [], "upgrades": []}, "security-only")
    result = COORDINATION["plan"](
        tmp_path,
        config,
        {"maintenance": {"mode": "security-only"}},
        "workflow_dispatch",
        {"repository": {"default_branch": "trunk"}, "ref": "refs/heads/trunk"},
        kind,
        [],
    )
    assert result[kind] is True
    assert result["upgrades" if kind == "security" else "security"] is False
    assert not result["refresh_only"] and not result["validate_main"]


@pytest.mark.parametrize("path", ["app/.nvmrc", "app/.node-version", ".nvmrc"])
def test_node_declaration_push_refreshes_the_open_security_proposal(tmp_path, path):
    config = setup(tmp_path, {"security": [], "upgrades": []}, "security-only")
    result = COORDINATION["plan"](
        tmp_path,
        config,
        {"maintenance": {"mode": "security-only"}},
        "push",
        {"repository": {"default_branch": "main"}, "ref": "refs/heads/main"},
        "auto",
        [
            {
                "number": 42,
                "headRefName": BRANCHES["security"],
                "isCrossRepository": False,
            }
        ],
        changed_paths=[path],
        directory="app",
    )
    assert result["validate_main"] and result["security"] and result["refresh_only"]


def test_adoption_rejects_an_unresolved_legacy_proposal(tmp_path):
    config = setup(tmp_path, {"security": [], "upgrades": []})
    with pytest.raises(ValueError, match="Merge or close the legacy"):
        COORDINATION["plan"](
            tmp_path,
            config,
            {"maintenance": {"mode": "security-and-maintenance"}},
            "push",
            {"repository": {"default_branch": "main"}, "ref": "refs/heads/main"},
            "auto",
            [
                {
                    "number": 1,
                    "headRefName": "maintenance/dependency-audit",
                    "isCrossRepository": False,
                }
            ],
        )


@pytest.mark.parametrize(
    "kind,mode",
    [("security", "security-only"), ("upgrades", "security-and-maintenance")],
)
@pytest.mark.parametrize("drifted", [False, True])
def test_resolved_policy_cannot_publish_into_the_wrong_channel(
    tmp_path, kind, mode, drifted
):
    action = yaml.safe_load((ROOT / "node/audit/action.yml").read_text())
    step = next(
        step
        for step in action["runs"]["steps"]
        if step.get("name") == "Verify the selected proposal channel"
    )
    if drifted:
        mode = (
            "security-and-maintenance" if mode == "security-only" else "security-only"
        )
    result = subprocess.run(
        ["bash", "-c", step["run"]],
        env={**os.environ, "PROPOSAL_KIND": kind, "MODE": mode},
        capture_output=True,
    )
    assert result.returncode == int(drifted)


@pytest.mark.parametrize("manager", ["npm", "pnpm"])
@pytest.mark.parametrize("failed", [False, True])
def test_validate_only_checks_committed_files_without_attempting_repairs(
    request, monkeypatch, manager, failed
):
    directory = request.getfixturevalue(manager + "_project")
    fake_npm(monkeypatch)
    module = audit_module["prepare"].__globals__
    before = audit_module["valid_snapshot"](directory)
    monkeypatch.setitem(
        module,
        "fix_security",
        lambda *a, **kw: pytest.fail("Read-only validation attempted a repair"),
    )
    commands = []

    def run(path, *args, **kwargs):
        commands.append(args)
        assert args[0] in ("ci", "install", "run", "view")
        if args[0] == "install":
            assert "--frozen-lockfile" in args
        return subprocess.CompletedProcess(
            args, int(failed and args[0] == "run"), '"1.0.0"', ""
        )

    monkeypatch.setitem(module, "run", run)
    monkeypatch.setitem(
        module,
        "audit",
        lambda *a, **kw: {
            "vulnerabilities": {},
            "metadata": {"vulnerabilities": {"total": 0}},
        },
    )
    validation = {}
    audit_module["prepare"](directory, validation=validation, validate_only=True)
    assert validation["passed"] is not failed
    assert audit_module["valid_snapshot"](directory) == before
    assert any(command[0] == "run" for command in commands)


class Publisher:
    def __init__(self, tmp_path):
        self.root = tmp_path
        self.remote = tmp_path / "remote.git"
        self.work = tmp_path / "work"
        self.git("init", "--bare", str(self.remote), cwd=tmp_path)
        self.git("clone", str(self.remote), str(self.work), cwd=tmp_path)
        self.git("config", "user.name", "Test")
        self.git("config", "user.email", "test@example.org")
        self.git("checkout", "-b", "main")
        (self.work / "app").mkdir()
        self.files("1.0.0")
        self.git("add", ".")
        self.git("commit", "-m", "baseline")
        self.git("push", "origin", "main")
        self.state = tmp_path / "state.json"
        self.state.write_text("{}")
        self.log = tmp_path / "commands.jsonl"
        binary = tmp_path / "bin"
        binary.mkdir()
        gh = binary / "gh"
        gh.write_text(f"#!{sys.executable}\n" + MOCK_GH)
        gh.chmod(0o755)
        self.env = {
            **os.environ,
            "PATH": str(binary) + os.pathsep + os.environ["PATH"],
            "STATE": str(self.state),
            "LOG": str(self.log),
            "NPM_PROJECT": "app",
            "BASE_BRANCH": "main",
            "RUNNER_TEMP": str(tmp_path),
            "PR_FOOTER": "[Workflow run](https://example.org/run)",
        }

    def git(self, *args, cwd=None):
        return subprocess.check_output(
            ["git", *args], cwd=cwd or self.work, text=True, stderr=subprocess.DEVNULL
        ).strip()

    def files(self, version):
        for name in ("package.json", "pnpm-lock.yaml"):
            (self.work / "app" / name).write_text(
                json.dumps({"version": version}) + "\n"
            )

    def publish(
        self,
        kind,
        version,
        *,
        refresh=False,
        passed=True,
        complete=True,
        stale=False,
        closed=False,
        api_error=False,
    ):
        state = json.loads(self.state.read_text())
        expected = str(state.get(BRANCHES[kind], {}).get("number", ""))
        self.git("reset", "--hard", "origin/main")
        self.git("checkout", "-B", "audit-input", "origin/main")
        sha = self.git("rev-parse", "HEAD")
        if stale:
            (self.work / "unrelated.txt").write_text("new main\n")
            self.git("add", ".")
            self.git("commit", "-m", "advance main")
            self.git("push", "origin", "HEAD:main")
            self.git("reset", "--hard", sha)
        self.files(version)
        (self.root / "dependency-audit-pr.md").write_text(
            "**1 dependency update · 1 security fix · Validation passed**\n\nOriginal report.\n"
        )
        return subprocess.run(
            ["bash", str(ROOT / "node/publish/publish.sh")],
            cwd=self.work,
            env={
                **self.env,
                "PROPOSAL_KIND": kind,
                "VALIDATION_PASSED": str(passed).lower(),
                "PROPOSAL_COMPLETE": str(complete).lower(),
                "AUDIT_SHA": sha,
                "REFRESH_ONLY": str(refresh).lower(),
                "EXPECTED_PR": expected,
                "CLOSE_ON_VIEW": str(closed).lower(),
                "API_ERROR": str(api_error).lower(),
            },
            capture_output=True,
            text=True,
        )

    def merge(self, kind):
        branch = BRANCHES[kind]
        self.git("reset", "--hard", "origin/main")
        self.git("checkout", "-B", "main", "origin/main")
        self.git("merge", "--squash", "origin/" + branch)
        self.git("commit", "-m", "merge " + kind)
        self.git("push", "origin", "main")
        state = json.loads(self.state.read_text())
        state[branch]["state"] = "MERGED"
        self.state.write_text(json.dumps(state))


MOCK_GH = """import json, os, sys
from pathlib import Path
args = sys.argv[1:]
path = Path(os.environ['STATE'])
state = json.loads(path.read_text())
with open(os.environ['LOG'], 'a') as output: output.write(json.dumps(args) + '\\n')
command = args[1]
if command == 'list':
    pr = state.get(args[args.index('--head') + 1], {})
    print(pr.get('number', '') if pr.get('state') == 'OPEN' else '')
elif command == 'create':
    branch = args[args.index('--head') + 1]
    assert branch not in state or state[branch]['state'] != 'OPEN'
    state[branch] = {'number': len(state) + 1, 'state': 'OPEN', 'isDraft': '--draft' in args,
                     'body': Path(args[args.index('--body-file') + 1]).read_text(),
                     'title': args[args.index('--title') + 1], 'baseRefName': 'main'}
else:
    pr = next(pr for pr in state.values() if str(pr['number']) == args[2])
    if command == 'view':
        key = args[args.index('--json') + 1]
        if key == 'state' and os.environ.get('API_ERROR') == 'true': sys.exit(1)
        if key == 'state' and os.environ.get('CLOSE_ON_VIEW') == 'true': pr['state'] = 'CLOSED'
        value = pr[key]
        print(str(value).lower() if isinstance(value, bool) else value)
    elif command == 'edit':
        if '--body-file' in args: pr['body'] = Path(args[args.index('--body-file') + 1]).read_text()
        if '--title' in args: pr['title'] = args[args.index('--title') + 1]
    elif command == 'ready':
        assert '--undo' in args
        pr['isDraft'] = True
    elif command == 'comment': pr.setdefault('comments', []).append(args[args.index('--body') + 1])
    elif command == 'close': pr['state'] = 'CLOSED'
    else: raise AssertionError(args)
path.write_text(json.dumps(state))
"""


@pytest.fixture
def publisher(tmp_path):
    return Publisher(tmp_path)


@pytest.mark.parametrize("first", ["security", "upgrades"])
def test_both_merge_orders_refresh_same_pr_or_close_obsolete_proposal(publisher, first):
    for kind, version in (("security", "1.0.1"), ("upgrades", "1.1.0")):
        result = publisher.publish(kind, version)
        assert result.returncode == 0, result.stderr
    publisher.merge(first)
    remaining = "upgrades" if first == "security" else "security"
    result = publisher.publish(remaining, "1.1.0", refresh=True)
    assert result.returncode == 0, result.stderr
    state = json.loads(publisher.state.read_text())
    pr = state[BRANCHES[remaining]]
    assert pr["state"] == ("OPEN" if first == "security" else "CLOSED")
    assert pr["title"].startswith("Node " + remaining + ":")
    if pr["state"] == "OPEN":
        assert publisher.git(
            "merge-base", "origin/main", "origin/" + BRANCHES[remaining]
        ) == publisher.git("rev-parse", "origin/main")
    else:
        assert "Original report." in pr["body"] and len(pr["comments"]) == 1
    commands = [json.loads(line) for line in publisher.log.read_text().splitlines()]
    assert len([c for c in commands if c[:2] == ["pr", "create"]]) == 2


@pytest.mark.parametrize("passed,complete", [(False, True), (True, False)])
def test_empty_failed_or_incomplete_proposals_do_not_close_existing_pr(
    publisher, passed, complete
):
    assert publisher.publish("security", "1.0.1").returncode == 0
    result = publisher.publish(
        "security", "1.0.0", refresh=True, passed=passed, complete=complete
    )
    assert result.returncode == (0 if passed else 1)
    assert (
        json.loads(publisher.state.read_text())[BRANCHES["security"]]["state"] == "OPEN"
    )


def test_refresh_never_creates_a_missing_pr(publisher):
    result = publisher.publish("security", "1.0.1", refresh=True)
    assert result.returncode == 0
    assert json.loads(publisher.state.read_text()) == {}
    assert not publisher.git("ls-remote", "--heads", "origin", BRANCHES["security"])


@pytest.mark.parametrize("race", ["stale", "closed", "api_error"])
def test_stale_or_closed_proposals_do_not_publish(publisher, race):
    assert publisher.publish("upgrades", "1.1.0").returncode == 0
    before = publisher.git("rev-parse", "origin/" + BRANCHES["upgrades"])
    result = publisher.publish("upgrades", "1.2.0", refresh=True, **{race: True})
    assert result.returncode == (0 if race == "closed" else 1), result.stderr
    assert publisher.git("rev-parse", "origin/" + BRANCHES["upgrades"]) == before


def test_successful_refresh_does_not_promote_an_existing_draft(publisher):
    assert publisher.publish("security", "1.0.1", passed=False).returncode == 1
    assert publisher.publish("security", "1.0.2", refresh=True).returncode == 0
    assert (
        json.loads(publisher.state.read_text())[BRANCHES["security"]]["isDraft"] is True
    )


def test_coordinator_separates_project_execution_from_write_credentials():
    workflow = yaml.safe_load(
        (ROOT / ".github/workflows/node-maintenance.yml").read_text()
    )
    for kind in ("main", "security", "upgrades"):
        job = workflow["jobs"][kind]
        assert job["permissions"] == {"contents": "read", "issues": "write"}
        assert "secrets" not in job
        assert job["with"]["artifact-prefix"] == "node-" + kind
        assert job["with"]["audit-ref"] == "${{ needs.plan.outputs.sha }}"
    for kind in ("security", "upgrades"):
        job = workflow["jobs"][kind + "-pr"]
        assert job["needs"] == ["plan", kind]
        assert job["with"]["proposal-kind"] == kind
    caller = yaml.safe_load((ROOT / "node/coordinated-caller.yml").read_text())
    assert caller["on"]["push"]["paths"] == COORDINATION["PUSH_PATHS"]
    assert caller["concurrency"]["cancel-in-progress"] is False
