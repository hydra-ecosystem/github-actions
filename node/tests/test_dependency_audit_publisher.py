# Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved
import json
import os
import subprocess
import sys

import pytest
from workflow_source import load_workflow

WORKFLOW = load_workflow()
PUBLISH = WORKFLOW["jobs"]["pull-request"]["steps"][-1]


def test_app_credentials_are_scoped_to_trusted_repository_publishing():
    audit = WORKFLOW["jobs"]["audit"]
    assert "secrets." not in json.dumps(audit)
    assert "app-token" not in json.dumps(audit)
    assert WORKFLOW["permissions"] == {"contents": "read"}
    assert set(audit.get("needs", [])) == set()

    steps = WORKFLOW["jobs"]["pull-request"]["steps"]
    app = next(step for step in steps if step.get("id") == "app-token")
    checkout = next(
        step for step in steps if step.get("uses", "").startswith("actions/checkout@")
    )
    assert steps.index(app) < steps.index(checkout)
    assert app["if"] == "${{ inputs.app-client-id != '' }}"
    assert "continue-on-error" not in app
    assert app["with"]["owner"] == "${{ github.repository_owner }}"
    assert app["with"]["repositories"] == "${{ github.event.repository.name }}"
    permissions = {
        key: value
        for key, value in app["with"].items()
        if key.startswith("permission-")
    }
    assert permissions == {
        "permission-contents": "write",
        "permission-pull-requests": "write",
    }
    assert app["with"].get("skip-token-revoke", False) is False
    assert checkout["with"]["token"] == PUBLISH["env"]["GH_TOKEN"]
    assert checkout["with"]["token"] == (
        "${{ steps.app-token.outputs.token || github.token }}"
    )
    assert checkout["with"].get("persist-credentials", True) is True
    assert "if" not in checkout and "if" not in PUBLISH


@pytest.mark.parametrize("failed_replay", [False, True])
@pytest.mark.parametrize("changed_base", [False, True])
@pytest.mark.parametrize("changed_report", [False, True])
@pytest.mark.parametrize("changed_title", [False, True])
def test_repeated_audits_refresh_one_pr_only_when_proposal_is_outdated(
    tmp_path, failed_replay, changed_base, changed_report, changed_title
):

    def git(*args, cwd=None):
        return subprocess.check_output(
            ["git", *args], cwd=cwd or work, text=True
        ).strip()

    remote, work = tmp_path / "remote.git", tmp_path / "work"
    git("init", "--bare", str(remote), cwd=tmp_path)
    git("clone", str(remote), str(work), cwd=tmp_path)
    git("config", "user.name", "Test")
    git("config", "user.email", "test@example.org")
    git("checkout", "-b", "main")
    (work / "website").mkdir()
    for name in ("package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml"):
        (work / "website" / name).write_text("baseline\n")
    git("add", ".")
    git("commit", "-m", "baseline")
    git("push", "origin", "main")
    binary = tmp_path / "bin"
    binary.mkdir()
    gh = binary / "gh"
    gh.write_text(
        f"#!{sys.executable}\n"
        "import json, os, sys\nfrom pathlib import Path\n"
        "args = sys.argv[1:]\n"
        "state = Path(os.environ['PR_STATE'])\n"
        "with open(os.environ['COMMAND_LOG'], 'a') as f: f.write(json.dumps(args) + '\\n')\n"
        "if args[:2] == ['pr', 'list']: print('42' if state.exists() else '')\n"
        "elif args[:2] == ['pr', 'view']: print(state.with_suffix('.md').read_text() if 'body' in args else state.with_suffix('.title').read_text() if 'title' in args else os.environ['EXISTING_BASE'] if 'baseRefName' in args else 'false')\n"
        "elif args[:2] in (['pr', 'create'], ['pr', 'edit']):\n"
        "    state.write_text('42')\n"
        "    state.with_suffix('.title').write_text(args[args.index('--title') + 1])\n"
        "    if '--body-file' in args: state.with_suffix('.md').write_text(Path(args[args.index('--body-file') + 1]).read_text())\n"
    )
    gh.chmod(0o755)
    log = tmp_path / "commands"
    env = {
        **os.environ,
        "PATH": str(binary) + os.pathsep + os.environ["PATH"],
        "PR_STATE": str(tmp_path / "pr-state"),
        "COMMAND_LOG": str(log),
        "NPM_PROJECT": "website",
        "BASE_BRANCH": "main",
        "PR_BRANCH": "maintenance/dependency-audit",
        "VALIDATION_PASSED": "true",
        "RUNNER_TEMP": str(tmp_path),
        "PR_FOOTER": "workflow",
    }

    iteration = 0

    def publish(version, passed=True, report="Latest report"):
        nonlocal iteration
        iteration += 1
        git("reset", "--hard", "origin/main")
        git("checkout", "-B", "audit-input", "origin/main")
        (work / "website/pnpm-lock.yaml").write_text(version + "\n")
        (tmp_path / "dependency-audit-pr.md").write_text(
            "**9 routine dependency updates · Validation passed**\n\n"
            + report
            + f"\nRun: 2026-10-17T12:00:{iteration:02d}Z\n"
        )
        result = subprocess.run(
            ["bash", "-e", "-c", PUBLISH["run"]],
            cwd=work,
            env={
                **env,
                "VALIDATION_PASSED": str(passed).lower(),
                "EXISTING_BASE": "old-main" if changed_base else "main",
                "PR_FOOTER": f"[Workflow run](https://example.com/runs/{iteration})",
            },
            capture_output=True,
            text=True,
        )
        assert result.returncode == (0 if passed else 1), result.stderr
        return git("rev-parse", "refs/remotes/origin/maintenance/dependency-audit")

    first = publish("candidate-1")
    if changed_title:
        (tmp_path / "pr-state.title").write_text("Outdated generic title")
    assert (
        publish(
            "candidate-1",
            passed=not failed_replay,
            report="New advisory found" if changed_report else "Latest report",
        )
        == first
    )  # No new commit for the same proposal.
    assert publish("candidate-2") != first
    commands = [json.loads(line) for line in log.read_text().splitlines()]
    assert len([c for c in commands if c[:2] == ["pr", "create"]]) == 1
    edits = [c for c in commands if c[:2] == ["pr", "edit"]]
    assert len(edits) == 1 + (
        failed_replay or changed_base or changed_report or changed_title
    )
    assert all(edit[2] == "42" for edit in edits)
    assert all(
        edit[edit.index("--base") + 1] == "main" for edit in edits if "--base" in edit
    )
    title_only_edits = [edit for edit in edits if "--body-file" not in edit]
    assert len(title_only_edits) == int(
        changed_title and not (failed_replay or changed_base or changed_report)
    )
    writes = [c for c in commands if c[:2] in (["pr", "create"], ["pr", "edit"])]
    assert all(
        command[command.index("--title") + 1]
        == "Node: 9 routine dependency updates, no security fixes"
        for command in writes
    )
    assert all(
        "--base" not in command for command in commands if command[:2] == ["pr", "list"]
    )
    assert len([c for c in commands if c[:2] == ["pr", "ready"]]) == int(failed_replay)


@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize("changes", [False, True])
@pytest.mark.parametrize("passed", [False, True])
@pytest.mark.parametrize("draft", [False, True])
@pytest.mark.parametrize("failure", [None, "view", "draft", "edit"])
def test_publication_preserves_reports_and_signals_failed_validation(
    tmp_path, existing, changes, passed, draft, failure
):
    cli = tmp_path / "mock-cli"
    cli.write_text(
        f"#!{sys.executable}\n"
        "import json, os, sys\n"
        "from pathlib import Path\n"
        "tool, args = Path(sys.argv[0]).name, sys.argv[1:]\n"
        "with open(os.environ['COMMAND_LOG'], 'a') as log:\n"
        "    log.write(json.dumps([tool, *args]) + '\\n')\n"
        "if tool == 'git' and args[0] == 'rev-parse':\n"
        "    sys.exit(1)\n"
        "if tool == 'git' and args[0] == 'diff':\n"
        "    sys.exit(int(os.environ['HAS_CHANGES']))\n"
        "if tool == 'gh' and args[:2] == ['pr', 'list']:\n"
        "    print(os.environ['PR_NUMBER'])\n"
        "if tool == 'gh' and args[:2] == ['pr', 'view']:\n"
        "    if os.environ['API_FAILURE'] == 'view': sys.exit(1)\n"
        "    print(os.environ['IS_DRAFT'])\n"
        "if tool == 'gh' and args[:2] == ['pr', 'ready']:\n"
        "    if os.environ['API_FAILURE'] == 'draft': sys.exit(1)\n"
        "if tool == 'gh' and args[:2] == ['pr', 'edit']:\n"
        "    if os.environ['API_FAILURE'] == 'edit': sys.exit(1)\n"
    )
    cli.chmod(0o755)
    for tool in ("git", "gh"):
        (tmp_path / tool).symlink_to(cli)
    project = tmp_path / "website"
    project.mkdir()
    for filename in ("package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml"):
        (project / filename).write_text("{}")
    report = "## Production build\n\nFailed; manual repair required.\n"
    (tmp_path / "dependency-audit-pr.md").write_text(report)
    command_log = tmp_path / "commands.jsonl"
    result = subprocess.run(
        ["bash", "-c", PUBLISH["run"]],
        cwd=tmp_path,
        env={
            **os.environ,
            **PUBLISH["env"],
            "PROPOSAL_KIND": "legacy",
            "REFRESH_ONLY": "false",
            "PATH": f"{tmp_path}:{os.environ['PATH']}",
            "NPM_PROJECT": "website",
            "BASE_BRANCH": "main",
            "RUNNER_TEMP": str(tmp_path),
            "COMMAND_LOG": str(command_log),
            "HAS_CHANGES": str(int(changes)),
            "PR_NUMBER": "42" if existing else "",
            "VALIDATION_PASSED": str(passed).lower(),
            "IS_DRAFT": str(draft).lower(),
            "API_FAILURE": failure or "",
        },
        capture_output=True,
        text=True,
    )
    inspect_draft = existing and changes and not passed
    view_failed = inspect_draft and failure == "view"
    convert_draft = inspect_draft and not draft and not view_failed
    draft_failed = convert_draft and failure == "draft"
    blocked = view_failed or draft_failed
    edit_failed = existing and changes and not blocked and failure == "edit"
    assert result.returncode == (1 if not passed or blocked or edit_failed else 0), (
        result.stderr
    )
    commands = [json.loads(line) for line in command_log.read_text().splitlines()]
    commits = [command for command in commands if command[:2] == ["git", "commit"]]
    assert commits == (
        [
            [
                "git",
                "commit",
                "-m",
                "Node dependency audit and upgrades",
            ]
        ]
        if changes and not blocked
        else []
    )
    writes = [
        command
        for command in commands
        if command[:2] == ["gh", "pr"] and command[2] in ("create", "edit")
    ]
    assert len(writes) == int(changes and not blocked)
    if writes:
        assert writes[0][2] == ("edit" if existing else "create")
        assert ("--draft" in writes[0]) == (not existing and not passed)
        assert writes[0][writes[0].index("--title") + 1] == (
            "Node: dependency updates, security fixes unconfirmed"
        )
    assert (tmp_path / "dependency-audit-pr.md").read_text().startswith(report)
    draft_commands = [
        command for command in commands if command[:3] == ["gh", "pr", "ready"]
    ]
    assert draft_commands == (
        [["gh", "pr", "ready", "42", "--undo"]] if convert_draft else []
    )
    inspections = [
        command for command in commands if command[:3] == ["gh", "pr", "view"]
    ]
    assert len(inspections) == int(inspect_draft)
    pushes = [command for command in commands if command[:2] == ["git", "push"]]
    assert len(pushes) == int(changes and not blocked)
    if pushes and draft_commands:
        assert commands.index(draft_commands[0]) < commands.index(pushes[0])
