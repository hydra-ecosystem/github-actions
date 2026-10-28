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
        "permission-actions": "read",
        "permission-checks": "read",
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


def test_publication_rejects_oversized_final_body_before_push(tmp_path):
    cli = tmp_path / "mock-cli"
    cli.write_text(
        f"#!{sys.executable}\n"
        "import os, sys\n"
        "from pathlib import Path\n"
        "tool, args = Path(sys.argv[0]).name, sys.argv[1:]\n"
        "with open(os.environ['COMMAND_LOG'], 'a') as log: log.write(tool + ' ' + ' '.join(args) + '\\n')\n"
        "if tool == 'git' and args[0] == 'rev-parse': sys.exit(1)\n"
        "if tool == 'git' and args[0] == 'diff': sys.exit(int(os.environ['HAS_CHANGES']))\n"
        "if tool == 'gh' and args[:2] == ['pr', 'list']: print('')\n"
        "if tool == 'gh' and args[:2] == ['pr', 'create']:\n"
        "    body = Path(args[args.index('--body-file') + 1]).read_text()\n"
        "    sys.exit(42 if len(body) > 65536 else 0)\n"
    )
    cli.chmod(0o755)
    for tool in ("git", "gh"):
        (tmp_path / tool).symlink_to(cli)
    project = tmp_path / "website"
    project.mkdir()
    (project / "package.json").write_text("{}\n")
    (project / "package-lock.json").write_text("{}\n")
    report = tmp_path / "dependency-audit-pr.md"
    report.write_text(
        "**9 dependency updates · 1 security fix · Validation passed**\n\n"
        + "x" * 65520
    )
    log = tmp_path / "commands"
    result = subprocess.run(
        ["bash", "-c", PUBLISH["run"]],
        cwd=tmp_path,
        env={
            **os.environ,
            **PUBLISH["env"],
            "PROPOSAL_KIND": "legacy",
            "NPM_PROJECT": "website",
            "BASE_BRANCH": "main",
            "PR_BRANCH": "maintenance/dependency-audit",
            "VALIDATION_PASSED": "true",
            "RUNNER_TEMP": str(tmp_path),
            "COMMAND_LOG": str(log),
            "HAS_CHANGES": "1",
            "PR_FOOTER": "footer",
            "PATH": f"{tmp_path}:{os.environ['PATH']}",
        },
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0, result.stdout
    commands = log.read_text().splitlines()
    assert not any(command.startswith("git push ") for command in commands)
    assert not any(command.startswith("gh pr create ") for command in commands)
    assert "65536" in result.stderr


def test_publisher_size_block_isolated_from_checkout_python_modules(
    tmp_path, monkeypatch
):
    import shlex

    marker = tmp_path / "shadowed"
    (tmp_path / "pathlib.py").write_text(
        "import os\n"
        "Path = type('Path', (), {'__init__': lambda self, _: None})\n"
        "open(os.environ['SHADOW_MARKER'], 'w').write(os.environ['GH_TOKEN'])\n"
        "raise SystemExit(73)\n"
    )
    body = tmp_path / "body.md"
    body.write_text("small body\n")
    marker_text = "python3 -I - \"$body_file\" <<'PY'\n"
    assert marker_text in PUBLISH["run"]
    python_body = PUBLISH["run"].split(marker_text, 1)[1].split("\nPY\n", 1)[0]
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    monkeypatch.setenv("GH_TOKEN", "dummy-publisher-token")
    monkeypatch.setenv("SHADOW_MARKER", str(marker))
    environment = os.environ.copy()

    def invoke(flag):
        return subprocess.run(
            [
                "bash",
                "-c",
                "body_file="
                + shlex.quote(str(body))
                + "\npython3 "
                + flag
                + " - \"$body_file\" <<'PY'\n"
                + python_body
                + "\nPY\n",
            ],
            cwd=tmp_path,
            env=environment,
            capture_output=True,
            text=True,
        )

    control = invoke("")
    assert control.returncode == 73
    assert marker.read_text() == "dummy-publisher-token"
    marker.unlink()
    isolated = invoke("-I")
    assert isolated.returncode == 0, isolated.stderr
    assert not marker.exists()


@pytest.fixture
def sealed_history(tmp_path, monkeypatch):
    import base64
    import hashlib
    import io
    import runpy
    import zipfile
    from pathlib import Path

    engine = runpy.run_path(
        str(Path(__file__).parents[1] / "runtime/templates/dependency_audit.py")
    )
    record = dict(
        version=1,
        repository="owner/repo",
        source="a" * 40,
        project="app",
        candidate_state={"package.json": "b" * 64},
        before_state={"package.json": "c" * 64},
        manager="pnpm",
        node="24.22.1",
        manager_version="11.21.0",
        validation_script="build",
        before={"original": "CVE-2026-12345"},
        after={},
        package_report="Original row",
        fixed_ids=["GHSA-aaaa-bbbb-cccc"],
        initial_ids=["GHSA-aaaa-bbbb-cccc"],
        remaining_ids=[],
    )
    report = (
        b"Report\n<!-- node-audit-history:v1:"
        + base64.b64encode(engine["canonical_history"](record))
        + b" -->\n"
    )
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as bundle:
        bundle.writestr("dependency-audit-pr.md", report)
    archive = stream.getvalue()
    locator = dict(
        run=10,
        job=20,
        check=30,
        artifact=40,
        archive_sha256=hashlib.sha256(archive).hexdigest(),
        content_sha256=hashlib.sha256(report).hexdigest(),
    )
    job_name = "security / Node audit evidence (node-security)"
    check_url = "https://api.github.com/repos/owner/repo/check-runs/30"
    job = dict(
        id=20,
        run_id=10,
        head_sha="a" * 40,
        run_attempt=1,
        name=job_name,
        check_run_url=check_url,
        status="completed",
        conclusion="success",
        html_url="job-url",
        steps=[
            dict(name=name, conclusion="success")
            for name in [
                "Prepare and seal audit evidence",
                "Seal uploaded audit evidence",
            ]
        ],
    )
    data = {
        "actions/runs/10": dict(
            repository={"full_name": "owner/repo"},
            head_sha="a" * 40,
            event="workflow_dispatch",
            run_attempt=1,
            referenced_workflows=[
                dict(
                    path="hydra-ecosystem/github-actions/.github/workflows/node-audit.yml@tag",
                    sha="d" * 40,
                )
            ],
        ),
        "actions/jobs/20": job,
        "actions/runs/10/attempts/1/jobs?per_page=100": dict(total_count=1, jobs=[job]),
        "check-runs/30": dict(
            id=30,
            head_sha="a" * 40,
            app={"id": 15368},
            details_url="job-url",
            output={"annotations_count": 1},
        ),
        "check-runs/30/annotations?per_page=100": [
            dict(
                title=engine["HISTORY_TITLE"],
                annotation_level="notice",
                message=f"v1:40:{locator['archive_sha256']}:{locator['content_sha256']}",
            )
        ],
        "actions/artifacts/40": dict(
            id=40,
            expired=False,
            size_in_bytes=len(archive),
            digest="sha256:" + locator["archive_sha256"],
            workflow_run={"id": 10, "head_sha": "a" * 40},
        ),
        "actions/artifacts/40/zip": archive,
    }

    def api(repository, suffix, **_):
        assert repository == "owner/repo"
        return data[suffix]

    monkeypatch.setitem(engine["verify_history"].__globals__, "history_api", api)
    arguments = dict(
        repository="owner/repo",
        source="a" * 40,
        project="app",
        candidate_state=record["candidate_state"],
        trusted_workflow_sha="d" * 40,
        expected_job_name=job_name,
    )
    return engine, record, report, locator, data, arguments


def test_sealed_history_retains_original_cve_rows_and_exact_artifact(sealed_history):
    engine, record, report, locator, _, arguments = sealed_history
    assert engine["history_record"](report) == record
    assert engine["verify_history"](locator, **arguments) == record


def test_history_binds_trigger_and_planned_checkout_separately(sealed_history):
    engine, record, _, locator, data, arguments = sealed_history
    data["actions/runs/10"]["head_sha"] = "b" * 40
    data["actions/jobs/20"]["head_sha"] = "b" * 40
    data["check-runs/30"]["head_sha"] = "b" * 40
    data["actions/artifacts/40"]["workflow_run"]["head_sha"] = "b" * 40
    assert engine["verify_history"](locator, **arguments) == record


@pytest.mark.parametrize("mismatch", ["job", "check", "artifact", "checkout", "run"])
def test_history_rejects_mismatched_trigger_or_checkout(sealed_history, mismatch):
    engine, _, _, locator, data, arguments = sealed_history
    data["actions/runs/10"]["head_sha"] = "b" * 40
    data["actions/jobs/20"]["head_sha"] = "b" * 40
    data["check-runs/30"]["head_sha"] = "b" * 40
    data["actions/artifacts/40"]["workflow_run"]["head_sha"] = "b" * 40
    if mismatch == "job":
        data["actions/jobs/20"]["head_sha"] = arguments["source"]
    elif mismatch == "check":
        data["check-runs/30"]["head_sha"] = arguments["source"]
    elif mismatch == "artifact":
        data["actions/artifacts/40"]["workflow_run"]["head_sha"] = arguments["source"]
    elif mismatch == "checkout":
        arguments["source"] = "c" * 40
    else:
        data["actions/runs/10"]["head_sha"] = "not-a-revision"
    with pytest.raises(ValueError):
        engine["verify_history"](locator, **arguments)


def test_locate_history_omits_opaque_record_from_human_report(
    sealed_history, tmp_path, monkeypatch
):
    import hashlib
    from pathlib import Path

    engine, record, sealed, locator, _, _ = sealed_history
    project = tmp_path / "app"
    project.mkdir()
    (project / "package.json").write_text('{"name":"app"}\n')
    (project / "package-lock.json").write_text('{"lockfileVersion":3}\n')
    canonical = sealed[sealed.index(b"<!--") :]
    original = (
        "**1 dependency update · 1 security fix · Validation pending**\n\n".encode()
        + b"## Validation\n\n- Project checks: Pending.\n\n"
        + canonical
    )
    report = tmp_path / "dependency-audit-pr.md"
    report.write_bytes(original)
    envfile = tmp_path / "environment"
    published_locator = dict(
        locator, content_sha256=hashlib.sha256(original).hexdigest()
    )
    located = []

    def locate(actual, directory, **kwargs):
        located.append((actual, directory, kwargs))
        return published_locator

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("VALIDATION_PASSED", "true")
    monkeypatch.setitem(engine["main"].__globals__, "locate_current_history", locate)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "dependency_audit.py",
            "--directory",
            "app",
            "--report",
            str(report),
            "--locate-history",
            "--trusted-workflow-sha",
            "d" * 40,
            "--artifact-prefix",
            "node-security",
            "--github-env",
            str(envfile),
        ],
    )
    engine["main"]()

    assert located == [
        (
            original,
            Path("app"),
            {"trusted_workflow_sha": "d" * 40, "prefix": "node-security"},
        )
    ]
    assert engine["history_record"](original) == record
    assert hashlib.sha256(original).hexdigest() == published_locator["content_sha256"]
    human = report.read_text()
    assert "node-audit-history:v1:" not in human
    assert "## Validation" in human and "Project checks: Pending." in human
    assert "Node-Audit-content-sha256: " + published_locator["content_sha256"] in (
        envfile.read_text()
    )


@pytest.mark.parametrize(
    "case",
    [
        "sibling-job",
        "forged-check",
        "unrelated-app",
        "duplicate-notice",
        "wrong-notice",
        "failed-seal",
        "wrong-workflow",
        "wrong-head",
        "wrong-project",
        "wrong-state",
        "expired",
        "missing-digest",
        "altered-archive",
        "oversized",
        "ambiguous-job",
        "old-attempt",
    ],
)
def test_history_rejects_forged_or_unavailable_evidence(sealed_history, case):
    engine, _, _, locator, data, arguments = sealed_history
    if case == "sibling-job":
        data["actions/jobs/20"]["check_run_url"] = (
            "https://api.github.com/repos/owner/repo/check-runs/31"
        )
    elif case == "forged-check":
        locator["check"] = 31
    elif case == "unrelated-app":
        data["check-runs/30"]["app"]["id"] = 999
    elif case == "duplicate-notice":
        data["check-runs/30/annotations?per_page=100"] *= 2
    elif case == "wrong-notice":
        data["check-runs/30/annotations?per_page=100"][0]["message"] = (
            "v1:41:" + "a" * 129
        )
    elif case == "failed-seal":
        data["actions/jobs/20"]["steps"][-1]["conclusion"] = "failure"
    elif case == "wrong-workflow":
        data["actions/runs/10"]["referenced_workflows"][0]["sha"] = "e" * 40
    elif case == "wrong-head":
        data["actions/jobs/20"]["head_sha"] = "e" * 40
    elif case == "wrong-project":
        arguments["project"] = "other"
    elif case == "wrong-state":
        arguments["candidate_state"] = {}
    elif case == "expired":
        data["actions/artifacts/40"]["expired"] = True
    elif case == "missing-digest":
        data["actions/artifacts/40"].pop("digest")
    elif case == "altered-archive":
        data["actions/artifacts/40/zip"] += b"x"
    elif case == "oversized":
        data["actions/artifacts/40"]["size_in_bytes"] = 8388609
    elif case == "ambiguous-job":
        data["actions/runs/10/attempts/1/jobs?per_page=100"]["jobs"] *= 2
    elif case == "old-attempt":
        data["actions/jobs/20"]["run_attempt"] = 2
    with pytest.raises(ValueError):
        engine["verify_history"](locator, **arguments)


@pytest.mark.parametrize(
    "change", ["duplicate", "unknown-version", "oversized", "malformed"]
)
def test_sealed_history_rejects_ambiguous_records(sealed_history, change):
    engine, _, report, _, _, _ = sealed_history
    if change == "duplicate":
        report *= 2
    elif change == "unknown-version":
        report = report.replace(b"node-audit-history:v1:", b"node-audit-history:v2:")
    elif change == "oversized":
        report = b"x" * 1048577
    else:
        report = b"<!-- node-audit-history:v1:==== -->"
    with pytest.raises(ValueError):
        engine["history_record"](report)


@pytest.mark.parametrize("validate_only", [False, True])
def test_producer_never_installs_or_runs_project_checks(
    tmp_path, monkeypatch, validate_only
):
    import runpy
    from pathlib import Path
    from test_dependency_audit import fake_npm, npm_project

    project = tmp_path / "app"
    project.mkdir()
    npm_project.__wrapped__(project)
    commands = fake_npm(monkeypatch)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("NODE_AUDIT_NODE_VERSION", "24.22.1")
    monkeypatch.setenv("NODE_AUDIT_MANAGER_VERSION", "11.9.0")
    monkeypatch.setattr(subprocess, "check_output", lambda *a, **kw: "a" * 40 + "\n")
    engine = runpy.run_path(
        str(Path(__file__).parents[1] / "runtime/templates/dependency_audit.py")
    )
    report = engine["prepare"](
        Path("app"),
        prepare_only=True,
        maintenance_mode="security-only",
        validate_only=validate_only,
    )
    assert not any(command[0] in {"ci", "run"} for command in commands)
    assert all(
        "--lockfile-only" in command or "--package-lock-only" in command
        for command in commands
        if command[0] == "install"
    )
    record = engine["history_record"](report.encode())
    assert record["repository"] == "owner/repo"
    assert record["source"] == "a" * 40
    assert record["before"]["vulnerabilities"]["transitive"]["severity"] == "high"
    assert (
        "Committed dependency validation · Pending"
        if validate_only
        else "Validation pending"
    ) in report.splitlines()[0]


def test_current_publisher_resolves_only_expected_producer(sealed_history, monkeypatch):
    from pathlib import Path

    engine, record, report, locator, data, _ = sealed_history
    original = data["actions/jobs/20"]
    sibling = dict(
        original,
        id=21,
        name="Project validation",
        check_run_url="https://api.github.com/repos/owner/repo/check-runs/31",
    )
    data["actions/runs/10/jobs?per_page=100"] = dict(
        total_count=2, jobs=[original, sibling]
    )
    data["check-runs/31/annotations?per_page=100"] = data[
        "check-runs/30/annotations?per_page=100"
    ]
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("GITHUB_RUN_ID", "10")
    monkeypatch.setitem(
        engine["locate_current_history"].__globals__,
        "check_prepared_history",
        lambda actual, _: record if actual == report else None,
    )
    assert (
        engine["locate_current_history"](
            report, Path("app"), trusted_workflow_sha="d" * 40, prefix="node-security"
        )
        == locator
    )
    data["check-runs/30/annotations?per_page=100"] = []
    with pytest.raises(ValueError, match="unique artifact seal"):
        engine["locate_current_history"](
            report, Path("app"), trusted_workflow_sha="d" * 40, prefix="node-security"
        )
    sibling["name"] = original["name"]
    with pytest.raises(ValueError, match="ambiguous expected producer"):
        engine["locate_current_history"](
            report, Path("app"), trusted_workflow_sha="d" * 40, prefix="node-security"
        )


def test_producer_and_validation_keep_separate_permissions_and_artifacts():
    import yaml
    from pathlib import Path

    value = yaml.safe_load(
        (Path(__file__).parents[2] / ".github/workflows/node-audit.yml").read_text()
    )
    producer, validation = value["jobs"]["audit"], value["jobs"]["validation"]
    assert producer["permissions"] == validation["permissions"] == {"contents": "read"}
    for namespace in ["npm", "pnpm"]:
        for setting in ["ignore_scripts", "ignore_pnpmfile", "lockfile_only"]:
            assert producer["env"][namespace + "_config_" + setting] == "true"
    assert "env" not in validation
    assert validation["needs"] == "audit"
    checks = next(
        step for step in validation["steps"] if step.get("id") == "validation"
    )
    assert checks["continue-on-error"] == "${{ inputs.operation != 'validate' }}"
    downloads = [
        step["with"]
        for step in validation["steps"]
        if step.get("uses", "").startswith("actions/download-artifact@")
    ]
    assert [step["artifact-ids"] for step in downloads] == [
        "${{ needs.audit.outputs.dependencies_artifact_id }}",
        "${{ needs.audit.outputs.node_update_artifact_id }},${{ needs.audit.outputs.report_artifact_id }}",
    ]
    assert "node_update_artifact_id" in producer["outputs"]
    assert "history-seal" not in value["on"]["workflow_call"]["inputs"]


@pytest.fixture(params=["npm", "pnpm"])
def prepared_validation(request, sealed_history, tmp_path, monkeypatch):
    import base64
    from pathlib import Path

    engine, original, *_ = sealed_history
    project = tmp_path / "app"
    project.mkdir()
    selected = request.param
    version = "11.21.0" if selected == "pnpm" else "11.9.0"
    (project / "package.json").write_text(
        json.dumps(
            {"packageManager": f"{selected}@{version}", "scripts": {"build": "true"}}
        )
    )
    if selected == "pnpm":
        (project / "pnpm-lock.yaml").write_text(
            "lockfileVersion: '9.0'\nimporters:\n  .: {}\npackages: {}\n"
        )
        (project / "pnpm-workspace.yaml").write_text("packages: ['.']\n")
    else:
        (project / "package-lock.json").write_text('{"lockfileVersion": 3}\n')
    monkeypatch.chdir(tmp_path)
    for args in [
        ["init", "-q"],
        ["add", "app"],
        [
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.org",
            "commit",
            "-qm",
            "base",
        ],
    ]:
        subprocess.run(["git", *args], check=True, cwd=tmp_path)
    record = dict(
        original,
        manager=selected,
        manager_version=version,
        candidate_state=engine["dependency_state"](engine["valid_snapshot"](project)),
        source=subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
    )
    report = tmp_path / "dependency-audit-pr.md"

    def seal():
        report.write_bytes(
            b"Report\n<!-- node-audit-history:v1:"
            + base64.b64encode(engine["canonical_history"](record))
            + b" -->\n"
        )

    seal()
    binary = tmp_path / "bin"
    binary.mkdir()
    log = tmp_path / "commands.jsonl"
    stub = (
        f"#!{sys.executable}\n"
        "import json, os, sys\nfrom pathlib import Path\n"
        "name = Path(sys.argv[0]).name\nargs = sys.argv[1:]\n"
        "with open(os.environ['COMMAND_LOG'], 'a') as f:\n"
        " f.write(json.dumps([name, *args]) + '\\n')\n"
        "if name == 'npm' and args[:2] == ['install', '--global'] and os.environ.get('npm_config_package_lock_only') == 'true':\n"
        " sys.exit(17)\n"
        "if args[-1:] == ['--version']:\n"
        " print(os.environ['TEST_NODE'] if name == 'node' else os.environ['TEST_MANAGER'])\n"
        " if name != 'node': sys.exit(int(os.environ.get('TEST_MANAGER_EXIT', '0')))\n"
        "elif 'audit' in args:\n"
        " print(json.dumps({'advisories': {}, 'vulnerabilities': {}, 'metadata': {'vulnerabilities': {'total': 0}}}))\n"
    )
    for name in ["node", "npm", "corepack"]:
        executable = binary / name
        executable.write_text(stub)
        executable.chmod(0o755)
    monkeypatch.setenv("PATH", str(binary) + os.pathsep + os.environ["PATH"])
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("COMMAND_LOG", str(log))
    monkeypatch.setenv("TEST_NODE", "v24.22.1")
    monkeypatch.setenv("TEST_MANAGER", version)
    output = tmp_path / "outputs"
    envfile = tmp_path / "environment"
    command = [
        sys.executable,
        str(Path(__file__).parents[1] / "runtime/templates/dependency_audit.py"),
        "--directory",
        "app",
        "--report",
        str(report),
        "--check-prepared",
    ]
    return command, record, seal, report, envfile, output, log, selected, version


def test_prepared_toolchain_export_and_validation_run_real_cli(prepared_validation):
    command, record, _, report, envfile, output, log, selected, version = (
        prepared_validation
    )
    before = report.read_bytes()
    result = subprocess.run(
        command + ["--github-env", str(envfile)], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr
    values = dict(line.split("=", 1) for line in envfile.read_text().splitlines())
    assert values == {
        "NODE_AUDIT_NODE_VERSION": record["node"],
        "NODE_AUDIT_MANAGER": selected,
        "NODE_AUDIT_MANAGER_VERSION": version,
    }
    assert report.read_bytes() == before
    assert not log.exists(), (
        "Configuration export must not run project or manager commands"
    )
    import yaml
    from pathlib import Path

    steps = yaml.safe_load(
        (Path(__file__).parents[1] / "audit/action.yml").read_text()
    )["runs"]["steps"]
    export = next(
        step
        for step in steps
        if "--check-prepared" in step.get("run", "")
        and "--github-env" in step.get("run", "")
    )
    setup_index = next(
        i
        for i, step in enumerate(steps)
        if step.get("uses", "").startswith("actions/setup-node@")
    )
    assert steps.index(export) < setup_index
    setup = next(
        step
        for step in steps
        if step.get("name") == "Enable the project's pinned package manager"
    )
    assert setup["env"]["npm_config_package_lock_only"] == "false"
    setup_env = {
        **os.environ,
        **setup["env"],
        "PACKAGE_MANAGER": selected,
        "PACKAGE_MANAGER_VERSION": version,
        "npm_config_package_lock_only": "false",
    }
    subprocess.run(
        ["bash", "-c", setup["run"]],
        check=True,
        env=setup_env,
    )
    result = subprocess.run(
        command + ["--github-output", str(output)], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr
    assert output.read_text() == "validation_passed=true\n"
    commands = [json.loads(line) for line in log.read_text().splitlines()]
    assert commands[0] == (
        ["corepack", "enable"]
        if selected == "pnpm"
        else [
            "npm",
            "install",
            "--global",
            f"npm@{version}",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
        ]
    )
    assert ["node", "--version"] in commands
    assert (
        ["corepack", "pnpm", "--version"]
        if selected == "pnpm"
        else ["npm", "--version"]
    ) in commands


@pytest.mark.parametrize(
    "mutation",
    [
        "node",
        "manager",
        "manager-failure",
        "files",
        "source",
        "unsafe-version",
        "wrong-manager",
    ],
)
def test_prepared_validation_rejects_drift_before_project_commands(
    prepared_validation, monkeypatch, mutation
):
    command, record, seal, report, envfile, output, log, selected, _ = (
        prepared_validation
    )
    if mutation == "node":
        monkeypatch.setenv("TEST_NODE", "v24.23.0")
    elif mutation == "manager":
        monkeypatch.setenv("TEST_MANAGER", "99.0.0")
    elif mutation == "manager-failure":
        monkeypatch.setenv("TEST_MANAGER_EXIT", "1")
    elif mutation == "files":
        from pathlib import Path

        with Path("app/package.json").open("a") as file:
            file.write("\n")
    elif mutation == "source":
        record["source"] = "b" * 40
    elif mutation == "unsafe-version":
        record["manager_version"] = "11.9.0\nINJECTED=value"
    else:
        record["manager"] = "npm" if selected == "pnpm" else "pnpm"
    seal()
    before = report.read_bytes()
    export_only = mutation in {"files", "source", "unsafe-version", "wrong-manager"}
    args = (
        ["--github-env", str(envfile)]
        if export_only
        else ["--github-output", str(output)]
    )
    result = subprocess.run(command + args, capture_output=True, text=True)
    assert result.returncode != 0, result.stdout
    assert report.read_bytes() == before
    assert not envfile.exists() and not output.exists()
    commands = (
        [json.loads(line) for line in log.read_text().splitlines()]
        if log.exists()
        else []
    )
    assert all(command[-1:] == ["--version"] for command in commands)


def test_verified_producer_seals_concrete_node_version(tmp_path):
    import yaml
    from pathlib import Path

    steps = yaml.safe_load(
        (Path(__file__).parents[1] / "audit/action.yml").read_text()
    )["runs"]["steps"]
    verify = next(
        step
        for step in steps
        if step.get("name") == "Verify the declared toolchain before dependency changes"
    )
    binary = tmp_path / "bin"
    binary.mkdir()
    for name, content in {"python": "exit 0", "node": "echo v24.22.1"}.items():
        executable = binary / name
        executable.write_text("#!/bin/bash\n" + content + "\n")
        executable.chmod(0o755)
    envfile = tmp_path / "environment"
    subprocess.run(
        ["bash", "-c", verify["run"]],
        check=True,
        env={
            **os.environ,
            "PATH": str(binary) + os.pathsep + os.environ["PATH"],
            "NODE_AUDIT_NODE_VERSION": "24",
            "GITHUB_ACTION_PATH": str(tmp_path),
            "RUNNER_TEMP": str(tmp_path),
            "AUDIT_KIND": "security",
            "GITHUB_ENV": str(envfile),
        },
    )
    assert envfile.read_text() == "NODE_AUDIT_NODE_VERSION=24.22.1\n"


def test_prepared_validation_reconstructs_node_candidate_before_project_check(
    tmp_path, monkeypatch
):
    import base64
    import runpy
    from pathlib import Path

    engine = runpy.run_path(
        str(Path(__file__).parents[1] / "runtime/templates/dependency_audit.py")
    )
    project = tmp_path / "app"
    project.mkdir()
    (tmp_path / ".github").mkdir()
    (tmp_path / ".github/node-maintenance.json").write_text(
        json.dumps({"directory": "app", "toolchain": {"node": "project"}})
    )
    (project / "package.json").write_text(
        json.dumps({"packageManager": "pnpm@11.21.0", "scripts": {"build": "true"}})
    )
    (project / "pnpm-lock.yaml").write_text(
        "lockfileVersion: '9.0'\nimporters:\n  .: {}\npackages: {}\n"
    )
    (project / "pnpm-workspace.yaml").write_text("packages: ['.']\n")
    (project / ".nvmrc").write_text("24.13.0\n")
    monkeypatch.chdir(tmp_path)
    for args in [
        ["init", "-q"],
        ["add", "app"],
        [
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.org",
            "commit",
            "-qm",
            "base",
        ],
    ]:
        subprocess.run(["git", *args], check=True, cwd=tmp_path)
    record = {
        "version": 1,
        "repository": "owner/repo",
        "source": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True
        ).strip(),
        "project": "app",
        "candidate_state": engine["dependency_state"](
            engine["valid_snapshot"](project)
        ),
        "before_state": {"package.json": "c" * 64},
        "manager": "pnpm",
        "node": "24.22.1",
        "manager_version": "11.21.0",
        "validation_script": "build",
        "before": {"original": "CVE-2026-12345"},
        "after": {},
        "package_report": "Original row",
        "fixed_ids": ["GHSA-aaaa-bbbb-cccc"],
        "initial_ids": ["GHSA-aaaa-bbbb-cccc"],
        "remaining_ids": [],
    }
    report = tmp_path / "dependency-audit-pr.md"
    report.write_bytes(
        b"Report\n<!-- node-audit-history:v1:"
        + base64.b64encode(engine["canonical_history"](record))
        + b" -->\n"
    )
    plan = tmp_path / "node-audit-node-update.json"
    plan.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "directory": "app",
                "version": "24.14.0",
                "changes": [
                    {
                        "path": "app/.nvmrc",
                        "before": "24.13.0\n",
                        "after": "24.14.0\n",
                    }
                ],
                "message": "",
            }
        )
    )
    binary = tmp_path / "bin"
    binary.mkdir()
    (binary / "node").write_text("#!/bin/sh\nprintf 'v24.22.1\\n'\n")
    (binary / "corepack").write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, pathlib, sys\n"
        "args = sys.argv[1:]\n"
        "if args and args[0] == 'pnpm': args = args[1:]\n"
        "if args[-1:] == ['--version']: print('11.21.0')\n"
        "elif 'audit' in args: print(json.dumps({'advisories': {}, 'vulnerabilities': {}, 'metadata': {'vulnerabilities': {'total': 0}}}))\n"
        "elif args[:2] == ['run', 'build']:\n"
        "    if os.environ.get('MUTATE_NODE'): pathlib.Path('.nvmrc').write_text('24.13.0\\n')\n"
        "    raise SystemExit(0 if pathlib.Path('.nvmrc').read_text() == '24.14.0\\n' else 1)\n"
    )
    for name in ("node", "corepack"):
        (binary / name).chmod(0o755)
    monkeypatch.setenv("PATH", str(binary) + os.pathsep + os.environ["PATH"])
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    command = [
        str(Path(__file__).parents[1] / "runtime/templates/dependency_audit.py"),
        "--directory",
        "app",
        "--report",
        str(report),
        "--check-prepared",
        "--node-update",
        str(plan),
    ]
    namespace = engine["main"].__globals__
    original_run_path = namespace["runpy"].run_path

    def load_node_proposal(path, *args, **kwargs):
        loaded = original_run_path(path, *args, **kwargs)
        if str(path).endswith("node_proposal.py"):
            loaded["SECURITY"]["latest_security_release"] = lambda _: "24.14.0"
        return loaded

    monkeypatch.setattr(namespace["runpy"], "run_path", load_node_proposal)

    def invoke(*args):
        monkeypatch.setattr(sys, "argv", [*command, *args])
        namespace["main"]()

    envfile = tmp_path / "environment"
    invoke("--github-env", str(envfile))
    assert (project / ".nvmrc").read_text() == "24.14.0\n"
    sealed_report = report.read_bytes()
    output = tmp_path / "outputs"
    invoke("--github-output", str(output))
    assert output.read_text() == "validation_passed=true\n"
    report.write_bytes(sealed_report)
    output.unlink()
    monkeypatch.setenv("MUTATE_NODE", "1")
    with pytest.raises(
        ValueError, match="Project validation changed a proposed Node declaration"
    ):
        invoke("--github-output", str(output))
    assert not output.exists()


@pytest.mark.parametrize("declaration", [".nvmrc", ".node-version", "local-config"])
def test_node_candidate_reconstruction_covers_declaration_forms(tmp_path, declaration):
    import runpy
    from pathlib import Path

    proposal = runpy.run_path(
        str(Path(__file__).parents[1] / "runtime/node_proposal.py")
    )
    project = tmp_path / "app"
    project.mkdir()
    (tmp_path / ".github").mkdir()
    config = {"directory": "app", "toolchain": {"node": "project"}}
    if declaration == "local-config":
        config["toolchain"]["node"] = "24.13.0"
    else:
        (project / declaration).write_text("24.13.0\n")
    (tmp_path / ".github/node-maintenance.json").write_text(json.dumps(config))
    changes = proposal["declaration_changes"](tmp_path, project, "24.14.0")
    assert changes and changes[0]["path"] == (
        ".github/node-maintenance.json"
        if declaration == "local-config"
        else f"app/{declaration}"
    )
    plan = {"changes": changes}
    proposal["write_changes"](tmp_path, plan)
    proposal["verify_candidate"](tmp_path, plan)
