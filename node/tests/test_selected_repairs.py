"""Selection, sealed candidate, validation and guarded publication contracts."""

import copy
import json
import os
import runpy
import shlex
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

ROOT = Path(__file__).parents[2]
CHOICES = runpy.run_path(str(ROOT / "node/runtime/repair_choices.py"))
ENGINE = runpy.run_path(str(ROOT / "node/runtime/templates/dependency_audit.py"))
REPAIR = runpy.run_path(str(ROOT / "node/runtime/repair.py"))
FIXTURES = json.loads((ROOT / "repair-app/selection-fixtures.json").read_text())
ITEM = {"name": "launch-editor", "from": "2.14.1", "to": "2.14.2"}
REVISION = {"head": "a" * 40, "base": "b" * 40}


@pytest.fixture
def normal_publication(tmp_path):
    """Run the actual normal publisher against a native remote and PR state."""
    import shutil

    remote, work, binary = (
        tmp_path / "remote.git",
        tmp_path / "work",
        tmp_path / "bin",
    )

    def git(*args):
        return subprocess.check_output(
            ["git", *args], cwd=work if work.exists() else tmp_path, text=True
        ).strip()

    git("init", "--bare", "-q", str(remote))
    git("clone", "-q", str(remote), str(work))
    git("config", "user.name", "Fixture")
    git("config", "user.email", "fixture@example.com")
    git("checkout", "-qb", "main")
    project = work / "app"
    project.mkdir()
    (project / "package.json").write_text('{"name":"fixture"}\n')
    (project / "pnpm-lock.yaml").write_text("baseline\n")
    git("add", ".")
    git("commit", "-qm", "baseline")
    git("push", "-q", "origin", "main")
    base = git("rev-parse", "HEAD")
    binary.mkdir()
    commands = tmp_path / "commands.jsonl"
    state = tmp_path / "pr.json"
    state.write_text(json.dumps({"body": "Original report", "draft": False}))
    (binary / "gh").write_text(
        f"#!{sys.executable}\n"
        "import json, os, sys\nfrom pathlib import Path\n"
        "args=sys.argv[1:]\n"
        "with open(os.environ['COMMAND_LOG'],'a') as f: f.write(json.dumps(args)+'\\n')\n"
        "path=Path(os.environ['PR_STATE']); state=json.loads(path.read_text())\n"
        "if args[:2]==['pr','list']: print('1')\n"
        "elif args[:2]==['pr','view']:\n"
        " field=args[args.index('--json')+1]\n"
        " print({'state':'OPEN','isDraft':str(state['draft']).lower(),'body':state['body'],'baseRefName':'main','title':'Original title'}[field])\n"
        "else:\n"
        " state['mutated']=True\n"
        " if '--body-file' in args: state['body']=Path(args[args.index('--body-file')+1]).read_text()\n"
        " path.write_text(json.dumps(state))\n"
    )
    (binary / "gh").chmod(0o755)
    real_git = shutil.which("git")
    (binary / "git").write_text(
        f"#!{sys.executable}\nimport os,sys\n"
        "if sys.argv[1]=='log' and os.environ.get('FAIL_HISTORY')=='true': raise SystemExit(73)\n"
        f"os.execv({real_git!r},[{real_git!r},*sys.argv[1:]])\n"
    )
    (binary / "git").chmod(0o755)

    def publish(history, candidate="changed"):
        nonlocal base
        git("checkout", "-qb", "maintenance/node-security")
        (project / "pnpm-lock.yaml").write_text("selected repair\n")
        git("add", ".")
        trailer = (
            "Node-Repair: validated-selected-pins-v1"
            if history not in {"ordinary", "forged-body", "lookalike"}
            else "Node-Repair: validated-selected-pins-v10"
            if history == "lookalike"
            else ""
        )
        git("commit", "-qm", "Selected repair\n\n" + trailer)
        if history == "maintainer":
            (work / "maintainer.md").write_text("Keep this maintainer change\n")
            git("add", ".")
            git("commit", "-qm", "Later maintainer change")
        head = git("rev-parse", "HEAD")
        git("push", "-q", "origin", "maintenance/node-security")
        if history == "merged":
            git("checkout", "main")
            git("merge", "--ff-only", head)
            git("push", "-q", "origin", "main")
            base = head
        git("checkout", "--detach", base)
        if history == "missing-head":
            git("update-ref", "-d", "refs/remotes/origin/maintenance/node-security")
        if candidate != "unchanged":
            (project / "pnpm-lock.yaml").write_text("new normal candidate\n")
        if history == "stale-body":
            state.write_text(
                json.dumps({"body": "Stale pre-repair report", "draft": True})
            )
        elif history == "forged-body":
            state.write_text(
                json.dumps(
                    {"body": "Node-Repair: validated-selected-pins-v1", "draft": False}
                )
            )
        before = state.read_bytes()
        (tmp_path / "dependency-audit-pr.md").write_text("New normal report\n")
        result = subprocess.run(
            ["bash", str(ROOT / "node/publish/publish.sh")],
            cwd=work,
            env={
                **os.environ,
                "PATH": str(binary) + os.pathsep + os.environ["PATH"],
                "COMMAND_LOG": str(commands),
                "PR_STATE": str(state),
                "NPM_PROJECT": "app",
                "BASE_BRANCH": "main",
                "PROPOSAL_KIND": "security",
                "AUDIT_SHA": base,
                "VALIDATION_PASSED": str(candidate != "invalid").lower(),
                "PROPOSAL_COMPLETE": "true",
                "RUNNER_TEMP": str(tmp_path),
                "PR_FOOTER": "Normal audit run",
                "FAIL_HISTORY": str(history == "log-error").lower(),
            },
            capture_output=True,
            text=True,
        )
        calls = [json.loads(line) for line in commands.read_text().splitlines()]
        actual = git(
            "ls-remote", "origin", "refs/heads/maintenance/node-security"
        ).split()[0]
        return (
            result,
            head,
            actual,
            before,
            state.read_bytes(),
            calls,
            git("rev-parse", "HEAD"),
            base,
        )

    return publish


@pytest.mark.parametrize("history", ["repair", "maintainer", "stale-body"])
@pytest.mark.parametrize("candidate", ["changed", "unchanged", "invalid"])
def test_normal_audit_retains_unmerged_native_repair(
    normal_publication, history, candidate
):
    result, head, actual, before, after, calls, checkout, base = normal_publication(
        history, candidate
    )
    assert result.returncode == int(candidate == "invalid"), (
        result.stdout + result.stderr
    )
    assert actual == head
    assert before == after
    assert checkout == base
    assert all(call[:2] == ["pr", "list"] for call in calls)
    assert "unmerged validated repair" in result.stdout


@pytest.mark.parametrize("history", ["ordinary", "forged-body", "lookalike", "merged"])
def test_normal_audit_requires_unmerged_exact_native_repair(
    normal_publication, history
):
    result, head, actual, _, _, calls, _, _ = normal_publication(history)
    assert result.returncode == 0, result.stdout + result.stderr
    assert actual != head
    assert "unmerged validated repair" not in result.stdout
    assert any(call[:2] == ["pr", "edit"] for call in calls)


@pytest.mark.parametrize("history", ["missing-head", "log-error"])
def test_normal_audit_fails_closed_when_repair_history_unavailable(
    normal_publication, history
):
    result, head, actual, before, after, calls, checkout, base = normal_publication(
        history
    )
    assert result.returncode != 0
    assert actual == head
    assert before == after
    assert checkout == base
    assert all(call[:2] == ["pr", "list"] for call in calls)
    assert "Unable to inspect unmerged repair history" in result.stderr


@pytest.mark.parametrize("override", ["2.14.1", "2.14.2", "^2.14.1", None])
def test_security_candidate_cannot_bypass_retained_exact_direct_pin(tmp_path, override):
    manifest = {
        "packageManager": "pnpm@11.21.0",
        "dependencies": {"launch-editor": "^2.14.1"},
    }
    policy = {
        "packages": ["."],
        "overrides": {"launch-editor": override} if override else {},
    }
    lock = {
        "lockfileVersion": "9.0",
        "importers": {
            ".": {
                "dependencies": {
                    "launch-editor": {"specifier": "2.14.1", "version": "2.14.1"}
                }
            }
        },
        "packages": {"launch-editor@2.14.1": {}},
    }
    (tmp_path / "package.json").write_text(json.dumps(manifest))
    (tmp_path / "pnpm-workspace.yaml").write_text(yaml.safe_dump(policy))
    (tmp_path / "pnpm-lock.yaml").write_text(yaml.safe_dump(lock))
    original = ENGINE["valid_snapshot"](tmp_path)
    # Actual hosted pnpm audit --fix=update output: the preserved pin and
    # lockfile override remain 2.14.1, but the direct candidate becomes 2.14.2.
    manifest["dependencies"]["launch-editor"] = "2.14.2"
    lock["importers"]["."]["dependencies"]["launch-editor"] = {
        "specifier": "2.14.2",
        "version": "2.14.2",
    }
    lock["packages"] = {"launch-editor@2.14.2": {}}
    (tmp_path / "package.json").write_text(json.dumps(manifest))
    (tmp_path / "pnpm-lock.yaml").write_text(yaml.safe_dump(lock))
    notes = []
    rejected = ENGINE["restore_invalid_state"](
        tmp_path, original, notes, "Security fix", security_fix=True
    )
    assert rejected == (override == "2.14.1")
    if rejected:
        assert ENGINE["valid_snapshot"](tmp_path) == original
        assert "pin" in notes[0]
    else:
        assert (
            json.loads((tmp_path / "package.json").read_text())["dependencies"][
                "launch-editor"
            ]
            == "2.14.2"
        )


@pytest.mark.parametrize("case", FIXTURES["cases"], ids=lambda case: case["name"])
def test_shared_app_fixtures(case):
    if case.get("invalid"):
        with pytest.raises(ValueError):
            CHOICES["parse"](case["body"])
    else:
        result = CHOICES["parse"](case["body"])
        assert result == case["items"]
        assert (
            CHOICES["fingerprint"](FIXTURES["pr"]["number"], **REVISION, items=result)
            == case["fingerprint"]
        )


def test_render_is_exact_consent_and_needs_real_revision_context():
    body = CHOICES["render"]([ITEM], **REVISION)
    assert CHOICES["parse"](body) == []
    assert CHOICES["parse"](body.replace("[ ]", "[x]")) == [ITEM]
    assert body.count("<!-- node-repair:revision:v1 ") == 1
    assert CHOICES["revision_marker"](**REVISION) in body
    assert "/repair selected" in body and "**Comment**" in body
    assert "Checks →" not in body and "validation has not run" in body
    assert "one attempt" in body and "does not approve merging" in body
    with pytest.raises(TypeError):
        CHOICES["render"]([ITEM])
    for bad in ["main", "a" * 39, "A" * 40, "a" * 40 + "\n"]:
        with pytest.raises(ValueError):
            CHOICES["render"]([ITEM], head=bad, base=REVISION["base"])


def test_fingerprint_binds_all_consent_fields_and_canonical_key_order():
    fingerprint = CHOICES["fingerprint"](12, **REVISION, items=[ITEM])
    assert fingerprint == CHOICES["fingerprint"](
        12, **REVISION, items=[dict(reversed(list(ITEM.items())))]
    )
    assert fingerprint != CHOICES["fingerprint"](13, **REVISION, items=[ITEM])
    assert fingerprint != CHOICES["fingerprint"](
        12, head="c" * 40, base="b" * 40, items=[ITEM]
    )
    assert fingerprint != CHOICES["fingerprint"](
        12, head="a" * 40, base="c" * 40, items=[ITEM]
    )
    assert fingerprint != CHOICES["fingerprint"](
        12, **REVISION, items=[{**ITEM, "to": "2.14.3"}]
    )


def findings(candidate=True):
    detail = {
        "url": "https://github.com/advisories/GHSA-587h-7wmj-h5pm",
        "title": "Example advisory",
        "range": "<=2.14.1",
        "severity": "high",
        "nodes": ["launch-editor@2.14.1"],
        "patchedRange": ">=2.14.2",
        "fixStatus": "Published patch: `launch-editor@2.14.2`. Blocked by retained override `pnpm-workspace.yaml overrides.launch-editor` = `2.14.1`. Override preserved for manual compatibility review.",
    }
    if candidate:
        detail.update(
            _verifiedPatchedVersions=["2.14.2"],
            _verifiedRepairVersions=["2.14.2"],
            _repairFrom="2.14.1",
        )
    return {
        "package_manager": "pnpm",
        "metadata": {"vulnerabilities": {"high": 1}},
        "vulnerabilities": {"launch-editor": {"severity": "high", "via": [detail]}},
    }


def test_status_text_alone_does_not_establish_eligibility():
    data = findings(False)
    assert CHOICES["candidates"](data) == []
    data = findings()
    assert CHOICES["candidates"](data) == [ITEM]
    data["vulnerabilities"]["launch-editor"]["via"].append(
        {"_repairCandidate": {**ITEM, "to": "2.14.3"}}
    )
    assert CHOICES["candidates"](data) == []
    data["vulnerabilities"]["launch-editor"]["via"][-1] = {
        "fixStatus": "No patched version declared"
    }
    assert CHOICES["candidates"](data) == []
    assert CHOICES["candidates"]({**findings(), "package_manager": "npm"}) == []


def test_candidates_intersect_verified_sets_and_skip_older_minor():
    data = findings(False)
    details = data["vulnerabilities"]["launch-editor"]["via"]
    details[0].update(
        _verifiedPatchedVersions=["2.13.9", "2.14.2", "2.14.3"],
        _verifiedRepairVersions=["2.13.9", "2.14.2", "2.14.3"],
        _repairFrom="2.14.1",
    )
    details.append(
        {
            "_verifiedPatchedVersions": ["2.14.3", "2.15.0"],
            "_verifiedRepairVersions": ["2.14.3", "2.15.0"],
            "_repairFrom": "2.14.1",
        }
    )
    assert CHOICES["candidates"](data) == [
        {"name": "launch-editor", "from": "2.14.1", "to": "2.14.3"}
    ]


def test_candidates_compare_oversized_stable_components_without_integer_parsing():
    old = "1.2." + "9" * 5001
    new = "1.2." + "1" + "0" * 5002
    data = findings(False)
    data["vulnerabilities"]["launch-editor"]["via"][0].update(
        _verifiedPatchedVersions=[new],
        _verifiedRepairVersions=[new],
        _repairFrom=old,
    )
    assert CHOICES["candidates"](data) == [
        {"name": "launch-editor", "from": old, "to": new}
    ]


def test_describe_retains_common_same_minor_patch_across_advisories(
    monkeypatch, tmp_path
):
    data = findings(False)
    first = data["vulnerabilities"]["launch-editor"]["via"][0]
    first["patchedRange"] = "<2.14.0 || >=2.14.2"
    second = copy.deepcopy(first)
    second["patchedRange"] = ">=2.14.3"
    data["vulnerabilities"]["launch-editor"]["via"].append(second)
    files = {
        "pnpm-workspace.yaml": yaml.safe_dump(
            {"overrides": {"launch-editor": "2.14.1"}}
        ).encode(),
        "pnpm-lock.yaml": yaml.safe_dump(
            {
                "snapshots": {
                    "parent@1.0.0": {"dependencies": {"launch-editor": "2.14.1"}}
                }
            }
        ).encode(),
    }

    def run(directory, command, package, *fields, **kwargs):
        if package == "parent@1.0.0":
            value = {"dependencies": {"launch-editor": "^2.0.0"}}
        elif package.startswith("launch-editor@<2.14.0 || >=2.14.2"):
            value = ["2.13.9", "2.14.2", "2.14.3"]
        elif package.startswith("launch-editor@>=2.14.3"):
            value = ["2.14.3", "2.15.0"]
        elif package.startswith("launch-editor@^2.0.0 <2.14.0"):
            value = ["2.13.9"]
        elif package.startswith("launch-editor@^2.0.0 >=2.14.2"):
            value = ["2.14.2", "2.14.3"]
        elif package.startswith("launch-editor@^2.0.0 >=2.14.3"):
            value = ["2.14.3"]
        elif package.startswith("launch-editor@2.14.1 "):
            value = []
        else:
            raise AssertionError(package)
        return SimpleNamespace(returncode=0, stdout=json.dumps(value))

    fn = ENGINE["describe_pnpm_fixes"]
    monkeypatch.setitem(fn.__globals__, "run", run)
    monkeypatch.setitem(
        fn.__globals__, "valid_snapshot", lambda directory: (b"{}", files, {}, {})
    )
    monkeypatch.setitem(fn.__globals__, "restore_invalid_state", lambda *a, **k: False)
    fn(tmp_path, data, files, [], float("inf"), {})
    assert CHOICES["candidates"](data) == [
        {"name": "launch-editor", "from": "2.14.1", "to": "2.14.3"}
    ]


@pytest.mark.parametrize(
    "details",
    [
        [
            {
                "_verifiedPatchedVersions": ["2.14.2"],
                "_verifiedRepairVersions": ["2.14.2"],
                "_repairFrom": "2.14.1",
            },
            {
                "_verifiedPatchedVersions": ["2.15.0"],
                "_verifiedRepairVersions": ["2.15.0"],
                "_repairFrom": "2.14.1",
            },
        ],
        [
            {
                "_verifiedPatchedVersions": ["2.14.2"],
                "_repairFrom": "2.14.1",
            }
        ],
    ],
)
def test_candidates_withhold_unknown_or_empty_common_evidence(details):
    data = findings(False)
    data["vulnerabilities"]["launch-editor"]["via"] = details
    assert CHOICES["candidates"](data) == []


@pytest.mark.parametrize(
    "problem",
    [None, "unknown-parent", "blocked-parent", "qualified-override", "range-pin"],
)
def test_only_verified_compatible_exact_pins_receive_candidate_evidence(
    monkeypatch, tmp_path, problem
):
    fn = ENGINE["describe_pnpm_fixes"]
    module = fn.__globals__
    data = findings()
    policy = {
        "overrides": {
            "launch-editor": "^2.14.1" if problem == "range-pin" else "2.14.1"
        }
    }
    if problem == "qualified-override":
        policy["overrides"]["parent>launch-editor"] = "2.14.1"
    lock = {
        "snapshots": {"parent@1.0.0": {"dependencies": {"launch-editor": "2.14.1"}}}
    }
    files = {
        "pnpm-workspace.yaml": yaml.safe_dump(policy).encode(),
        "pnpm-lock.yaml": yaml.safe_dump(lock).encode(),
    }

    def run(directory, command, package, *fields, **kwargs):
        if package == "parent@1.0.0":
            value = (
                None
                if problem == "unknown-parent"
                else {"dependencies": {"launch-editor": "^2.0.0"}}
            )
        elif package.startswith("launch-editor@^2.0.0"):
            value = [] if problem == "blocked-parent" else ["2.14.2"]
        elif package.startswith("launch-editor@2.14.1 "):
            value = []
        else:
            value = ["2.14.2"]
        return SimpleNamespace(
            returncode=1 if value is None else 0, stdout=json.dumps(value)
        )

    monkeypatch.setitem(module, "run", run)
    monkeypatch.setitem(
        module, "valid_snapshot", lambda directory: (b"{}", files, {}, {})
    )
    monkeypatch.setitem(module, "restore_invalid_state", lambda *args, **kwargs: False)
    fn(tmp_path, data, files, [], 999999999999, {})
    assert CHOICES["candidates"](data) == ([] if problem else [ITEM])


def test_mixed_report_places_folded_evidence_immediately_under_eligible_row():
    data = findings()
    blocked = copy.deepcopy(data["vulnerabilities"]["launch-editor"])
    blocked["via"][0].pop("_verifiedPatchedVersions")
    blocked["via"][0].pop("_verifiedRepairVersions")
    blocked["via"][0].pop("_repairFrom")
    blocked["via"][0]["url"] = "https://github.com/advisories/GHSA-example-blocked"
    blocked["via"][0]["fixStatus"] = (
        "No published stable patch matches registry range `>=2.0.0`."
    )
    data["vulnerabilities"]["other-package"] = blocked
    report = ENGINE["format_audit_summary"](
        data, data, "pnpm", repair_options=[ITEM], repair_revision=REVISION
    )
    assert "🟡 Needs review" in report and "🔴 Blocked" in report
    row = report.index("<tr><td><code>launch-editor</code>")
    folded = report.index('<tr><td colspan="6"><details>', row)
    following = report.index("<tr><td><code>other-package</code>", folded)
    assert row < folded < following
    assert "Likely feasible. Repair validation has not run." in report
    assert CHOICES["parse"](report.replace("[ ]", "[x]")) == [ITEM]
    assert "GHSA-587h-7wmj-h5pm" in report


def test_html_evidence_escapes_registry_content_and_refuses_bad_links():
    data = findings()
    detail = data["vulnerabilities"]["launch-editor"]["via"][0]
    detail["title"] = '<img src=x onerror="alert(1)">'
    detail["_checkedParentConstraints"] = ["parent <unsafe>"]
    report = ENGINE["format_audit_summary"](data, data, "pnpm", repair_options=[ITEM])
    assert "<img" not in report and "&lt;img" in report
    assert "parent &lt;unsafe&gt;" in report
    detail["url"] = "javascript:alert(1)"
    report = ENGINE["format_audit_summary"](data, data, "pnpm", repair_options=[ITEM])
    assert "javascript:" not in report


def repair_request():
    return {
        "id": "12345678-1234-1234-1234-123456789abc",
        "repository": "example/project",
        "head": REVISION["head"],
        "base": REVISION["base"],
        "pr": 12,
        "selections": [ITEM],
    }


def repair_audit():
    data = findings()
    detail = data["vulnerabilities"][ITEM["name"]]["via"][0]
    data["advisories"] = {
        "1": {
            "module_name": ITEM["name"],
            "severity": detail["severity"],
            "title": detail["title"],
            "url": detail["url"],
            "vulnerable_versions": detail["range"],
            "patched_versions": detail["patchedRange"],
            "findings": [{"version": ITEM["from"]}],
        }
    }
    data["vulnerabilities"][ITEM["name"]]["via"][0]["_verifiedVulnerableVersions"] = [
        ITEM["from"]
    ]
    return data


@pytest.mark.parametrize(
    "key,value",
    [
        (None, None),
        ("REPAIR_PR", "0"),
        ("REPAIR_PR", "01"),
        ("REPAIR_REQUEST", "not-a-uuid"),
        ("REPAIR_HEAD", "A" * 40),
        ("REPAIR_BASE", "main"),
        ("REPAIR_SELECTIONS", "[]"),
        ("GITHUB_REPOSITORY", "../outside/project"),
    ],
)
def test_repair_request_validates_the_fixed_dispatch_inputs(monkeypatch, key, value):
    expected = repair_request()
    for variable, setting in {
        "REPAIR_REQUEST": expected["id"],
        "GITHUB_REPOSITORY": expected["repository"],
        "REPAIR_PR": str(expected["pr"]),
        "REPAIR_HEAD": expected["head"],
        "REPAIR_BASE": expected["base"],
        "REPAIR_SELECTIONS": json.dumps(expected["selections"]),
    }.items():
        monkeypatch.setenv(variable, setting)
    if key is None:
        assert REPAIR["request"]() == expected
    else:
        monkeypatch.setenv(key, value)
        with pytest.raises(ValueError):
            REPAIR["request"]()


def empty_audit():
    return {
        "package_manager": "pnpm",
        "metadata": {"vulnerabilities": {"high": 0}},
        "advisories": {},
        "vulnerabilities": {},
    }


def envelope():
    return dict(
        schema_version=1,
        request=repair_request(),
        project_directory=".",
        before=repair_audit(),
        candidate=empty_audit(),
    )


@pytest.mark.parametrize(
    "problem",
    [
        None,
        "head",
        "base",
        "fork",
        "branch",
        "author",
        "closed",
        "number",
        "selection",
        "marker",
        "duplicate-marker",
        "unicode-marker",
        "crlf",
    ],
)
def test_repair_guard_rechecks_canonical_pr_without_an_idle_check(monkeypatch, problem):
    expected = repair_request()
    repository = {
        "id": 123,
        "full_name": expected["repository"],
        "default_branch": "main",
    }
    pr = {
        "number": 12,
        "state": "open",
        "user": {"type": "Bot"},
        "head": {
            "repo": {"id": 123},
            "ref": "maintenance/node-security",
            "sha": expected["head"],
        },
        "base": {"repo": {"id": 123}, "ref": "main", "sha": expected["base"]},
        "body": CHOICES["render"]([ITEM], **REVISION).replace("[ ]", "[x]"),
    }
    if problem in ("head", "base"):
        pr[problem]["sha"] = "c" * 40
    elif problem == "fork":
        pr["head"]["repo"]["id"] = 999
    elif problem == "branch":
        pr["head"]["ref"] = "main"
    elif problem == "author":
        pr["user"]["type"] = "User"
    elif problem == "closed":
        pr["state"] = "closed"
    elif problem == "number":
        pr["number"] = 13
    elif problem == "selection":
        pr["body"] = pr["body"].replace("[x]", "[ ]")
    elif problem == "marker":
        pr["body"] = pr["body"].replace(expected["head"], "c" * 40)
    elif problem == "duplicate-marker":
        pr["body"] += "\n" + CHOICES["revision_marker"](**REVISION)
    elif problem == "unicode-marker":
        marker = CHOICES["revision_marker"](**REVISION)
        pr["body"] = pr["body"].replace(marker, "prefix\u2028" + marker)
    elif problem == "crlf":
        pr["body"] = pr["body"].replace("\n", "\r\n")
    paths = []

    def read(path):
        paths.append(path)
        return pr if "/pulls/" in path else repository

    fn = REPAIR["guard"]
    monkeypatch.setitem(fn.__globals__, "gh", read)
    if problem and problem != "crlf":
        with pytest.raises(ValueError):
            fn(expected)
    else:
        assert fn(expected) == pr
    assert paths == ["repos/example/project", "repos/example/project/pulls/12"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", True),
        ("schema_version", 2),
        ("request", {}),
        ("before", "unavailable"),
        ("candidate", {}),
        ("project_directory", "../outside"),
        ("project_directory", "/tmp/project"),
        ("project_directory", "./"),
        ("extra", "untrusted"),
    ],
)
def test_strict_candidate_envelope_rejects_wrong_fields(field, value):
    data = envelope()
    data[field] = value
    with pytest.raises(ValueError):
        REPAIR["validate_envelope"](data, repair_request(), ".")


@pytest.mark.parametrize(
    "field,value",
    [
        ("id", "another-request"),
        ("repository", "other/repo"),
        ("head", "c" * 40),
        ("base", "c" * 40),
        ("pr", 13),
        ("pr", True),
        ("selections", [{**ITEM, "to": "2.14.3"}]),
        ("extra", True),
    ],
)
def test_strict_candidate_envelope_binds_every_request_field(field, value):
    data = envelope()
    data["request"][field] = value
    with pytest.raises(ValueError):
        REPAIR["validate_envelope"](data, repair_request(), ".")


@pytest.mark.parametrize(
    "missing", ["schema_version", "request", "project_directory", "before", "candidate"]
)
def test_candidate_envelope_rejects_missing_fields(missing):
    data = envelope()
    del data[missing]
    with pytest.raises(ValueError):
        REPAIR["validate_envelope"](data, repair_request(), ".")


@pytest.mark.parametrize("advisory", ["malformed", {"severity": "unknown"}])
def test_candidate_rejects_raw_advisories_hidden_from_normalized_counts(advisory):
    data = envelope()
    data["candidate"]["advisories"]["bad"] = advisory
    with pytest.raises(ValueError, match="raw audit"):
        REPAIR["validate_envelope"](data, repair_request(), ".")


@pytest.mark.parametrize(
    "field,value",
    [
        ("module_name", "other"),
        ("title", "other"),
        ("url", "https://other"),
        ("severity", "low"),
        ("vulnerable_versions", "*"),
        ("patched_versions", None),
        ("findings", [{"version": "2.14.0"}]),
        ("findings", ["malformed"]),
        ("findings", [{"version": ""}]),
    ],
)
def test_envelope_raw_and_normalized_advisory_evidence_must_agree(field, value):
    data = envelope()
    data["before"]["advisories"]["1"][field] = value
    with pytest.raises(ValueError, match="advisory|advisories"):
        REPAIR["validate_envelope"](data, repair_request(), ".")


@pytest.mark.parametrize("value", [[], {}, False])
def test_envelope_rejects_malformed_normalized_patch_range(value):
    data = envelope()
    data["before"]["vulnerabilities"][ITEM["name"]]["via"][0]["patchedRange"] = value
    with pytest.raises(ValueError, match="Malformed audit"):
        REPAIR["validate_envelope"](data, repair_request(), ".")


def test_envelope_reads_exact_json_and_rejects_symlinks_and_unproved_fixes(
    monkeypatch, tmp_path
):
    monkeypatch.chdir(tmp_path)
    path = tmp_path / "audit.json"
    path.write_text(json.dumps(envelope()))
    assert REPAIR["read_envelope"](path, repair_request(), ".") == envelope()
    path.write_text('{"schema_version":1,' + json.dumps(envelope())[1:])
    with pytest.raises(ValueError, match="Duplicate"):
        REPAIR["read_envelope"](path, repair_request(), ".")
    link = tmp_path / "link.json"
    link.symlink_to(path)
    with pytest.raises(ValueError, match="regular"):
        REPAIR["read_envelope"](link, repair_request(), ".")
    (tmp_path / "real").mkdir()
    (tmp_path / "alias").symlink_to(tmp_path / "real", target_is_directory=True)
    data = {**envelope(), "project_directory": "alias"}
    with pytest.raises(ValueError, match="Symlinked"):
        REPAIR["validate_envelope"](data, repair_request(), "alias")
    for key in ["_verifiedRepairVersions", "_verifiedVulnerableVersions"]:
        data = envelope()
        del data["before"]["vulnerabilities"][ITEM["name"]]["via"][0][key]
        with pytest.raises(ValueError, match="not confirmed"):
            REPAIR["validate_envelope"](data, repair_request(), ".")
    data = envelope()
    data["candidate"] = repair_audit()
    with pytest.raises(ValueError, match="not confirmed"):
        REPAIR["validate_envelope"](data, repair_request(), ".")
    data = envelope()
    data["before"]["metadata"]["vulnerabilities"]["high"] = 0
    with pytest.raises(ValueError, match="counts"):
        REPAIR["validate_envelope"](data, repair_request(), ".")


def repair_files(directory, version="2.14.1"):
    policy = {
        "packages": ["."],
        "minimumReleaseAge": 14400,
        "overrides": {ITEM["name"]: version, "untouched": "1.0.0"},
    }
    lock = {
        "lockfileVersion": "9.0",
        "settings": {"autoInstallPeers": True},
        "overrides": policy["overrides"],
        "importers": {
            ".": {
                "dependencies": {
                    ITEM["name"]: {
                        "specifier": version,
                        "version": version + "(peer@1.0.0)",
                    },
                    "untouched": {"specifier": "^1.0.0", "version": "1.0.0"},
                }
            }
        },
        "packages": {
            f"{ITEM['name']}@{version}": {"resolution": {"integrity": version}},
            "untouched@1.0.0": {"resolution": {"integrity": "untouched"}},
        },
        "snapshots": {
            f"{ITEM['name']}@{version}(peer@1.0.0)": {},
            "untouched@1.0.0": {
                "dependencies": {ITEM["name"]: version + "(peer@1.0.0)"}
            },
        },
    }
    (directory / "package.json").write_text(
        json.dumps(
            {
                "name": "fixture",
                "packageManager": "pnpm@11.21.0",
                "dependencies": {ITEM["name"]: "^2.14.1"},
            }
        )
    )
    (directory / "pnpm-workspace.yaml").write_text(yaml.safe_dump(policy))
    (directory / "pnpm-lock.yaml").write_text(yaml.safe_dump(lock))
    return ENGINE["valid_snapshot"](directory)


@pytest.mark.parametrize(
    "problem",
    [
        None,
        "setting",
        "unselected-metadata",
        "importer",
        "peers",
        "snapshot-peers",
        "unselected-version",
        "policy",
        "manifest",
    ],
)
def test_candidate_scope_preserves_unrelated_metadata_and_peer_suffixes(
    tmp_path, problem
):
    before = repair_files(tmp_path)
    after = repair_files(tmp_path, ITEM["to"])
    assert before is not None and after is not None
    if problem:
        files = dict(after[1])
        lock = yaml.safe_load(files["pnpm-lock.yaml"])
        if problem == "setting":
            lock["settings"]["autoInstallPeers"] = False
        elif problem == "unselected-metadata":
            lock["packages"]["untouched@1.0.0"]["resolution"]["integrity"] = "changed"
        elif problem == "importer":
            lock["importers"]["."]["dependencies"]["untouched"]["specifier"] = "*"
        elif problem == "peers":
            lock["importers"]["."]["dependencies"][ITEM["name"]]["version"] = (
                ITEM["to"] + "(peer@2.0.0)"
            )
        elif problem == "unselected-version":
            lock["packages"]["added@1.0.0"] = {}
        elif problem == "snapshot-peers":
            key = ITEM["name"] + "@" + ITEM["to"] + "(peer@1.0.0)"
            lock["snapshots"][key.replace("peer@1.0.0", "peer@2.0.0")] = lock[
                "snapshots"
            ].pop(key)
        elif problem == "policy":
            policy = yaml.safe_load(files["pnpm-workspace.yaml"])
            policy["minimumReleaseAge"] = 0
            files["pnpm-workspace.yaml"] = yaml.safe_dump(policy).encode()
        elif problem == "manifest":
            (tmp_path / "package.json").write_text('{"packageManager":"pnpm@11.21.0"}')
        files["pnpm-lock.yaml"] = yaml.safe_dump(lock).encode()
        for name, value in files.items():
            (tmp_path / name).write_bytes(value)
        after = ENGINE["valid_snapshot"](tmp_path)
        with pytest.raises(ValueError):
            REPAIR["check_scope"](before, after, [ITEM])
    else:
        REPAIR["check_scope"](before, after, [ITEM])


@pytest.mark.parametrize(
    "problem", [None, "parent", "direct", "young", "unavailable", "pin"]
)
def test_targets_use_verified_sets_and_independent_direct_constraints(
    monkeypatch, tmp_path, problem
):
    snapshot = repair_files(tmp_path)
    fn = REPAIR["verified_targets"]
    engine = fn.__globals__["ENGINE"]
    target = {**ITEM, "to": "2.14.3"}

    def describe(directory, proof, files, *args, **kwargs):
        detail = proof["vulnerabilities"][ITEM["name"]]["via"][0]
        detail.update(
            fixVersion="2.14.2",
            _repairFrom=ITEM["from"],
            _verifiedVulnerableVersions=[ITEM["from"]],
            _verifiedRepairVersions=[] if problem == "parent" else ["2.14.2", "2.14.3"],
        )

    def lookup(directory, command, package, *fields, **kwargs):
        if fields[0] == "time":
            value = {
                target["to"]: "2999-01-01T00:00:00Z"
                if problem == "young"
                else "2020-01-01T00:00:00Z"
            }
        else:
            assert package == "launch-editor@^2.14.1 2.14.3"
            value = [] if problem == "direct" else target["to"]
        return SimpleNamespace(
            returncode=1 if problem == "unavailable" else 0, stdout=json.dumps(value)
        )

    monkeypatch.setitem(engine, "describe_pnpm_fixes", describe)
    monkeypatch.setitem(engine, "run", lookup)
    if problem == "pin":
        target = {**target, "from": "2.14.0"}
    if problem:
        with pytest.raises(ValueError):
            fn(tmp_path, repair_audit(), snapshot, [target], float("inf"), 14400)
    else:
        # A common selected patch may exceed this advisory's minimum patch.
        proof = fn(tmp_path, repair_audit(), snapshot, [target], float("inf"), 14400)
        assert (
            target["to"]
            in proof["vulnerabilities"][ITEM["name"]]["via"][0][
                "_verifiedRepairVersions"
            ]
        )


@pytest.mark.parametrize("problem", [None, "install", "audit", "scope", "extra-file"])
def test_preparation_seals_only_three_members_without_validation(
    monkeypatch, tmp_path, problem
):
    project = tmp_path / "project"
    project.mkdir()
    before = repair_files(project)
    changed = tmp_path / "changed"
    changed.mkdir()
    candidate = repair_files(changed, ITEM["to"])
    monkeypatch.chdir(project)
    fn = REPAIR["prepare"]
    module = fn.__globals__
    engine = module["ENGINE"]
    monkeypatch.setenv("npm_config_ignore_pnpmfile", "false")
    monkeypatch.setitem(
        module,
        "project_context",
        lambda: (project, {"minimumReleaseAge": 14400}, before),
    )
    monkeypatch.setitem(module, "verified_targets", lambda *a, **kw: repair_audit())
    monkeypatch.setitem(module, "native_history", lambda *a: normal_history(before))
    monkeypatch.setitem(module, "export_patch", lambda paths: b"sealed patch\n")
    status = []

    def command(*args):
        if args == ("rev-parse", "HEAD"):
            return REVISION["head"]
        if "-z" in args:
            return " M pnpm-lock.yaml\0 M pnpm-workspace.yaml\0" + (
                "?? unrelated\0" if problem == "extra-file" else ""
            )
        status.append(args)
        return ""

    def install(directory, *args, **kwargs):
        import os

        assert args == REPAIR["CANDIDATE_INSTALL"]
        assert all(
            os.environ[key] == value for key, value in REPAIR["HOOK_ENV"].items()
        )
        (project / "pnpm-lock.yaml").write_bytes(candidate[1]["pnpm-lock.yaml"])
        if problem == "scope":
            (project / "package.json").write_text("{}")
        return SimpleNamespace(returncode=1 if problem == "install" else 0)

    audits = iter(
        [repair_audit(), "unavailable" if problem == "audit" else empty_audit()]
    )
    monkeypatch.setitem(module, "git", command)
    monkeypatch.setitem(engine, "run", install)
    monkeypatch.setitem(engine, "audit", lambda *a, **kw: next(audits))
    monkeypatch.setitem(engine, "describe_pnpm_fixes", lambda *a, **kw: None)
    artifact = tmp_path / "sealed"
    if problem:
        with pytest.raises(ValueError):
            fn(repair_request(), artifact)
        assert not artifact.exists()
    else:
        result = fn(repair_request(), artifact)
        assert set(p.name for p in artifact.iterdir()) == {
            "candidate.patch",
            "audit.json",
            "result.md",
        }
        assert (
            REPAIR["read_envelope"](artifact / "audit.json", repair_request(), ".")
            == result
        )
        assert "Project validation has not run" in (artifact / "result.md").read_text()
    import os

    assert os.environ["npm_config_ignore_pnpmfile"] == "false"


def test_patch_export_never_executes_repository_diff_helpers(monkeypatch, tmp_path):
    def git(*args):
        return subprocess.run(
            ["git", *args], cwd=tmp_path, check=True, capture_output=True
        )

    git("init", "-q")
    git("config", "user.name", "Fixture")
    git("config", "user.email", "fixture@example.invalid")
    path = tmp_path / "pnpm-workspace.yaml"
    path.write_text("overrides: {launch-editor: 2.14.1}\n")
    (tmp_path / ".gitattributes").write_text("*.yaml diff=evil\n")
    git("add", ".")
    git("commit", "-qm", "fixture")
    hook = tmp_path / "external.sh"
    hook.write_text("#!/bin/sh\ntouch helper-executed\nprintf forged\n")
    hook.chmod(0o755)
    git("config", "diff.evil.textconv", str(hook))
    git("config", "diff.external", str(hook))
    monkeypatch.setenv("GIT_EXTERNAL_DIFF", str(hook))
    path.write_text("overrides: {launch-editor: 2.14.2}\n")
    monkeypatch.chdir(tmp_path)
    patch = REPAIR["export_patch"]([path.name])
    assert b"-overrides: {launch-editor: 2.14.1}" in patch
    assert b"+overrides: {launch-editor: 2.14.2}" in patch
    assert not (tmp_path / "helper-executed").exists()


def test_repair_workflow_keeps_preparation_separate_from_read_only_validation():
    workflow = yaml.safe_load((ROOT / ".github/workflows/node-repair.yml").read_text())
    action = yaml.safe_load((ROOT / "node/repair/action.yml").read_text())
    assert set(workflow["on"]["workflow_call"]["inputs"]) == {
        "request-id",
        "pull-request",
        "expected-head",
        "expected-base",
        "selections",
    }
    assert set(workflow["jobs"]) == {"guard", "prepare", "validate", "publish"}
    for name, job in workflow["jobs"].items():
        if name != "publish":
            assert set(job["permissions"].values()) == {"read"}
        assert any(step.get("uses") == "$/node/repair" for step in job["steps"])
    prepare = workflow["jobs"]["prepare"]
    assert prepare["env"] == REPAIR["HOOK_ENV"]
    checkout = prepare["steps"][0]
    assert checkout["with"] == {
        "ref": "${{ inputs.expected-head }}",
        "persist-credentials": False,
        "fetch-depth": 0,
    }
    assert "candidate-artifact-id" in prepare["outputs"]
    upload = next(
        step for step in action["runs"]["steps"] if step.get("id") == "candidate"
    )
    assert [Path(p).name for p in upload["with"]["path"].splitlines()] == [
        "candidate.patch",
        "audit.json",
        "result.md",
    ]
    validation = workflow["jobs"]["validate"]
    assert validation["needs"] == "prepare"
    assert validation["steps"][0]["with"] == {
        k: v for k, v in checkout["with"].items() if k != "fetch-depth"
    }
    assert (
        validation["steps"][1]["with"]["candidate-artifact-id"]
        == "${{ needs.prepare.outputs.candidate-artifact-id }}"
    )
    assert (
        workflow["on"]["workflow_call"]["outputs"]["candidate-artifact-id"]["value"]
        == "${{ jobs.prepare.outputs.candidate-artifact-id }}"
    )
    download = next(
        step
        for step in action["runs"]["steps"]
        if step.get("uses", "").startswith("actions/download-artifact@")
    )
    assert set(download["with"]) == {"artifact-ids", "path", "digest-mismatch"}
    assert download["with"]["artifact-ids"] == "${{ inputs.candidate-artifact-id }}"
    assert download["with"]["digest-mismatch"] == "error"
    assert upload["if"] == "${{ inputs.operation == 'prepare' }}"
    human = next(
        step
        for step in action["runs"]["steps"]
        if step.get("name") == "Retain human validation evidence only"
    )
    assert human["with"]["path"] == "${{ runner.temp }}/node-repair-validation/"
    publisher = workflow["jobs"]["publish"]
    assert publisher["needs"] == ["prepare", "validate"]
    assert publisher["permissions"] == {
        "contents": "write",
        "pull-requests": "write",
        "actions": "read",
        "checks": "read",
    }
    assert publisher["concurrency"] == {
        "group": "node-dependency-proposal-${{ github.repository }}",
        "cancel-in-progress": False,
    }
    # The job context is available in step env, not in job-level env.
    assert "env" not in publisher
    assert publisher["steps"][1]["env"] == {
        "TRUSTED_WORKFLOW_SHA": "${{ job.workflow_sha }}"
    }
    assert publisher["steps"][0]["with"] == checkout["with"]
    assert (
        publisher["steps"][1]["with"]["candidate-artifact-id"]
        == "${{ needs.prepare.outputs.candidate-artifact-id }}"
    )
    for step in action["runs"]["steps"]:
        if (
            "corepack" in step.get("run", "")
            or step.get("uses", "").startswith("actions/setup-node@")
            or step.get("name") == "Resolve the declared preparation toolchain"
        ):
            assert (
                step["if"]
                == "${{ inputs.operation == 'prepare' || inputs.operation == 'validate' }}"
            )
    assert "publish" in download["if"]


@pytest.mark.parametrize(
    "action_path,step_name",
    [
        ("node/repair/action.yml", "Install configuration and audit parser"),
        ("node/audit/action.yml", "Install configuration and audit report parser"),
    ],
)
def test_parser_install_isolated_from_checkout_module_shadowing(
    tmp_path, action_path, step_name
):
    action = yaml.safe_load((ROOT / action_path).read_text())
    command = next(
        step["run"] for step in action["runs"]["steps"] if step.get("name") == step_name
    )
    assert command == "python -I -m pip install PyYAML==6.0.3"
    legacy_command = command.replace("python -I -m pip", "python -m pip", 1)

    for name, command_to_run, shadowed in [
        ("legacy", legacy_command, True),
        ("isolated", command, False),
    ]:
        checkout = tmp_path / name
        checkout.mkdir()
        marker = checkout / "project-code-executed"
        (checkout / "pip.py").write_text(
            "import os\nfrom pathlib import Path\n"
            'Path(os.environ["PIP_SHADOW_MARKER"]).write_text("executed")\n'
        )
        environment = os.environ.copy()
        environment.update(
            {
                "PIP_SHADOW_MARKER": str(marker),
                "PIP_NO_INDEX": "true",
                "PIP_DISABLE_PIP_VERSION_CHECK": "1",
                "PIP_CACHE_DIR": str(tmp_path / "pip-cache"),
            }
        )
        arguments = shlex.split(command_to_run)
        assert arguments[0] == "python"
        arguments[0] = sys.executable
        result = subprocess.run(
            arguments,
            cwd=checkout,
            env=environment,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
        assert marker.exists() is shadowed


@pytest.fixture
def sealed_checkout(monkeypatch, tmp_path):
    root = tmp_path / "checkout"
    root.mkdir()
    monkeypatch.chdir(root)
    before = repair_files(root)
    (root / ".github").mkdir()
    (root / ".github/node-maintenance.json").write_text('{"validationScript":"check"}')
    (root / "unrelated.txt").write_text("unchanged\n")
    subprocess.run(["git", "init", "-q"], check=True)
    subprocess.run(["git", "add", "."], check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.com",
            "commit",
            "-qm",
            "fixture",
        ],
        check=True,
    )
    expected = dict(repair_request(), head=REPAIR["git"]("rev-parse", "HEAD").strip())
    repair_files(root, ITEM["to"])
    artifact = tmp_path / "candidate"
    artifact.mkdir()
    (artifact / "candidate.patch").write_bytes(
        REPAIR["export_patch"](["pnpm-workspace.yaml", "pnpm-lock.yaml"])
    )
    (artifact / "audit.json").write_text(json.dumps(dict(envelope(), request=expected)))
    (artifact / "result.md").write_text("Original preparation report\n")
    subprocess.run(["git", "reset", "--hard", "-q", "HEAD"], check=True)
    module = REPAIR["validate"].__globals__
    monkeypatch.setitem(
        module, "project_context", lambda: (root, {"validationScript": "check"}, before)
    )
    return root, artifact, before, expected


@pytest.mark.parametrize(
    "problem",
    [
        None,
        "extra-member",
        "missing-member",
        "symlink",
        "directory",
        "wrong-request",
        "empty-patch",
        "extra-path",
        "mode",
        "delete",
        "rename",
        "copy",
        "absolute",
        "traversal",
    ],
)
def test_candidate_consumption_uses_native_git_scope_before_execution(
    sealed_checkout, problem
):
    root, artifact, before, expected = sealed_checkout
    patch = artifact / "candidate.patch"
    if problem == "extra-member":
        (artifact / "extra").touch()
    elif problem == "missing-member":
        (artifact / "result.md").unlink()
    elif problem in ("symlink", "directory"):
        (artifact / "result.md").unlink()
        if problem == "symlink":
            (artifact / "result.md").symlink_to(root / "unrelated.txt")
        else:
            (artifact / "result.md").mkdir()
    elif problem == "wrong-request":
        data = json.loads((artifact / "audit.json").read_text())
        data["request"]["id"] = "0" * 36
        (artifact / "audit.json").write_text(json.dumps(data))
    elif problem == "empty-patch":
        patch.write_text("")
    elif problem == "extra-path":
        (root / "unrelated.txt").write_text("changed\n")
        patch.write_bytes(
            patch.read_bytes() + REPAIR["export_patch"](["unrelated.txt"])
        )
        subprocess.run(["git", "checkout", "--", "unrelated.txt"], check=True)
    elif problem == "mode":
        patch.write_text(
            patch.read_text().replace(
                "index ", "old mode 100644\nnew mode 100755\nindex ", 1
            )
        )
    elif problem == "delete":
        (root / "pnpm-lock.yaml").unlink()
        patch.write_bytes(REPAIR["export_patch"](["pnpm-lock.yaml"]))
        subprocess.run(["git", "checkout", "--", "pnpm-lock.yaml"], check=True)
    elif problem in ("rename", "copy"):
        patch.write_text(
            f"diff --git a/pnpm-lock.yaml b/other.yaml\nsimilarity index 100%\n{problem} from pnpm-lock.yaml\n{problem} to other.yaml\n"
        )
    elif problem in ("absolute", "traversal"):
        name = "/tmp/outside.yaml" if problem == "absolute" else "../outside.yaml"
        patch.write_text(
            patch.read_text()
            .replace("a/pnpm-lock.yaml", "a/" + name)
            .replace("b/pnpm-lock.yaml", "b/" + name)
        )
    if problem:
        with pytest.raises((ValueError, subprocess.CalledProcessError)):
            REPAIR["apply_candidate"](expected, artifact, root, before)
        assert ENGINE["valid_snapshot"](root) == before
    else:
        _, candidate = REPAIR["apply_candidate"](expected, artifact, root, before)
        REPAIR["check_scope"](before, candidate, expected["selections"])


@pytest.mark.parametrize(
    "problem",
    [
        None,
        "install-failure",
        "check-failure",
        "install-drift",
        "check-drift",
        "policy-mode",
        "lock-symlink",
        "config-drift",
        "new-config",
        "audit-drift",
        "malformed-audit",
        "selected-remains",
        "new-finding",
        "artifact-tamper",
    ],
)
def test_validation_fails_closed_and_never_reseals_candidate(
    monkeypatch, sealed_checkout, tmp_path, problem
):
    import shutil

    root, original, _, expected = sealed_checkout
    original_bytes = {p.name: p.read_bytes() for p in original.iterdir()}
    artifact = tmp_path / "downloaded"
    shutil.copytree(original, artifact)
    module = REPAIR["validate"].__globals__
    commands = []

    def command(directory, *args, **kwargs):
        commands.append(args)
        install = args[0] == "install"
        if problem == ("install-drift" if install else "check-drift"):
            with (root / "pnpm-lock.yaml").open("a") as stream:
                stream.write("\n# changed by project\n")
        if not install:
            if problem == "config-drift":
                (root / ".github/node-maintenance.json").write_text("{}")
            elif problem == "new-config":
                (root / ".npmrc").write_text("ignore-scripts=true")
            elif problem == "policy-mode":
                (root / "pnpm-workspace.yaml").chmod(0o755)
            elif problem == "lock-symlink":
                lock = root / "pnpm-lock.yaml"
                saved = tmp_path / "lock-copy"
                saved.write_bytes(lock.read_bytes())
                lock.unlink()
                lock.symlink_to(saved)
            elif problem == "artifact-tamper":
                (artifact / "candidate.patch").write_text("forged patch\n")
                (artifact / "result.md").write_text("forged success\n")
        return SimpleNamespace(
            returncode=int(
                problem == ("install-failure" if install else "check-failure")
            ),
            stdout="test output",
            stderr="",
        )

    def audit(*args, **kwargs):
        if problem == "audit-drift":
            (root / "pnpm-workspace.yaml").write_text("{}")
        if problem == "malformed-audit":
            return "unavailable"
        if problem in ("selected-remains", "new-finding"):
            result = repair_audit()
            if problem == "new-finding":
                result["advisories"]["1"]["url"] += "-new"
                result["vulnerabilities"][ITEM["name"]]["via"][0]["url"] += "-new"
            return result
        return empty_audit()

    monkeypatch.setitem(module["ENGINE"], "run", command)
    monkeypatch.setitem(module["ENGINE"], "audit", audit)
    evidence = tmp_path / "human-evidence"
    if problem in (None, "artifact-tamper"):
        REPAIR["validate"](expected, artifact, evidence)
        assert commands == [("install", "--frozen-lockfile"), ("run", "check")]
        assert "Validation passed" in (evidence / "result.md").read_text()
        assert "forged" not in (evidence / "result.md").read_text()
    else:
        with pytest.raises(ValueError):
            REPAIR["validate"](expected, artifact, evidence)
        assert "Validation failed" in (evidence / "result.md").read_text()
        if problem.startswith("install-"):
            assert len(commands) == 1
    assert not (evidence / "candidate.patch").exists()
    assert {p.name: p.read_bytes() for p in original.iterdir()} == original_bytes
    assert REPAIR["git"]("rev-parse", "HEAD").strip() == expected["head"]


def normal_history(snapshot):
    audit = repair_audit()
    return dict(
        version=1,
        repository=repair_request()["repository"],
        source="c" * 40,
        project=".",
        manager="pnpm",
        before_state=ENGINE["dependency_state"](snapshot),
        candidate_state=ENGINE["dependency_state"](snapshot),
        before=audit,
        after=audit,
        fixed_ids=[],
        package_report=ENGINE["format_audit_summary"](
            audit, audit, "pnpm", fixed_ids=set(), locks=(snapshot[3], snapshot[3])
        ),
    )


@pytest.fixture
def cumulative_candidate(tmp_path, monkeypatch):
    root = tmp_path / "source"
    root.mkdir()
    monkeypatch.chdir(root)
    before = repair_files(root)
    initial = normal_history(before)
    after = repair_files(root, ITEM["to"])
    proof = repair_audit()
    # The original advisory disappeared from the registry. Only fresh evidence
    # for another advisory can establish this attempt's selected repair.
    for detail in (
        proof["advisories"]["1"],
        proof["vulnerabilities"][ITEM["name"]]["via"][0],
    ):
        detail["url"] = "https://github.com/advisories/GHSA-fresh-one1-test"
    report = REPAIR["cumulative_report"](
        initial,
        repair_request(),
        root,
        {},
        before,
        after,
        proof,
        empty_audit(),
        {"https://github.com/advisories/GHSA-fresh-one1-test"},
    )
    return root, before, after, initial, proof, report


def test_three_attempt_history_retains_original_inventory(cumulative_candidate):
    root, before, after, initial, proof, report = cumulative_candidate
    record = ENGINE["history_record"](report.encode())
    assert record["attempts"][0] == initial
    original_url = repair_audit()["advisories"]["1"]["url"]
    assert original_url in report
    assert "Historical evidence (attempt 1)" in report
    assert "Cumulative evidence: 2 advisory/package pairs across 2 attempts" in report
    assert report.count("| Package |") == 1
    final = repair_files(root, "2.14.3")
    fresh = repair_audit()
    raw = fresh["advisories"]["1"]
    raw["findings"][0]["version"] = ITEM["to"]
    detail = fresh["vulnerabilities"][ITEM["name"]]["via"][0]
    detail["nodes"] = [ITEM["name"] + "@" + ITEM["to"]]
    detail["_verifiedVulnerableVersions"] = [ITEM["to"]]
    detail["_verifiedRepairVersions"] = ["2.14.3"]
    for item in (raw, detail):
        item["url"] = "https://github.com/advisories/GHSA-fresh-two2-test"
    request = dict(
        repair_request(),
        head="d" * 40,
        selections=[dict(ITEM, **{"from": ITEM["to"], "to": "2.14.3"})],
    )
    third = REPAIR["cumulative_report"](
        record, request, root, {}, after, final, fresh, empty_audit(), {detail["url"]}
    )
    third_record = ENGINE["history_record"](third.encode())
    assert third_record["attempts"][:2] == record["attempts"]
    assert len(third_record["attempts"]) == 3
    assert original_url in third and raw["url"] in third
    assert "Cumulative evidence: 3 advisory/package pairs across 3 attempts" in third
    assert third.count("| Package |") == 1
    assert third.count("| `launch-editor`") == 3
    assert "Historical evidence (attempt 2)" in third
    assert "Current attempt" in third
    # Original normalized and raw CVE evidence is carried, not regenerated.
    assert third_record["attempts"][0]["before"] == initial["before"]


def test_history_absence_is_not_a_new_fix_claim(cumulative_candidate):
    root, before, after, initial, proof, _ = cumulative_candidate
    initial["before"] = initial["after"] = empty_audit()
    # Preserve a historical upgraded package row even when both fresh audits
    # omit that package entirely.
    initial["package_report"] = (
        "| `earlier` | `1.0.0` → `1.0.1` | High | 1 fixed | ✅ Fix proposed. Resolved. | [CVE-2026-1111](https://example.com/advisory) |"
    )
    report = REPAIR["cumulative_report"](
        initial, repair_request(), root, {}, before, after, proof, empty_audit(), set()
    )
    assert (
        "Historical evidence (attempt 1). Not observed in the current audit." in report
    )
    assert "withdrawn" not in report.lower()
    # The payload keeps the full prior row independently of a fresh audit.
    assert ENGINE["history_record"](report.encode())["attempts"][0] == initial


def test_current_unresolved_takes_precedence_over_historical_success(
    cumulative_candidate,
):
    root, before, after, initial, proof, _ = cumulative_candidate
    initial["package_report"] = initial["package_report"].replace(
        "🟡 Needs review.", "✅ Fix proposed. Resolved."
    )
    report = REPAIR["cumulative_report"](
        initial,
        repair_request(),
        root,
        {},
        before,
        after,
        repair_audit(),
        repair_audit(),
        set(),
    )
    assert "Historical evidence (attempt 1). Current unresolved." in report
    assert "Current attempt." in report


@pytest.mark.parametrize(
    "problem", ["chain", "identity", "missing-rows", "bad-audit", "oversized"]
)
def test_cumulative_seal_rejects_incomplete_history(cumulative_candidate, problem):
    root, before, after, initial, proof, report = cumulative_candidate
    if problem == "chain":
        initial["candidate_state"]["pnpm-lock.yaml"] = "0" * 64
    elif problem == "identity":
        initial["repository"] = "different/repo"
    elif problem == "missing-rows":
        initial["package_report"] = "No findings"
    elif problem == "bad-audit":
        initial["before"] = "unavailable"
    else:
        initial["package_report"] += "\n" + "x" * 524288
    with pytest.raises(ValueError):
        REPAIR["cumulative_report"](
            initial,
            repair_request(),
            root,
            {},
            before,
            after,
            proof,
            empty_audit(),
            set(),
        )


@pytest.fixture
def repair_history_provider(cumulative_candidate, monkeypatch):
    import hashlib
    from io import BytesIO
    from zipfile import ZipFile

    root, before, after, initial, proof, report = cumulative_candidate
    record = ENGINE["history_record"](report.encode())
    payload = dict(envelope(), before=proof)
    stream = BytesIO()
    with ZipFile(stream, "w") as bundle:
        for name, data in {
            "candidate.patch": b"actual sealed patch",
            "audit.json": json.dumps(payload).encode(),
            "result.md": report.encode(),
        }.items():
            bundle.writestr(name, data)
    archive = stream.getvalue()
    locator = dict(
        run=10,
        job=20,
        check=30,
        artifact=40,
        archive_sha256=hashlib.sha256(archive).hexdigest(),
        content_sha256=hashlib.sha256(report.encode()).hexdigest(),
    )
    repo = repair_request()["repository"]
    trigger = "e" * 40
    workflow = "f" * 40
    name = "repair / Node repair preparation"
    run = dict(
        repository={"full_name": repo},
        path=".github/workflows/fixture.yml",
        head_sha=trigger,
        event="workflow_dispatch",
        run_attempt=1,
        referenced_workflows=[
            dict(
                path="hydra-ecosystem/github-actions/.github/workflows/node-repair.yml@experiment/node-maintenance-repair",
                sha=workflow,
            )
        ],
    )
    job = dict(
        id=20,
        run_id=10,
        run_attempt=1,
        head_sha=trigger,
        name=name,
        check_run_url=f"https://api.github.com/repos/{repo}/check-runs/30",
        status="completed",
        conclusion="success",
        html_url=f"https://github.com/{repo}/actions/runs/10/job/20",
        steps=[
            {"name": s, "conclusion": "success"}
            for s in (
                "Prepare the selected candidate using trusted workflow code",
                "Seal uploaded repair evidence",
            )
        ],
    )
    check = dict(
        id=30,
        head_sha=trigger,
        app={"id": 15368},
        details_url=job["html_url"],
        output={"annotations_count": 1},
    )
    notice = dict(
        title=REPAIR["REPAIR_HISTORY_TITLE"],
        annotation_level="notice",
        message=f"v1:40:{locator['archive_sha256']}:{locator['content_sha256']}",
    )
    metadata = dict(
        id=40,
        expired=False,
        size_in_bytes=len(archive),
        digest="sha256:" + locator["archive_sha256"],
        workflow_run={"id": 10, "head_sha": trigger},
    )
    data = {
        "actions/runs/10": run,
        "actions/jobs/20": job,
        "actions/runs/10/attempts/1/jobs?per_page=100": {
            "total_count": 1,
            "jobs": [job],
        },
        "check-runs/30": check,
        "check-runs/30/annotations?per_page=100": [notice],
        "actions/artifacts/40": metadata,
        "actions/artifacts/40/zip": archive,
        f"contents/.github/workflows/fixture.yml?ref={trigger}": encoded_workflow(
            {"repair": {"uses": run["referenced_workflows"][0]["path"]}}
        ),
        f"contents/.github/workflows/node-repair.yml?ref={workflow}": encoded_workflow(
            {"prepare": {"name": "Node repair preparation", "steps": []}}
        ),
    }

    def api(repository, suffix, **kwargs):
        assert repository in (repo, "hydra-ecosystem/github-actions")
        return data[suffix]

    monkeypatch.setitem(
        REPAIR["verify_repair_history"].__globals__["ENGINE"], "history_api", api
    )
    return (
        locator,
        repo,
        record["source"],
        ".",
        record["candidate_state"],
        workflow,
        data,
        record,
    )


@pytest.mark.parametrize(
    "problem",
    [
        None,
        "sibling",
        "forged-check",
        "duplicate-notice",
        "notice-level",
        "notice-hash",
        "wrong-workflow",
        "job-failed",
        "step-order",
        "job-attempt",
        "job-head",
        "check-app",
        "check-url",
        "expired",
        "artifact-head",
        "artifact-digest",
        "archive",
        "source",
        "dependency-state",
    ],
)
def test_distinct_run_repair_history_requires_exact_producer(
    repair_history_provider, problem
):
    locator, repo, source, project, state, workflow, data, record = (
        repair_history_provider
    )
    if problem == "sibling":
        data["actions/jobs/20"]["name"] = "sibling / copied bytes"
    elif problem == "forged-check":
        data["actions/jobs/20"]["check_run_url"] = (
            f"https://api.github.com/repos/{repo}/check-runs/99"
        )
    elif problem == "duplicate-notice":
        data["check-runs/30/annotations?per_page=100"] *= 2
    elif problem == "notice-level":
        data["check-runs/30/annotations?per_page=100"][0]["annotation_level"] = (
            "warning"
        )
    elif problem == "notice-hash":
        data["check-runs/30/annotations?per_page=100"][0]["message"] += "x"
    elif problem == "wrong-workflow":
        data["actions/runs/10"]["referenced_workflows"][0]["sha"] = "0" * 40
    elif problem == "job-failed":
        data["actions/jobs/20"]["conclusion"] = "failure"
    elif problem == "step-order":
        data["actions/jobs/20"]["steps"].reverse()
    elif problem == "job-attempt":
        data["actions/jobs/20"]["run_attempt"] = 2
    elif problem == "job-head":
        data["actions/jobs/20"]["head_sha"] = source
    elif problem == "check-app":
        data["check-runs/30"]["app"]["id"] = 1
    elif problem == "check-url":
        data["check-runs/30"]["details_url"] += "-forged"
    elif problem == "expired":
        data["actions/artifacts/40"]["expired"] = True
    elif problem == "artifact-head":
        data["actions/artifacts/40"]["workflow_run"]["head_sha"] = source
    elif problem == "artifact-digest":
        data["actions/artifacts/40"]["digest"] = "sha256:" + "0" * 64
    elif problem == "archive":
        data["actions/artifacts/40/zip"] += b"tampered"
    elif problem == "source":
        source = "0" * 40
    elif problem == "dependency-state":
        state = dict(state, **{"pnpm-lock.yaml": "0" * 64})
    if problem:
        with pytest.raises(ValueError):
            REPAIR["verify_repair_history"](
                locator, repo, source, project, state, workflow
            )
    else:
        assert (
            REPAIR["verify_repair_history"](
                locator, repo, source, project, state, workflow
            )
            == record
        )


def test_native_history_uses_commit_trailers_and_rejects_missing_receipt(
    sealed_checkout, monkeypatch
):
    root, _, snapshot, expected = sealed_checkout
    with pytest.raises(ValueError, match="No sealed historical evidence"):
        REPAIR["native_history"](expected, root, snapshot)
    locator = dict(
        run=1,
        job=2,
        check=3,
        artifact=4,
        archive_sha256="a" * 64,
        content_sha256="b" * 64,
    )
    trailers = (
        "\n".join(f"Node-Audit-{k.replace('_', '-')}: {v}" for k, v in locator.items())
        + "\nNode-Audit-Workflow-SHA: "
        + "f" * 40
    )
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.com",
            "commit",
            "--allow-empty",
            "-qm",
            "Normal proposal\n\n" + trailers,
        ],
        check=True,
    )
    expected = dict(expected, head=REPAIR["git"]("rev-parse", "HEAD").strip())
    module = REPAIR["native_history"].__globals__["ENGINE"]
    monkeypatch.setitem(
        module,
        "history_api",
        lambda *a, **kw: {"name": "audit / Node audit evidence (node-security)"},
    )
    monkeypatch.setitem(
        REPAIR["native_history"].__globals__,
        "producer_names",
        lambda *args: ["audit / Node audit evidence (node-security)"],
    )
    calls = []

    def verify(actual, **kwargs):
        calls.append((actual, kwargs))
        return normal_history(snapshot)

    monkeypatch.setitem(module, "verify_history", verify)
    REPAIR["native_history"](expected, root, snapshot)
    assert calls[0][0] == locator
    assert calls[0][1]["candidate_state"] == ENGINE["dependency_state"](snapshot)
    assert calls[0][1]["source"] == REPAIR["git"]("rev-parse", "HEAD^").strip()


def test_historical_html_rows_preserve_renderer_evidence_and_versions():
    report = '<table><thead><tr><th>Package</th></tr></thead><tbody><tr><td><code>pkg</code></td><td><code>1.0.0</code> → <code>1.0.1</code></td><td>High</td><td>1 fixed</td><td>✅ Fix proposed. Resolved.</td><td><a href="https://example.com/GHSA-original">GHSA-original</a></td></tr><tr><td colspan="6"><details>pin assessment</details></td></tr></tbody></table>'
    rows = REPAIR["report_rows"](report)
    assert rows == [
        [
            "`pkg`",
            "`1.0.0` → `1.0.1`",
            "High",
            "1 fixed",
            "✅ Fix proposed. Resolved.",
            "[GHSA-original](https://example.com/GHSA-original)",
        ]
    ]
    assert REPAIR["report_rows"](
        "| `pkg` | one | High | 1 | action | evidence |\r\n"
    ) == [["`pkg`", "one", "High", "1", "action", "evidence"]]


@pytest.mark.parametrize("html_origin", [False, True])
def test_cumulative_table_keeps_range_pipes_inside_six_cells(
    cumulative_candidate, html_origin
):
    root, before, after, initial, proof, _ = cumulative_candidate
    audit = initial["before"]
    affected = ">=1.0.0 <2.0.0 || >=3.0.0 <4.0.0"
    audit["advisories"]["1"]["vulnerable_versions"] = affected
    audit["vulnerabilities"][ITEM["name"]]["via"][0]["range"] = affected
    initial["after"] = empty_audit()
    report = ENGINE["format_audit_summary"](
        audit,
        initial["after"],
        "pnpm",
        fixed_ids=set(),
        locks=(before[3], before[3]),
        repair_options=[ITEM] if html_origin else None,
    )
    assert ("<table>" in report) == html_origin
    initial["package_report"] = report
    result = REPAIR["cumulative_report"](
        initial, repair_request(), root, {}, before, after, proof, empty_audit(), set()
    )
    rows = [line for line in result.splitlines() if line.startswith("| `")]
    assert rows and all(len(line[2:-2].split(" | ")) == 6 for line in rows)
    historical = next(line for line in rows if "Historical evidence" in line)
    assert "&#124;&#124;" in historical
    assert len(historical.split("|")) == 8
    cells = historical[2:-2].split(" | ")
    assert "&#124;&#124;" in cells[4]
    assert audit["advisories"]["1"]["url"] in cells[5]


def test_documented_caller_covers_reusable_workflow_permissions():
    caller = yaml.safe_load((ROOT / "node/repair-caller.yml").read_text())
    workflow = yaml.safe_load((ROOT / ".github/workflows/node-repair.yml").read_text())
    job = caller["jobs"]["repair"]
    for reusable in workflow["jobs"].values():
        for scope, level in reusable["permissions"].items():
            assert (
                job["permissions"][scope] == "write"
                or level == job["permissions"][scope]
            )
    assert set(job["with"]) == set(workflow["on"]["workflow_call"]["inputs"])


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_selected_policy_edit_preserves_original_line_endings(newline):
    original = (
        "packages:\n  - .\noverrides:\n  launch-editor: 2.14.1 # retained comment\n"
    ).replace("\n", newline)
    updated = REPAIR["update_policy"](original, [ITEM])
    assert updated == original.replace("2.14.1", '"2.14.2"')


def test_preparation_upload_notice_is_after_immutable_upload():
    workflow = yaml.safe_load((ROOT / ".github/workflows/node-repair.yml").read_text())
    action = yaml.safe_load((ROOT / "node/repair/action.yml").read_text())
    producer = workflow["jobs"]["prepare"]
    assert producer["name"] == "Node repair preparation"
    assert producer["permissions"] == {
        "contents": "read",
        "actions": "read",
        "checks": "read",
    }
    seal = producer["steps"][-1]
    assert seal["name"] == "Seal uploaded repair evidence"
    assert "Node repair evidence v1" in seal["run"]
    assert (
        seal["env"]["ARTIFACT_ID"]
        == "${{ steps.prepare.outputs.candidate-artifact-id }}"
    )
    assert (
        action["outputs"]["candidate-archive-sha256"]["value"]
        == "${{ steps.candidate.outputs.artifact-digest }}"
    )
    steps = action["runs"]["steps"]
    assert next(
        i for i, s in enumerate(steps) if s.get("id") == "report-digest"
    ) < next(i for i, s in enumerate(steps) if s.get("id") == "candidate")
    assert workflow["jobs"]["validate"]["permissions"] == {"contents": "read"}


def encoded_workflow(jobs):
    import base64

    return {
        "type": "file",
        "encoding": "base64",
        "content": base64.b64encode(yaml.safe_dump({"jobs": jobs}).encode()).decode(),
    }


@pytest.mark.parametrize(
    "copied_name",
    ["attacker / Node repair preparation", "repair / Node repair preparation"],
)
def test_sibling_cannot_copy_producer_names_and_steps(
    repair_history_provider, copied_name
):
    locator, repo, source, project, state, workflow, data, record = (
        repair_history_provider
    )
    candidate = data["actions/jobs/20"]
    genuine = dict(candidate, id=21)
    candidate["name"] = copied_name
    data["actions/runs/10/attempts/1/jobs?per_page=100"] = {
        "total_count": 2,
        "jobs": [candidate, genuine],
    }
    data["contents/.github/workflows/fixture.yml?ref=" + "e" * 40] = encoded_workflow(
        {
            "repair": {
                "uses": data["actions/runs/10"]["referenced_workflows"][0]["path"]
            },
            "attacker": {"name": copied_name, "steps": []},
        }
    )
    with pytest.raises(ValueError):
        REPAIR["verify_repair_history"](locator, repo, source, project, state, workflow)


def test_same_package_history_qualifies_each_advisory_identity(cumulative_candidate):
    root, before, after, initial, proof, report = cumulative_candidate
    old_id = repair_audit()["advisories"]["1"]["url"].rsplit("/", 1)[-1]
    old_row = next(
        line
        for line in report.splitlines()
        if "Historical evidence (attempt 1)" in line
    )
    assert "Not observed in the current audit." in old_row
    assert f"Advisories: `{old_id}`" in old_row
    assert "Current unresolved." not in old_row
    # Another current advisory for the same package is not old-advisory proof.
    pending = REPAIR["cumulative_report"](
        initial, repair_request(), root, {}, before, after, proof, proof, set()
    )
    old_row = next(
        line
        for line in pending.splitlines()
        if "Historical evidence (attempt 1)" in line
    )
    assert "Not observed in the current audit." in old_row
    assert "Current unresolved." not in old_row
    # Reintroduction of the exact old identity is current unresolved evidence.
    old = repair_audit()
    reintroduced = REPAIR["cumulative_report"](
        initial, repair_request(), root, {}, before, after, old, old, set()
    )
    old_row = next(
        line
        for line in reintroduced.splitlines()
        if "Historical evidence (attempt 1)" in line
    )
    assert "Current unresolved." in old_row and "Not observed" not in old_row


@pytest.mark.parametrize("extra_commit", [False, True])
def test_full_checkout_resolves_native_receipt_at_or_below_head(
    sealed_checkout, monkeypatch, tmp_path, extra_commit
):
    root, _, snapshot, expected = sealed_checkout
    trailers = (
        "\n".join(
            f"Node-Audit-{k.replace('_', '-')}: {v}"
            for k, v in dict(
                run=1,
                job=2,
                check=3,
                artifact=4,
                archive_sha256="a" * 64,
                content_sha256="b" * 64,
            ).items()
        )
        + "\nNode-Audit-Workflow-SHA: "
        + "f" * 40
    )

    def commit(message):
        subprocess.run(
            [
                "git",
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.com",
                "commit",
                "--allow-empty",
                "-qm",
                message,
            ],
            check=True,
        )

    commit("Receipt\n\n" + trailers)
    receipt_parent = REPAIR["git"]("rev-parse", "HEAD^").strip()
    if extra_commit:
        commit("Unrelated maintainer commit")
    clone = tmp_path / "shallow"
    subprocess.run(
        ["git", "clone", "-q", "--depth=1", root.as_uri(), str(clone)], check=True
    )
    monkeypatch.chdir(clone)
    assert REPAIR["git"]("rev-parse", "--is-shallow-repository").strip() == "true"
    # actions/checkout fetch-depth:0 fetches the complete ancestry.
    workflow = yaml.safe_load((ROOT / ".github/workflows/node-repair.yml").read_text())
    assert workflow["jobs"]["prepare"]["steps"][0]["with"]["fetch-depth"] == 0
    subprocess.run(["git", "fetch", "-q", "--unshallow", "origin"], check=True)
    expected = dict(expected, head=REPAIR["git"]("rev-parse", "HEAD").strip())
    module = REPAIR["native_history"].__globals__
    monkeypatch.setitem(
        module,
        "producer_names",
        lambda *args: ["audit / Node audit evidence (node-security)"],
    )
    monkeypatch.setitem(
        module["ENGINE"],
        "history_api",
        lambda *args, **kw: {"name": "audit / Node audit evidence (node-security)"},
    )
    calls = []

    def verify(locator, **kwargs):
        calls.append(kwargs)
        return normal_history(snapshot)

    monkeypatch.setitem(module["ENGINE"], "verify_history", verify)
    REPAIR["native_history"](expected, clone, snapshot)
    assert calls[0]["source"] == receipt_parent


@pytest.fixture
def publisher_checkout(sealed_checkout, monkeypatch, tmp_path):
    root, artifact, before, expected = sealed_checkout
    remote = tmp_path / "origin.git"
    subprocess.run(["git", "init", "--bare", "-q", str(remote)], check=True)
    git = REPAIR["git"]
    git("remote", "add", "origin", str(remote))
    git("push", "origin", "HEAD:refs/heads/maintenance/node-security")
    body = (
        "## Platform security\n\nNode upgrade evidence stays unchanged.\n\n"
        "## Package security\n\nOld package report\n"
        + CHOICES["render"]([ITEM], head=expected["head"], base=expected["base"])
    ).replace("- [ ]", "- [x]")
    state = dict(body=body, base=expected["base"], updates=[], reads=0)
    repository = dict(id=1, full_name=expected["repository"], default_branch="main")

    def remote_head():
        return subprocess.check_output(
            [
                "git",
                "--git-dir",
                str(remote),
                "rev-parse",
                "refs/heads/maintenance/node-security",
            ],
            text=True,
        ).strip()

    def advance_remote():
        commit = subprocess.check_output(
            [
                "git",
                "-c",
                "user.name=Maintainer",
                "-c",
                "user.email=m@example.invalid",
                "commit-tree",
                git("rev-parse", "HEAD^{tree}").strip(),
                "-p",
                expected["head"],
            ],
            input="Maintainer concurrent work\n",
            text=True,
        ).strip()
        git("push", "origin", f"{commit}:refs/heads/maintenance/node-security")
        return commit

    def api(path, *, body=None):
        if path == f"repos/{expected['repository']}":
            return repository
        assert path == f"repos/{expected['repository']}/pulls/{expected['pr']}"
        if body is not None:
            if state.get("edit_failure"):
                raise subprocess.CalledProcessError(1, ["gh", "api"])
            state["updates"].append(body["body"])
            state["body"] = body["body"]
            return {}
        state["reads"] += 1
        response = dict(
            number=expected["pr"],
            state="open",
            user={"type": "Bot"},
            body=state["body"],
            head=dict(
                ref="maintenance/node-security", sha=remote_head(), repo=repository
            ),
            base=dict(ref="main", sha=state["base"], repo=repository),
        )
        if state.get("lease_race") and state["reads"] == 2:
            state["concurrent_commit"] = advance_remote()
        return response

    module = REPAIR["publish"].__globals__
    monkeypatch.setitem(module, "gh", api)

    def context(*, verify_runtime=True):
        assert not verify_runtime, "Publisher must not execute a package manager"
        return root, {}, before

    monkeypatch.setitem(module, "project_context", context)
    monkeypatch.setitem(
        module["ENGINE"], "run", lambda *a, **k: pytest.fail("Project command executed")
    )
    monkeypatch.setenv("GH_TOKEN", "fixture-no-real-token")
    monkeypatch.setenv("GITHUB_RUN_ID", "123")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(tmp_path / "summary.md"))
    candidate = repair_files(root, ITEM["to"])
    report = REPAIR["cumulative_report"](
        normal_history(before),
        expected,
        root,
        {},
        before,
        candidate,
        repair_audit(),
        empty_audit(),
        ENGINE["finding_ids"](repair_audit(), "pnpm"),
    )
    subprocess.run(["git", "checkout", "--", "."], check=True)
    (artifact / "result.md").write_text(report)
    import hashlib

    locator = dict(
        run=123,
        job=20,
        check=30,
        artifact=40,
        archive_sha256="a" * 64,
        content_sha256=hashlib.sha256(report.encode()).hexdigest(),
    )
    record = ENGINE["history_record"](report.encode())
    state.update(record=record, locator=locator, report=report)
    monkeypatch.setitem(
        module,
        "publication_locator",
        lambda value: locator if value == expected else pytest.fail("Request changed"),
    )

    def verified(loc, repo, source, project, hashes, workflow):
        assert (loc, repo, source, project, hashes, workflow) == (
            locator,
            expected["repository"],
            expected["head"],
            ".",
            record["candidate_state"],
            "f" * 40,
        )
        REPAIR["validate_history"](record)
        return record

    monkeypatch.setitem(module, "verify_repair_history", verified)
    monkeypatch.setenv("TRUSTED_WORKFLOW_SHA", "f" * 40)
    hook = root / ".git/hooks/pre-commit"
    marker = tmp_path / "commit-hook-executed"
    hook.write_text(f"#!/bin/sh\ntouch {shlex.quote(str(marker))}\nexit 1\n")
    hook.chmod(0o755)
    return root, artifact, expected, state, remote_head, advance_remote, marker


def test_publisher_commits_only_sealed_files_without_project_execution(
    publisher_checkout,
):
    root, artifact, expected, state, remote_head, _, marker = publisher_checkout
    sealed = {p.name: p.read_bytes() for p in artifact.iterdir()}
    commit = REPAIR["publish"](expected, artifact)
    assert remote_head() == commit != expected["head"]
    assert REPAIR["git"]("rev-parse", "HEAD^").strip() == expected["head"]
    assert set(REPAIR["git"]("diff", "--name-only", "HEAD^", "HEAD").splitlines()) == {
        "pnpm-lock.yaml",
        "pnpm-workspace.yaml",
    }
    assert "Node-Repair: validated-selected-pins-v1" in REPAIR["git"](
        "log", "-1", "--format=%B"
    )
    assert "Node-Repair-run: 123" in REPAIR["git"]("log", "-1", "--format=%B")
    assert "Node-Repair-artifact: 40" in REPAIR["git"]("log", "-1", "--format=%B")
    assert "Node-Repair-Workflow-SHA: " + "f" * 40 in REPAIR["git"](
        "log", "-1", "--format=%B"
    )
    assert not marker.exists()
    assert not REPAIR["git"]("status", "--porcelain").strip()
    assert len(state["updates"]) == 1
    body = state["updates"][0]
    assert body.startswith(
        "## Platform security\n\nNode upgrade evidence stays unchanged.\n\n"
    )
    assert "✅ Upgraded." in body and "Historical evidence (attempt 1)" in body
    assert "Project validation has not run" not in body
    assert "actions/runs/123" in body and commit in body
    assert CHOICES["revision_marker"](commit, expected["base"]) in body
    assert {p.name: p.read_bytes() for p in artifact.iterdir()} == sealed
    assert "were published" in body


@pytest.mark.parametrize(
    "problem", ["head", "base", "selection", "lease", "bad-report"]
)
def test_publisher_rejects_stale_consent_and_native_push_lease_conflicts(
    publisher_checkout, problem
):
    root, artifact, expected, state, remote_head, advance_remote, marker = (
        publisher_checkout
    )
    previous = expected["head"]
    if problem == "head":
        previous = advance_remote()
    elif problem == "base":
        state["base"] = "c" * 40
    elif problem == "selection":
        state["body"] = state["body"].replace("- [x]", "- [ ]")
    elif problem == "lease":
        state["lease_race"] = True
    elif problem == "bad-report":
        (artifact / "result.md").write_text("Unbound forged validation success")
    with pytest.raises((ValueError, subprocess.CalledProcessError)):
        REPAIR["publish"](expected, artifact)
    assert remote_head() == state.get("concurrent_commit", previous)
    assert not state["updates"] and not marker.exists()
    summary = Path(os.environ["GITHUB_STEP_SUMMARY"]).read_text()
    assert "No repair push was attempted" in summary or "inspect the branch" in summary
    assert "were published" not in summary


def test_publisher_reports_push_success_and_body_failure_as_partial(publisher_checkout):
    root, artifact, expected, state, remote_head, _, marker = publisher_checkout
    state["edit_failure"] = True
    original_body = state["body"]
    with pytest.raises(subprocess.CalledProcessError):
        REPAIR["publish"](expected, artifact)
    assert (
        remote_head() == REPAIR["git"]("rev-parse", "HEAD").strip() != expected["head"]
    )
    assert state["body"] == original_body and not state["updates"]
    summary = Path(os.environ["GITHUB_STEP_SUMMARY"]).read_text()
    assert "was published" in summary and "report update is incomplete" in summary
    assert "No repair push was attempted" not in summary and not marker.exists()


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_publication_body_preserves_platform_bytes_and_frozen_cumulative_rows(
    cumulative_candidate, monkeypatch, newline
):
    _, _, _, _, _, report = cumulative_candidate
    monkeypatch.setenv("GITHUB_RUN_ID", "123")
    platform = (
        "## Platform security\n\n✅ Node.js `24.21.0 → 24.22.1`.\n\n"
        "| Security release | CVE summary |\n| --- | --- |\n"
        "| 24.22.1 | [CVE list](https://nodejs.org/en/blog/release/v24.22.1/) |\n\n"
    ).replace("\n", newline)
    previous = (
        platform + "## Package security" + newline + "FORGED OLD PACKAGE EVIDENCE"
    )
    body = REPAIR["publication_body"](
        previous, report, repair_request(), "c" * 40, envelope()
    )
    assert body.startswith(platform)
    assert "FORGED OLD PACKAGE EVIDENCE" not in body
    assert "Historical evidence (attempt 1)" in body
    assert "Not observed in the current audit" in body
    assert "across 2 attempts" in body and "2 advisory/package pairs" in body
    assert "GHSA-fresh-one1-test" in body
    assert "node-audit-history:v1:" not in body
    assert body.count("| Package |") == 1
    assert "Selected repairs passed frozen installation" in body
    assert CHOICES["revision_marker"]("c" * 40, repair_request()["base"]) in body


@pytest.mark.parametrize(
    "platform",
    [
        "",
        "## PLATFORM SECURITY\nUnknown format\n",
        "## Platform security\nfirst\n## Platform security\nsecond\n",
    ],
)
def test_publisher_refuses_missing_or_ambiguous_platform_before_push(
    publisher_checkout, platform
):
    _, artifact, expected, state, remote_head, _, marker = publisher_checkout
    state["body"] = (
        platform
        + "## Package security\n"
        + CHOICES["render"](
            [ITEM], head=expected["head"], base=expected["base"]
        ).replace("- [ ]", "- [x]")
    )
    with pytest.raises(ValueError, match="platform report"):
        REPAIR["publish"](expected, artifact)
    assert (
        remote_head() == expected["head"]
        and not state["updates"]
        and not marker.exists()
    )


@pytest.mark.parametrize("problem", ["report-bytes", "before-proof", "missing-history"])
def test_publisher_rejects_modified_or_incomplete_sealed_evidence(
    publisher_checkout, problem
):
    _, artifact, expected, state, remote_head, _, marker = publisher_checkout
    if problem == "report-bytes":
        path = artifact / "result.md"
        path.write_bytes(
            path.read_bytes().replace(
                b"Historical evidence", b"Forged historical evidence", 1
            )
        )
    elif problem == "before-proof":
        state["record"]["attempts"][-1]["before"]["metadata"]["forged"] = (
            "not original proof"
        )
    else:
        record = state["record"]
        record.pop("attempts")
    with pytest.raises((ValueError, KeyError)):
        REPAIR["publish"](expected, artifact)
    assert (
        remote_head() == expected["head"]
        and not state["updates"]
        and not marker.exists()
    )


def test_ambiguous_native_push_requires_inspection_without_retry(
    publisher_checkout, monkeypatch
):
    _, artifact, expected, state, remote_head, _, _ = publisher_checkout
    actual = subprocess.run
    pushes = []

    def uncertain(command, **kwargs):
        if command[:4] == ["git", "-c", "core.hooksPath=/dev/null", "push"]:
            pushes.append(command)
            actual(command, **kwargs)
            raise subprocess.TimeoutExpired(command, 1)
        return actual(command, **kwargs)

    monkeypatch.setattr(subprocess, "run", uncertain)
    with pytest.raises(subprocess.TimeoutExpired):
        REPAIR["publish"](expected, artifact)
    assert len(pushes) == 1 and remote_head() != expected["head"]
    assert not state["updates"]
    summary = Path(os.environ["GITHUB_STEP_SUMMARY"]).read_text()
    assert remote_head() in summary and "inspect the branch" in summary
    assert "No repair push was attempted" not in summary


@pytest.mark.parametrize(
    "problem",
    [None, "artifact", "attempt", "duplicate", "job-url", "sibling", "missing-history"],
)
def test_publication_locator_requires_current_original_preparation(
    repair_history_provider, monkeypatch, problem
):
    locator, repo, _, _, _, workflow, data, _ = repair_history_provider
    monkeypatch.setenv("GITHUB_RUN_ID", "10")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
    monkeypatch.setenv("REPAIR_ARTIFACT_ID", "40")
    monkeypatch.setenv("TRUSTED_WORKFLOW_SHA", workflow)
    if problem == "artifact":
        monkeypatch.setenv("REPAIR_ARTIFACT_ID", "41")
    elif problem == "attempt":
        data["actions/runs/10"]["run_attempt"] = 2
    elif problem == "duplicate":
        data["check-runs/30/annotations?per_page=100"] *= 2
    elif problem == "job-url":
        data["actions/jobs/20"]["check_run_url"] = "https://evil.invalid/30"
    elif problem == "sibling":
        data["actions/jobs/20"]["name"] = "Sibling forgery"
    elif problem == "missing-history":
        data["check-runs/30/annotations?per_page=100"] = []
    if problem:
        with pytest.raises(ValueError):
            REPAIR["publication_locator"](repair_request())
    else:
        assert REPAIR["publication_locator"](repair_request()) == locator


@pytest.mark.parametrize(
    "change",
    ["head", "base", "body", "state", "head-ref", "base-ref", "head-repo", "base-repo"],
)
def test_publisher_retains_successful_push_when_pr_changes_before_body_edit(
    publisher_checkout, monkeypatch, change
):
    _, artifact, expected, state, remote_head, _, _ = publisher_checkout
    module = REPAIR["publish"].__globals__
    original = module["gh"]

    def changed(path, **kwargs):
        value = original(path, **kwargs)
        if (
            path.endswith(f"/pulls/{expected['pr']}")
            and not kwargs
            and state["reads"] == 3
        ):
            value = json.loads(json.dumps(value))
            if change == "head":
                value["head"]["sha"] = "e" * 40
            elif change == "base":
                value["base"]["sha"] = "e" * 40
            elif change == "body":
                value["body"] += "Maintainer edit after push"
            elif change == "state":
                value["state"] = "closed"
            elif change.endswith("-ref"):
                value[change.split("-")[0]]["ref"] = "different-branch"
            else:
                value[change.split("-")[0]]["repo"]["id"] = 2
        return value

    monkeypatch.setitem(module, "gh", changed)
    monkeypatch.setattr(
        module["time"], "sleep", lambda _: pytest.fail("Waited on changed PR")
    )
    with pytest.raises(ValueError, match="PR state differs after repair push"):
        REPAIR["publish"](expected, artifact)
    assert remote_head() != expected["head"] and not state["updates"]
    summary = Path(os.environ["GITHUB_STEP_SUMMARY"]).read_text()
    assert remote_head() in summary and "report update is incomplete" in summary


@pytest.mark.parametrize("stale_reads", [1, 3, 4])
def test_publisher_waits_only_for_exact_pre_push_view_without_another_push(
    publisher_checkout, monkeypatch, stale_reads
):
    _, artifact, expected, state, remote_head, _, marker = publisher_checkout
    module = REPAIR["publish"].__globals__
    original_api = module["gh"]
    original_run = module["subprocess"].run
    delays, pushes = [], []

    def api(path, **kwargs):
        value = original_api(path, **kwargs)
        if (
            path.endswith(f"/pulls/{expected['pr']}")
            and not kwargs
            and 3 <= state["reads"] <= 2 + stale_reads
        ):
            value["head"]["sha"] = expected["head"]
        return value

    def run(arguments, *args, **kwargs):
        if arguments[0] == "git" and "push" in arguments:
            pushes.append(arguments)
        return original_run(arguments, *args, **kwargs)

    monkeypatch.setitem(module, "gh", api)
    monkeypatch.setattr(module["time"], "sleep", delays.append)
    monkeypatch.setattr(module["subprocess"], "run", run)
    if stale_reads < 4:
        commit = REPAIR["publish"](expected, artifact)
        assert remote_head() == commit and len(state["updates"]) == 1
    else:
        with pytest.raises(ValueError, match="PR state differs after repair push"):
            REPAIR["publish"](expected, artifact)
        assert not state["updates"]
        summary = Path(os.environ["GITHUB_STEP_SUMMARY"]).read_text()
        assert remote_head() in summary and "report update is incomplete" in summary
    assert len(pushes) == 1 and remote_head() != expected["head"]
    assert delays == ([1] if stale_reads == 1 else [1, 2, 4])
    assert (
        len(
            REPAIR["git"](
                "rev-list", f"{expected['head']}..{remote_head()}"
            ).splitlines()
        )
        == 1
    )
    assert not marker.exists()


@pytest.mark.parametrize(
    "problem", ["demoted-headings", "controls-in-platform", "missing-package-boundary"]
)
def test_publisher_rejects_unrecognized_platform_boundary_before_native_push(
    publisher_checkout, problem
):
    _, artifact, expected, state, remote_head, _, marker = publisher_checkout
    body = state["body"]
    if problem == "demoted-headings":
        body = body.replace("## Package security\n", "### Package security\n").replace(
            "## Choose fixes to try\n", "### Choose fixes to try\n"
        )
    elif problem == "missing-package-boundary":
        body = body.replace("## Package security\n", "")
    else:
        platform = body.split("## Package security\n", 1)[0]
        choices = CHOICES["render"](
            [ITEM], head=expected["head"], base=expected["base"]
        ).replace("- [ ]", "- [x]")
        body = (
            platform
            + choices.replace("## Choose fixes to try", "### Choose fixes to try")
            + "\n## Package security\nOld packages\n"
        )
    state["body"] = body
    assert REPAIR["guard"](expected)["body"] == body
    with pytest.raises(ValueError, match="platform report"):
        REPAIR["publish"](expected, artifact)
    assert remote_head() == expected["head"]
    assert not state["updates"] and not marker.exists()
    summary = Path(os.environ["GITHUB_STEP_SUMMARY"]).read_text()
    assert "No repair push was attempted" in summary
