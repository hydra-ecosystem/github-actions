import copy
import json
import os
import runpy
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

ROOT = Path(__file__).parents[2]
REPAIR = runpy.run_path(str(ROOT / "node/runtime/repair.py"))
GLOBALS = REPAIR["prepare"].__globals__
CHOICES = REPAIR["CHOICES"]
ITEMS = [{"name": "launch-editor", "from": "2.14.1", "to": "2.14.2"}]


def snapshot(version="2.14.1"):
    lock = {
        "lockfileVersion": "9.0",
        "importers": {".": {}},
        "overrides": {"launch-editor": version},
        "packages": {
            f"launch-editor@{version}": {"resolution": {"integrity": version}},
            "parent@1.0.0": {"resolution": {"integrity": "parent"}},
        },
        "snapshots": {
            "parent@1.0.0": {"dependencies": {"launch-editor": version}},
            f"launch-editor@{version}": {},
        },
    }
    policy = {
        "packages": ["."],
        "minimumReleaseAge": 14400,
        "overrides": {"launch-editor": version},
    }
    return (
        b'{"name":"test","scripts":{"build":"true"}}',
        {
            "pnpm-workspace.yaml": yaml.safe_dump(policy).encode(),
            "pnpm-lock.yaml": yaml.safe_dump(lock).encode(),
        },
        {},
        {
            "packages": {
                f"launch-editor@{version}": {
                    "name": "launch-editor",
                    "version": version,
                },
                "parent@1.0.0": {"name": "parent", "version": "1.0.0"},
            }
        },
    )


def data():
    return {
        "package_manager": "pnpm",
        "vulnerabilities": {
            "launch-editor": {
                "severity": "high",
                "via": [
                    {
                        "url": "https://github.com/advisories/GHSA-example",
                        "title": "Example advisory",
                        "range": "<2.14.2",
                        "severity": "high",
                        "fixStatus": "Published patch: `launch-editor@2.14.2`. Blocked by retained override `pnpm-workspace.yaml overrides.launch-editor` = `2.14.1`. Override preserved for manual compatibility review.",
                    }
                ],
            }
        },
        "metadata": {"vulnerabilities": {"high": 1}},
    }


def test_consent_is_exact_and_shared_with_the_renderer():
    body = CHOICES["render"](ITEMS)
    assert "have not been tested" in body
    assert CHOICES["parse"](body.replace("[ ]", "[x]")) == ITEMS
    for text in (
        body,
        body + body,
        body.replace("2.14.2", "3.0.0"),
        body.replace("Allow", "Run"),
    ):
        with pytest.raises(ValueError):
            CHOICES["parse"](text)


def test_candidates_require_all_advisories_to_have_the_same_compatible_patch():
    finding = data()
    assert CHOICES["candidates"](finding) == ITEMS
    finding["vulnerabilities"]["launch-editor"]["via"].append(
        {"fixStatus": "No patched version declared by the registry."}
    )
    assert CHOICES["candidates"](finding) == []


def test_policy_edit_preserves_comments_and_unrelated_settings():
    text = '# security policy\nminimumReleaseAge: 14400\noverrides:\n  launch-editor: "2.14.1" # retained pin\n  other: "1.0.0"\n'
    result = REPAIR["update_policy"](text, ITEMS)
    assert result == text.replace('"2.14.1"', '"2.14.2"')
    for invalid in (
        text.replace("2.14.1", "^2.14.1"),
        text + '  launch-editor: "2.14.1"\n',
    ):
        with pytest.raises(ValueError):
            REPAIR["update_policy"](invalid, ITEMS)


def test_scope_accepts_only_selected_pins_and_their_lockfile_edges():
    REPAIR["check_scope"](snapshot(), snapshot("2.14.2"), ITEMS)


@pytest.mark.parametrize(
    "kind", ["dependencies", "devDependencies", "optionalDependencies"]
)
@pytest.mark.parametrize("specifier", ["override", "^2.14.1"])
def test_scope_accepts_selected_direct_importers(kind, specifier):
    before, after = snapshot(), snapshot("2.14.2")
    for state, version in ((before, "2.14.1"), (after, "2.14.2")):
        lock = yaml.safe_load(state[1]["pnpm-lock.yaml"])
        lock["importers"]["packages/app"] = {
            kind: {
                "launch-editor": {
                    "specifier": version if specifier == "override" else specifier,
                    "version": version + "(peer@1.0.0)",
                }
            }
        }
        state[1]["pnpm-lock.yaml"] = yaml.safe_dump(lock).encode()
    REPAIR["check_scope"](before, after, ITEMS)

    # Only the approved version may change; importer fields and peer edges stay bound.
    for field, value in (("specifier", "*"), ("version", "2.14.2(peer@2.0.0)")):
        invalid = copy.deepcopy(after)
        lock = yaml.safe_load(invalid[1]["pnpm-lock.yaml"])
        lock["importers"]["packages/app"][kind]["launch-editor"][field] = value
        invalid[1]["pnpm-lock.yaml"] = yaml.safe_dump(lock).encode()
        with pytest.raises(ValueError, match="unrelated lockfile"):
            REPAIR["check_scope"](before, invalid, ITEMS)


@pytest.mark.parametrize(
    "mutation", ["manifest", "policy", "metadata", "other-version", "wrong-target"]
)
def test_scope_rejects_unapproved_changes(mutation):
    candidate = list(copy.deepcopy(snapshot("2.14.2")))
    if mutation == "manifest":
        candidate[0] = b"{}"
    elif mutation == "policy":
        policy = yaml.safe_load(candidate[1]["pnpm-workspace.yaml"])
        policy["minimumReleaseAge"] = 0
        candidate[1]["pnpm-workspace.yaml"] = yaml.safe_dump(policy).encode()
    elif mutation == "metadata":
        lock = yaml.safe_load(candidate[1]["pnpm-lock.yaml"])
        lock["packages"]["parent@1.0.0"]["resolution"]["integrity"] = "tampered"
        candidate[1]["pnpm-lock.yaml"] = yaml.safe_dump(lock).encode()
    elif mutation == "other-version":
        candidate[3]["packages"]["parent@2.0.0"] = {
            "name": "parent",
            "version": "2.0.0",
        }
    else:
        candidate = snapshot("2.14.3")
    with pytest.raises(ValueError):
        REPAIR["check_scope"](snapshot(), candidate, ITEMS)


def test_folded_assessment_is_under_its_row_and_truthful():
    audit = data()
    audit["vulnerabilities"]["other"] = {
        "severity": "low",
        "via": [
            {
                "url": "https://github.com/advisories/other",
                "severity": "low",
                "fixStatus": "No patched version declared by the registry.",
            }
        ],
    }
    text = REPAIR["ENGINE"]["format_audit_summary"](
        audit, audit, "pnpm", repair_options=ITEMS
    )
    assert (
        text.index("<code>launch-editor</code>")
        < text.index("<details>")
        < text.index("<code>other</code>")
    )
    assert "has not been tested in this run" in text
    assert "Historical rationale has not been collected" in text
    assert "🟡 Needs review." in text and "🔴 Blocked." in text


def test_guard_rejects_changed_consent_or_revisions(monkeypatch):
    env = {
        "GITHUB_REPOSITORY": "example/repo",
        "REPAIR_PR": "1",
        "REPAIR_HEAD": "a" * 40,
        "REPAIR_BASE": "b" * 40,
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    pr = {
        "state": "open",
        "head": {
            "repo": {"full_name": "example/repo"},
            "ref": "maintenance/node-security",
            "sha": "a" * 40,
        },
        "base": {"repo": {"full_name": "example/repo"}, "ref": "main", "sha": "b" * 40},
        "user": {"type": "Bot"},
        "body": CHOICES["render"](ITEMS).replace("[ ]", "[x]"),
    }
    monkeypatch.setitem(
        GLOBALS,
        "gh",
        lambda path: pr if "/pulls/" in path else {"default_branch": "main"},
    )
    assert REPAIR["guard"](ITEMS) == pr
    pr["head"]["sha"] = "c" * 40
    with pytest.raises(ValueError, match="changed"):
        REPAIR["guard"](ITEMS)


@pytest.mark.parametrize("problem", ["parent", "age", "audit"])
def test_unverified_or_young_patch_is_rejected(monkeypatch, tmp_path, problem):
    engine = GLOBALS["ENGINE"]
    initial = snapshot()
    monkeypatch.setitem(engine, "valid_snapshot", lambda _: initial)

    def describe(_directory, proof, *_args, **_kwargs):
        detail = proof["vulnerabilities"]["launch-editor"]["via"][0]
        detail.update(
            fixVersion=None if problem == "parent" else "2.14.2",
            _verifiedPatchedVersions=["2.14.2"],
            _verifiedVulnerableVersions=["2.14.1"],
        )

    monkeypatch.setitem(engine, "describe_pnpm_fixes", describe)
    monkeypatch.setitem(
        engine,
        "run",
        lambda *_a, **_k: SimpleNamespace(
            returncode=0, stdout=json.dumps({"2.14.2": "2099-01-01T00:00:00Z"})
        ),
    )
    with pytest.raises(ValueError):
        REPAIR["verified_targets"](
            tmp_path,
            "unavailable" if problem == "audit" else data(),
            initial,
            ITEMS,
            1000,
            14400,
        )


def test_candidate_preparation_does_not_execute_validation(monkeypatch, tmp_path):
    directory = tmp_path / "website"
    directory.mkdir()
    initial, candidate = snapshot(), snapshot("2.14.2")
    (directory / "pnpm-workspace.yaml").write_bytes(initial[1]["pnpm-workspace.yaml"])
    artifact = tmp_path / "artifacts"
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    (tmp_path / "node-repair-config.json").write_text('{"configuration":{}}')
    monkeypatch.setitem(
        GLOBALS["PROJECT"],
        "resolve_for_run",
        lambda *_a: (
            directory,
            {
                "manager": "pnpm",
                "minimumReleaseAge": 14400,
                "validationScript": "build",
            },
        ),
    )
    monkeypatch.setitem(GLOBALS["PROJECT"], "verify_runtime", lambda *_a: None)
    monkeypatch.setitem(GLOBALS, "verified_targets", lambda *_a: data())
    exported = []
    monkeypatch.setitem(
        GLOBALS, "export_patch", lambda paths: exported.append(paths) or b"candidate"
    )
    engine = GLOBALS["ENGINE"]
    reads = iter([initial, candidate])
    monkeypatch.setitem(engine, "valid_snapshot", lambda _: next(reads, candidate))
    clean = data()
    clean["vulnerabilities"] = {}
    clean["metadata"]["vulnerabilities"] = {}
    audits = iter([data(), clean])
    monkeypatch.setitem(engine, "audit", lambda *_a, **_k: next(audits))
    monkeypatch.setitem(
        engine,
        "confirmed_fixes",
        lambda *_args: {"https://github.com/advisories/GHSA-example"},
    )
    monkeypatch.setitem(engine, "run", lambda *_a, **_k: SimpleNamespace(returncode=0))

    def unexpected(*_args, **_kwargs):
        pytest.fail("Candidate sealing must precede project validation")

    monkeypatch.setitem(engine, "prepare", unexpected)
    REPAIR["prepare"](ITEMS, artifact)
    assert exported == [["website/pnpm-workspace.yaml", "website/pnpm-lock.yaml"]]
    assert (artifact / "candidate/candidate.patch").read_bytes() == b"candidate"
    assert (
        json.loads((artifact / "candidate/audit.json").read_text())["proof"] == data()
    )
    assert not (artifact / "evidence").exists()
    report = (artifact / "candidate/result.md").read_text()
    assert "Candidate audit evidence" in report and "GHSA-example" in report
    assert "Validation job passed" not in report


def test_failed_validation_does_not_create_publishable_evidence(monkeypatch, tmp_path):
    source = tmp_path / "candidate"
    source.mkdir()
    (source / "candidate.patch").write_bytes(b"sealed candidate")
    (source / "audit.json").write_text(json.dumps({"before": data(), "proof": data()}))
    config = tmp_path / "config.json"
    config.write_text('{"configuration":{}}')
    monkeypatch.setitem(
        GLOBALS,
        "project_context",
        lambda: (
            tmp_path,
            {"validationScript": "build", "minimumReleaseAge": 14400},
            snapshot(),
            config,
        ),
    )
    monkeypatch.setattr(subprocess, "run", lambda *_args, **_kwargs: None)
    monkeypatch.setitem(
        GLOBALS["ENGINE"], "valid_snapshot", lambda _: snapshot("2.14.2")
    )

    def failed(_directory, *, validation, **_kwargs):
        validation["passed"] = False
        return "Build failed"

    monkeypatch.setitem(GLOBALS["ENGINE"], "prepare", failed)
    with pytest.raises(ValueError, match="validation failed"):
        REPAIR["validate"](ITEMS, tmp_path)
    assert (tmp_path / "evidence/validation.md").read_text() == "Build failed"
    assert not (tmp_path / "evidence/result.md").exists()
    assert (source / "candidate.patch").read_bytes() == b"sealed candidate"


def test_validation_applies_sealed_candidate_on_fresh_checkout(monkeypatch, tmp_path):
    directory = tmp_path / "website"
    directory.mkdir()
    before, after = snapshot(), snapshot("2.14.2")
    (directory / "package.json").write_bytes(before[0])
    for name, content in before[1].items():
        (directory / name).write_bytes(content)

    def git(*args):
        return subprocess.check_output(["git", *args], cwd=tmp_path)

    git("init", "-q")
    git("config", "user.name", "Test fixture")
    git("config", "user.email", "test@example.invalid")
    git("add", ".")
    git("commit", "-qm", "baseline")
    for name, content in after[1].items():
        (directory / name).write_bytes(content)
    artifact = tmp_path / "artifact"
    source = artifact / "candidate"
    source.mkdir(parents=True)
    sealed = git("diff", "--binary")
    (source / "candidate.patch").write_bytes(sealed)
    (source / "audit.json").write_text(json.dumps({"before": data(), "proof": data()}))
    git("restore", ".")
    config = tmp_path / "config.json"
    config.write_text('{"configuration":{}}')
    monkeypatch.chdir(tmp_path)
    monkeypatch.setitem(
        GLOBALS,
        "project_context",
        lambda: (
            directory,
            {"validationScript": "build", "minimumReleaseAge": 14400},
            before,
            config,
        ),
    )

    def build(_directory, *, validation, **_kwargs):
        assert (directory / "pnpm-lock.yaml").read_bytes() == after[1]["pnpm-lock.yaml"]
        # This runner's local download is mutable. Publication must download the
        # original artifact from the preparation job, never reupload this copy.
        (source / "candidate.patch").write_bytes(b"tampered local download")
        validation["passed"] = True
        return "Frozen install and build passed"

    engine = GLOBALS["ENGINE"]
    monkeypatch.setitem(engine, "prepare", build)
    monkeypatch.setitem(engine, "valid_snapshot", lambda _: after)
    clean = data()
    clean["vulnerabilities"] = {}
    clean["metadata"]["vulnerabilities"] = {}
    monkeypatch.setitem(engine, "audit", lambda *_args, **_kwargs: clean)
    monkeypatch.setitem(
        engine,
        "confirmed_fixes",
        lambda *_args: {"https://github.com/advisories/GHSA-example"},
    )
    monkeypatch.setitem(engine, "describe_pnpm_fixes", lambda *_args: None)
    REPAIR["validate"](ITEMS, artifact)
    assert {path.name for path in (artifact / "evidence").iterdir()} == {
        "validation.md",
    }
    assert (source / "candidate.patch").read_bytes() != sealed


def test_publisher_stops_before_git_when_pr_is_stale(monkeypatch, tmp_path):
    def stale(_items):
        raise ValueError("stale PR")

    monkeypatch.setitem(GLOBALS, "guard", stale)
    calls = []
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: calls.append(args))
    with pytest.raises(ValueError, match="stale"):
        REPAIR["publish"](ITEMS, tmp_path)
    assert calls == []


@pytest.mark.parametrize("driver", ["external", "attribute-command", "textconv"])
def test_patch_export_ignores_repository_diff_helpers(monkeypatch, tmp_path, driver):
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=tmp_path)

    git("init", "-q")
    git("config", "user.name", "Test fixture")
    git("config", "user.email", "test@example.invalid")
    path = tmp_path / "pnpm-lock.yaml"
    path.write_text("validated: before\n")
    (tmp_path / ".gitattributes").write_text("pnpm-lock.yaml diff=untrusted\n")
    git("add", ".")
    git("commit", "-qm", "baseline")
    path.write_text("validated: after\n")
    helper = tmp_path / "untrusted-diff"
    helper.write_text("#!/bin/sh\ntouch helper-ran\nprintf 'forged patch\\n'\n")
    helper.chmod(0o700)
    setting = (
        "diff.external"
        if driver == "external"
        else f"diff.untrusted.{driver.split('-')[-1]}"
    )
    git("config", setting, str(helper))
    # Confirm this repository configuration is executable without the safeguards.
    git("diff", "--ext-diff", "--textconv", "HEAD", "--", path.name)
    assert (tmp_path / "helper-ran").exists()
    (tmp_path / "helper-ran").unlink()
    monkeypatch.chdir(tmp_path)
    patch = REPAIR["export_patch"]([path.name])
    assert not (tmp_path / "helper-ran").exists()
    assert b"+validated: after" in patch and b"forged patch" not in patch
    git("restore", "--", path.name)
    subprocess.run(["git", "apply", "-"], input=patch, cwd=tmp_path, check=True)
    assert path.read_text() == "validated: after\n"


@pytest.mark.parametrize("permitted", [True, False])
def test_direct_manifest_constraint_needs_independent_registry_proof(
    monkeypatch, tmp_path, permitted
):
    initial = list(snapshot())
    initial[2] = {"dependencies": {"launch-editor": "^2.14.1"}}
    engine = GLOBALS["ENGINE"]
    monkeypatch.setitem(engine, "valid_snapshot", lambda _: initial)

    def describe(_directory, proof, *_args, **_kwargs):
        proof["vulnerabilities"]["launch-editor"]["via"][0].update(
            fixVersion="2.14.2",
            _verifiedPatchedVersions=["2.14.2"],
            _verifiedVulnerableVersions=["2.14.1"],
        )

    monkeypatch.setitem(engine, "describe_pnpm_fixes", describe)

    def lookup(_directory, _view, package, field, *_args, **_kwargs):
        if field == "version":
            assert package == "launch-editor@^2.14.1 2.14.2"
            return SimpleNamespace(
                returncode=0, stdout=json.dumps(["2.14.2"] if permitted else [])
            )
        return SimpleNamespace(
            returncode=0, stdout=json.dumps({"2.14.2": "2020-01-01T00:00:00Z"})
        )

    monkeypatch.setitem(engine, "run", lookup)
    if permitted:
        REPAIR["verified_targets"](tmp_path, data(), initial, ITEMS, 1000, 14400)
    else:
        with pytest.raises(ValueError, match="direct manifest constraint"):
            REPAIR["verified_targets"](tmp_path, data(), initial, ITEMS, 1000, 14400)


def test_workflow_has_no_write_credentials_in_validation():
    workflow = yaml.safe_load((ROOT / ".github/workflows/node-repair.yml").read_text())
    jobs = workflow["jobs"]
    assert jobs["prepare"]["env"]["npm_config_ignore_pnpmfile"] == "true"
    assert jobs["prepare"]["env"]["pnpm_config_ignore_pnpmfile"] == "true"
    for name in ("prepare", "validate"):
        assert jobs[name]["permissions"] == {"contents": "read"}
        assert jobs[name]["steps"][0]["with"]["persist-credentials"] is False
    assert jobs["validate"]["needs"] == "prepare"
    assert jobs["publish"]["needs"] == ["prepare", "validate"]
    sealed_id = "${{ needs.prepare.outputs.candidate-artifact-id }}"
    for name in ("validate", "publish"):
        candidate = next(
            step
            for step in jobs[name]["steps"]
            if step.get("with", {}).get("artifact-ids") == sealed_id
        )
        assert candidate["with"]["path"].endswith("/candidate")
    uploads = [
        step
        for step in jobs["validate"]["steps"]
        if "upload-artifact@" in step.get("uses", "")
    ]
    assert len(uploads) == 1 and uploads[0]["with"]["path"].endswith("/evidence/")
    downloads = [
        step
        for step in jobs["publish"]["steps"]
        if "download-artifact@" in step.get("uses", "")
    ]
    assert len(downloads) == 1
    assert downloads[0]["with"]["artifact-ids"] == sealed_id
    assert not any("pull_request_target" in key for key in workflow["on"])


@pytest.mark.parametrize("failure", [None, "metadata", "stale", "lease", "report"])
def test_publisher_with_real_git_preserves_atomic_batch(monkeypatch, tmp_path, failure):
    root, remote, artifact = (
        tmp_path / "repo",
        tmp_path / "remote.git",
        tmp_path / "artifact",
    )
    root.mkdir()
    artifact.mkdir()
    (artifact / "candidate").mkdir()
    (artifact / "evidence").mkdir()
    directory = root / "website"
    directory.mkdir()
    before, after = snapshot(), snapshot("2.14.2")
    (directory / "package.json").write_bytes(before[0])
    for name, content in before[1].items():
        (directory / name).write_bytes(content)

    def git(*args):
        return subprocess.check_output(
            ["git", "-C", str(root), *args], text=True
        ).strip()

    subprocess.run(
        ["git", "init", "--bare", str(remote)], check=True, capture_output=True
    )
    subprocess.run(["git", "init", str(root)], check=True, capture_output=True)
    git("config", "user.name", "Test fixture")
    git("config", "user.email", "test@example.invalid")
    git("add", ".")
    git("commit", "-qm", "baseline")
    head = git("rev-parse", "HEAD")
    git("remote", "add", "origin", str(remote))
    git("push", "-q", "origin", "HEAD:refs/heads/maintenance/node-security")
    for name, content in after[1].items():
        (directory / name).write_bytes(content)
    if failure == "metadata":
        lock = yaml.safe_load((directory / "pnpm-lock.yaml").read_text())
        lock["packages"]["parent@1.0.0"]["resolution"]["integrity"] = "changed"
        (directory / "pnpm-lock.yaml").write_text(yaml.safe_dump(lock))
    (artifact / "candidate/candidate.patch").write_text(git("diff", "--binary") + "\n")
    (artifact / "candidate/result.md").write_text(
        "## Package security\n\nTrusted sealed audit\n"
    )
    (artifact / "evidence/result.md").write_text(
        "Forged validation result https://example.invalid/forged\n"
    )
    # Even a report artifact containing a replacement patch cannot shadow the
    # candidate downloaded separately from the preparation job's artifact ID.
    (artifact / "evidence/candidate.patch").write_bytes(b"forged report-side patch")
    git("restore", ".")
    if failure == "lease":
        git("commit", "--allow-empty", "-qm", "concurrent change")
        newer = git("rev-parse", "HEAD")
        git("push", "-q", "origin", "HEAD:refs/heads/maintenance/node-security")
        git("reset", "--hard", head)
    for key, value in {
        "REPAIR_HEAD": head,
        "REPAIR_PR": "1",
        "GITHUB_REPOSITORY": "test/repo",
        "GITHUB_RUN_ID": "123",
    }.items():
        monkeypatch.setenv(key, value)
    monkeypatch.chdir(root)
    checks = []

    def guard(_items):
        checks.append(True)
        if failure == "stale" and len(checks) == 2:
            raise ValueError("PR changed")
        return {
            "head": {"ref": "maintenance/node-security"},
            "body": "## Platform security\n\nNode evidence retained\n\n## Package security\n\nOld report",
        }

    monkeypatch.setitem(GLOBALS, "guard", guard)
    monkeypatch.setitem(
        GLOBALS["PROJECT"], "project_directory", lambda *_args: (directory, {})
    )
    monkeypatch.setitem(
        GLOBALS["PROJECT"]["CONFIGURATION"], "local_configuration", lambda *_args: {}
    )
    original_run = subprocess.run

    def run(command, **kwargs):
        if command[0] == "gh":
            assert command[1:3] == ["pr", "edit"]
            assert "Node evidence retained" in Path(command[-1]).read_text()
            assert "Trusted sealed audit" in Path(command[-1]).read_text()
            assert "Forged validation result" not in Path(command[-1]).read_text()
            assert "Validation job passed" in Path(command[-1]).read_text()
            if failure == "report":
                raise subprocess.CalledProcessError(1, command)
            return SimpleNamespace(returncode=0)
        return original_run(command, **kwargs)

    monkeypatch.setattr(subprocess, "run", run)
    if failure:
        error_type = (
            subprocess.CalledProcessError
            if failure in ("lease", "report")
            else ValueError
        )
        message = (
            None
            if failure in ("lease", "report")
            else "metadata"
            if failure == "metadata"
            else "PR changed"
        )
        with pytest.raises(error_type, match=message):
            REPAIR["publish"](ITEMS, artifact)
    else:
        REPAIR["publish"](ITEMS, artifact)
    published = subprocess.check_output(
        [
            "git",
            "--git-dir",
            str(remote),
            "rev-parse",
            "refs/heads/maintenance/node-security",
        ],
        text=True,
    ).strip()
    if failure == "lease":
        assert published == newer
    elif failure and failure != "report":
        assert published == head
    else:
        assert published != head
        assert git("rev-parse", "HEAD^") == head
        assert (
            git("log", "-1", "--format=%(trailers:key=Node-Repair,valueonly)")
            == "validated-selected-pins-v1"
        )


@pytest.mark.parametrize("child_commit", [False, True])
def test_normal_publisher_retains_repair_without_pr_body_marker(tmp_path, child_commit):
    root, remote = tmp_path / "repo", tmp_path / "remote.git"
    root.mkdir()
    (root / "website").mkdir()
    for name in ("package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml"):
        (root / "website" / name).write_text("reviewed repair\n")

    def git(*args):
        return subprocess.check_output(
            ["git", "-C", str(root), *args], text=True
        ).strip()

    subprocess.run(
        ["git", "init", "--bare", str(remote)], check=True, capture_output=True
    )
    subprocess.run(
        ["git", "init", "-b", "main", str(root)], check=True, capture_output=True
    )
    git("config", "user.name", "Test fixture")
    git("config", "user.email", "test@example.invalid")
    git("add", ".")
    git("commit", "-qm", "baseline")
    head = git("rev-parse", "HEAD")
    git("remote", "add", "origin", str(remote))
    git("push", "-q", "origin", "HEAD:main")
    (root / "website/pnpm-lock.yaml").write_text("validated selected repair\n")
    git("add", ".")
    git(
        "commit",
        "-qm",
        "Node: apply selected security pin repairs\n\nNode-Repair: validated-selected-pins-v1",
    )
    if child_commit:
        git("commit", "--allow-empty", "-qm", "Maintainer review adjustment")
    repair_head = git("rev-parse", "HEAD")
    git("push", "-q", "origin", "HEAD:maintenance/node-security")
    git("reset", "--hard", head)
    (root / "website/pnpm-lock.yaml").write_text("fresh default-branch audit\n")
    binary = tmp_path / "bin"
    binary.mkdir()
    gh = binary / "gh"
    gh.write_text('#!/bin/sh\ncase "$1:$2" in\npr:list) echo 1;;\n*) exit 3;;\nesac\n')
    gh.chmod(0o755)
    (tmp_path / "dependency-audit-pr.md").write_text("New audit report")
    result = subprocess.run(
        ["bash", str(ROOT / "node/publish/publish.sh")],
        cwd=root,
        env={
            **os.environ,
            "PATH": str(binary) + os.pathsep + os.environ["PATH"],
            "PROPOSAL_KIND": "security",
            "BASE_BRANCH": "main",
            "AUDIT_SHA": head,
            "RUNNER_TEMP": str(tmp_path),
            "VALIDATION_PASSED": "true",
            "PR_FOOTER": "",
            "NPM_PROJECT": "website",
        },
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "retain that batch" in result.stdout
    assert git("rev-parse", "origin/maintenance/node-security") == repair_head
    assert git("diff", "--cached", "--name-only") == ""
