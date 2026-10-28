"""Selection, candidate and read-only validation contracts; no publication."""

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
    monkeypatch.setitem(fn.__globals__, "valid_snapshot", lambda directory: object())
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
    monkeypatch.setitem(module, "valid_snapshot", lambda directory: object())
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
    assert set(workflow["jobs"]) == {"guard", "prepare", "validate"}
    for job in workflow["jobs"].values():
        assert set(job["permissions"].values()) == {"read"}
        assert any(step.get("uses") == "$/node/repair" for step in job["steps"])
    prepare = workflow["jobs"]["prepare"]
    assert prepare["env"] == REPAIR["HOOK_ENV"]
    checkout = prepare["steps"][0]
    assert checkout["with"] == {
        "ref": "${{ inputs.expected-head }}",
        "persist-credentials": False,
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
    assert validation["steps"][0]["with"] == checkout["with"]
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
    assert "publish" not in workflow["jobs"]


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
