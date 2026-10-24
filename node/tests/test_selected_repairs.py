"""Selection/report contract tests; no repair execution or publication."""

import copy
import json
import runpy
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

ROOT = Path(__file__).parents[2]
CHOICES = runpy.run_path(str(ROOT / "node/runtime/repair_choices.py"))
ENGINE = runpy.run_path(str(ROOT / "node/runtime/templates/dependency_audit.py"))
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
