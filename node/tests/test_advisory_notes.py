"""Maintainer context persists without suppressing findings or duplicating history."""

import copy
import json
import runpy
import subprocess
import sys
from pathlib import Path

import pytest
from test_local_patches import evidence
from test_dependency_audit_publisher import prepared_validation as prepared_validation
from test_dependency_audit_publisher import sealed_history as sealed_history
from test_node_standard import audit_module
from test_node_standard import npm_project as npm_project
from test_node_standard import pnpm_project as pnpm_project
from test_selected_repairs import ENGINE, REPAIR, repair_audit, repair_request
from test_selected_repairs import cumulative_candidate as cumulative_candidate
from test_shared_defaults import configure, configuration, public_sources
from test_shared_defaults import site as site

ROOT = Path(__file__).parents[2]
NOTES = runpy.run_path(str(ROOT / "node/runtime/advisory_notes.py"))
ID = "GHSA-2345-6789-cfgh"
TEXT = "Deferred pending an upstream release; revisit before enabling workers."


@pytest.mark.parametrize(
    "value",
    [
        None,
        [],
        "text",
        {"CVE-2026-1234": TEXT},
        {ID: None},
        {ID: 1},
        {ID: ""},
        {ID: "  "},
        {ID: "x" * 2049},
        {ID: "two\nlines"},
        {ID: "two\rlines"},
        {ID: "tab\there"},
        {ID: "\x7f"},
        {ID: "\ud800"},
        {ID: "\u0085"},
        {ID: "\u2028"},
        {ID: "\u2029"},
        {f"GHSA-aaaa-bbbb-{i:04d}": TEXT for i in range(33)},
    ],
)
def test_invalid_notes_fail_configuration_validation(value):
    with pytest.raises(ValueError, match="advisoryNotes"):
        configuration["validate_settings"]({"advisoryNotes": value}, "project")


def test_valid_limits_and_duplicate_key_rejection():
    value = {f"GHSA-aaaa-bbbb-{i:04d}": "🧪" * 2048 for i in range(32)}
    assert NOTES["validate"](value) == value
    with pytest.raises(ValueError, match="duplicate JSON key"):
        configuration["json_object"](
            ('{"advisoryNotes":{"' + ID + '":"first","' + ID + '":"second"}}').encode(),
            "project",
        )


@pytest.mark.parametrize("local", [False, True])
def test_notes_are_project_local_and_not_inherited(site, monkeypatch, local):
    root, _ = site
    public_sources(
        monkeypatch,
        {
            ("owner/settings", "defaults.json"): {
                "advisoryNotes": {ID: "Other project's decision."}
            }
        },
    )
    if local:
        configure(root, advisoryNotes={ID: TEXT})
    result = configuration["load_configuration"](root)
    assert result.get("advisoryNotes", {}) == ({ID: TEXT} if local else {})


@pytest.mark.parametrize("source", ["npm", "pnpm"])
def test_render_exact_active_advisories_once_without_mutating_evidence(source):
    data = evidence(source)
    data["vulnerabilities"]["duplicate-parent"] = copy.deepcopy(
        data["vulnerabilities"]["renderer"]
    )
    original = copy.deepcopy(data)
    notes = {ID: TEXT, "GHSA-aaaa-bbbb-cccc": "Not currently reported."}
    rendered = NOTES["render"](data, notes)
    assert rendered.count(TEXT) == rendered.count(ID) == 1
    assert "Not currently reported" not in rendered
    assert data == original
    assert NOTES["render"]("Audit unavailable", notes) == ""
    for url in (
        "https://example.com/" + ID,
        "https://github.com/advisories/" + ID + "-extra",
    ):
        for vulnerability in data["vulnerabilities"].values():
            vulnerability["via"][0]["url"] = url
        assert NOTES["render"](data, notes) == ""


def test_note_markup_cannot_add_controls_tables_or_hidden_history():
    text = "<!-- node-audit-history:v1 --> <script>x</script> [x](https://example.com) | `fix` ![image](x) &amp;"
    result = NOTES["render"](evidence(), {ID: text})
    assert "<!--" not in result and "<script>" not in result
    assert "[x]" not in result and "|" not in result and "`" not in result
    assert "&lt;script&gt;" in result and "&amp;amp;" in result


@pytest.mark.parametrize(
    "fixture,source", [("npm_project", "npm"), ("pnpm_project", "pnpm")]
)
def test_actual_audit_report_notes_leave_validation_and_findings_unchanged(
    request, monkeypatch, fixture, source
):
    root = request.getfixturevalue(fixture)
    engine = audit_module["prepare"].__globals__
    data = evidence(source)
    data["vulnerabilities"]["renderer"]["fixAvailable"] = False
    original = copy.deepcopy(data)
    monkeypatch.setitem(engine, "audit", lambda *a, **kw: copy.deepcopy(data))
    monkeypatch.setitem(
        engine,
        "fix_security",
        lambda *a, **kw: subprocess.CompletedProcess([], 0, "", ""),
    )
    for name in ("describe_npm_fixes", "describe_pnpm_fixes"):
        monkeypatch.setitem(engine, name, lambda *a, **kw: None)
    monkeypatch.setitem(
        engine, "run", lambda *a, **kw: subprocess.CompletedProcess([], 0, "", "")
    )
    baseline, noted = {}, {}
    audit_module["prepare"](root, maintenance_mode="security-only", validation=baseline)
    report = audit_module["prepare"](
        root,
        maintenance_mode="security-only",
        advisory_notes={ID: TEXT},
        validation=noted,
    )
    assert noted == baseline
    assert report.count(TEXT) == 1
    assert "Maintainer notes" in report and "high: 1" in report
    assert data == original


def test_separate_validation_runner_reloads_project_notes(
    prepared_validation, monkeypatch
):
    command, record, _, report, _, output, *_ = prepared_validation
    root = Path.cwd()
    (root / ".github").mkdir()
    (root / ".github/node-maintenance.json").write_text(
        json.dumps({"advisoryNotes": {ID: TEXT}})
    )
    engine = runpy.run_path(str(ROOT / "node/runtime/templates/dependency_audit.py"))
    original = report.read_text()

    def prepare(directory, **kwargs):
        assert kwargs["advisory_notes"] == {ID: TEXT}
        kwargs["validation"].update(passed=True, audit_errors=[])
        return original

    monkeypatch.setitem(engine["main"].__globals__, "prepare", prepare)
    monkeypatch.setattr(sys, "argv", command[1:] + ["--github-output", str(output)])
    engine["main"]()
    assert engine["history_record"](report.read_bytes()) == record


def test_cumulative_repair_keeps_notes_out_of_each_retained_attempt(
    cumulative_candidate,
):
    root, before, after, initial, proof, _ = cumulative_candidate
    data = repair_audit()
    advisory = data["vulnerabilities"]["launch-editor"]["via"][0]["url"].rsplit("/", 1)[
        -1
    ]
    baseline = REPAIR["cumulative_report"](
        initial, repair_request(), root, {}, before, after, proof, data, set()
    )
    noted = REPAIR["cumulative_report"](
        initial,
        repair_request(),
        root,
        {},
        before,
        after,
        proof,
        data,
        set(),
        advisory_notes={advisory: TEXT},
    )
    assert noted.count(TEXT) == 1
    assert ENGINE["history_record"](noted.encode()) == ENGINE["history_record"](
        baseline.encode()
    )
    assert TEXT not in json.dumps(ENGINE["history_record"](noted.encode()))
