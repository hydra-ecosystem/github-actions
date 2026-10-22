import json
import runpy
import urllib.error
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parents[2]
MODULE = runpy.run_path(str(ROOT / "node/runtime/node_security.py"))
RELEASES = [
    {"version": "v24.23.0", "security": False},
    {"version": "v24.22.1", "security": True},
    {"version": "v24.9.1", "security": True},
    {"version": "v22.23.4", "security": True},
    {"version": "v26.12.1", "security": True},
]


@pytest.mark.parametrize("installed", ["22.23.3", "24.21.0", "24.22.0"])
def test_older_runtime_fails_even_when_its_major_is_supported(installed):
    with pytest.raises(ValueError, match="older than the latest.*security release"):
        MODULE["verify_node_security"](installed, read=lambda: json.dumps(RELEASES))


@pytest.mark.parametrize(
    "installed,minimum",
    [("22.23.4", "22.23.4"), ("24.22.1", "24.22.1"), ("24.23.0", "24.22.1")],
)
def test_security_floor_is_per_major_and_uses_numeric_version_order(installed, minimum):
    assert (
        MODULE["verify_node_security"](
            installed, read=lambda: json.dumps(list(reversed(RELEASES)))
        )
        == minimum
    )


def test_a_new_security_release_changes_the_floor_without_a_workflow_update():
    releases = [*RELEASES, {"version": "v24.24.1", "security": True}]
    with pytest.raises(ValueError, match="security release 24.24.1"):
        MODULE["verify_node_security"]("24.23.0", read=lambda: json.dumps(releases))


@pytest.mark.parametrize(
    "data",
    [
        "not json",
        "{}",
        "[]",
        "[null]",
        '[{"version":"24"}]',
        '[{"version":"v24.22.1","security":"true"}]',
        '[{"version":"v24.22.1","security":false}]',
        '[{"version":"v22.23.4","security":true}]',
    ],
)
def test_missing_or_invalid_security_evidence_fails(data):
    with pytest.raises(ValueError):
        MODULE["verify_node_security"]("24.22.1", read=lambda: data)


@pytest.mark.parametrize("failure", ["unavailable", "oversized"])
def test_public_release_download_is_bounded_and_fails_without_fallback(
    monkeypatch, failure
):
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self, limit):
            assert limit == MODULE["MAX_BYTES"] + 1
            return b" " * limit

    class Opener:
        def open(self, request, timeout):
            assert request.full_url == "https://nodejs.org/dist/index.json"
            assert not request.has_header("Authorization")
            assert timeout == 15
            if failure == "unavailable":
                raise urllib.error.URLError("offline")
            return Response()

    monkeypatch.setenv("GH_TOKEN", "must-not-be-sent")
    monkeypatch.setenv("GITHUB_TOKEN", "must-not-be-sent")
    monkeypatch.setattr(
        MODULE["urllib"].request, "build_opener", lambda handler: Opener()
    )
    with pytest.raises(ValueError, match="Cannot verify|size limit"):
        MODULE["verify_node_security"]("24.22.1")


def test_runtime_setup_checks_for_new_releases_in_audit_and_ci():
    action = yaml.safe_load((ROOT / "node/audit/action.yml").read_text())
    workflow = yaml.safe_load((ROOT / ".github/workflows/validate.yml").read_text())
    for steps in (action["runs"]["steps"], workflow["jobs"]["toolchain"]["steps"]):
        setup = next(
            step
            for step in steps
            if step.get("uses", "").startswith("actions/setup-node@")
        )
        assert setup["with"]["check-latest"] is True
