import json
import re
import runpy
import subprocess
import sys
import urllib.error
from pathlib import Path

import pytest

RUNTIME = Path(__file__).parents[1] / "runtime"
module = runpy.run_path(str(RUNTIME / "project.py"))
configuration = module["CONFIGURATION"]
SHA = "a" * 40
SOURCE = {"repository": "owner/settings", "path": "defaults.json", "ref": "main"}


@pytest.fixture
def site(tmp_path):
    (tmp_path / ".github").mkdir()
    (tmp_path / ".github/node-maintenance.json").write_text(
        json.dumps(
            {
                "directory": "website",
                "defaults": SOURCE,
                "validationScript": "check",
            }
        )
    )
    website = tmp_path / "website"
    website.mkdir()
    (website / ".nvmrc").write_text("24\n")
    (website / "package.json").write_text(
        json.dumps(
            {
                "packageManager": "pnpm@11.21.0",
                "engines": {"node": ">=24"},
                "dependencies": {"@docusaurus/core": "3.10.2"},
                "scripts": {"check": "site-owned check"},
            }
        )
    )
    (website / "pnpm-workspace.yaml").write_text(
        "packages: ['.']\nminimumReleaseAge: 14400\n"
    )
    return tmp_path, website


def configure(root, **overrides):
    path = root / ".github/node-maintenance.json"
    config = json.loads(path.read_text())
    config.update(overrides)
    path.write_text(json.dumps(config))


def public_sources(monkeypatch, files):
    calls = []

    def read(url, accept="application/json"):
        calls.append((url, accept))
        if url.startswith("https://api.github.com/repos/"):
            assert accept == "application/vnd.github.sha"
            return SHA.encode()
        prefix = "https://raw.githubusercontent.com/"
        assert url.startswith(prefix)
        repo, name, commit, path = url[len(prefix) :].split("/", 3)
        assert commit == SHA
        value = files[(f"{repo}/{name}", path)]
        return value if isinstance(value, bytes) else json.dumps(value).encode()

    monkeypatch.setitem(
        configuration["load_configuration"].__globals__, "public_read", read
    )
    return calls


def test_live_defaults_merge_per_field_without_inheriting_site_specific_fields(
    site, monkeypatch
):
    root, website = site
    remote = {
        "directory": "some/other/site",
        "validationScript": "remote-build",
        "schedule": ["0 2 * * 1"],
        "toolchain": {"node": "24", "pnpm": "11.21.0"},
        "minimumReleaseAgeDays": 10,
        "maintenance": {"mode": "security-only", "upgradeScope": "patch"},
    }
    calls = public_sources(monkeypatch, {("owner/settings", "defaults.json"): remote})
    configure(root, maintenance={"upgradeScope": "minor"})
    before = {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}
    sources = []
    directory, selected = module["project"](root, sources=sources)
    assert directory == website and selected["validationScript"] == "check"
    assert selected["maintenance"] == {"mode": "security-only", "upgradeScope": "minor"}
    assert selected["minimumReleaseAge"] == 14400
    assert sources == [{**SOURCE, "commit": SHA}]
    assert len(calls) == 2
    remote["minimumReleaseAgeDays"] = 14
    assert module["project"](root)[1]["minimumReleaseAge"] == 20160
    assert all(p.read_bytes() == data for p, data in before.items())


def test_shared_default_schedule_is_inherited_and_frozen_for_the_run(
    site, monkeypatch, tmp_path
):
    root, _ = site
    defaults = {
        "maintenance": {"mode": "security-and-maintenance"},
        "schedule": {"security": ["0 2 * * 1"], "upgrades": ["0 2 1 */3 *"]},
    }
    public_sources(monkeypatch, {("owner/settings", "defaults.json"): defaults})
    snapshot = tmp_path / "resolved.json"
    module["resolve_for_run"](root, snapshot, [])
    assert (
        json.loads(snapshot.read_text())["configuration"]["schedule"]
        == defaults["schedule"]
    )
    defaults["schedule"]["security"] = ["0 2 * * 2"]
    module["resolve_for_run"](root, snapshot, [])
    assert json.loads(snapshot.read_text())["configuration"]["schedule"][
        "security"
    ] == ["0 2 * * 1"]
    assert configuration["load_configuration"](root)["schedule"]["security"] == [
        "0 2 * * 2"
    ]


@pytest.mark.parametrize(
    "override,expected",
    [
        ({"upgrades": []}, {"security": ["0 2 * * 1"], "upgrades": []}),
        (
            {"security": ["0 2 * * 2"]},
            {"security": ["0 2 * * 2"], "upgrades": ["0 2 1 */3 *"]},
        ),
        ({}, {"security": ["0 2 * * 1"], "upgrades": ["0 2 1 */3 *"]}),
        (["0 2 * * 3"], ["0 2 * * 3"]),
    ],
)
def test_local_schedule_fields_override_inherited_cadences(
    site, monkeypatch, override, expected
):
    root, _ = site
    public_sources(
        monkeypatch,
        {
            ("owner/settings", "defaults.json"): {
                "schedule": {"security": ["0 2 * * 1"], "upgrades": ["0 2 1 */3 *"]}
            }
        },
    )
    configure(root, schedule=override)
    assert configuration["load_configuration"](root)["schedule"] == expected


def test_nested_schedule_defaults_merge_per_kind_without_combining_cron_lists(
    site, monkeypatch
):
    root, _ = site
    public_sources(
        monkeypatch,
        {
            ("owner/settings", "defaults.json"): {
                "defaults": {**SOURCE, "path": "base.json"},
                "schedule": {"security": ["0 2 * * 2"]},
            },
            ("owner/settings", "base.json"): {
                "schedule": {"security": ["0 2 * * 1"], "upgrades": ["0 2 1 */3 *"]}
            },
        },
    )
    assert configuration["load_configuration"](root)["schedule"] == {
        "security": ["0 2 * * 2"],
        "upgrades": ["0 2 1 */3 *"],
    }


def test_inherited_schedule_drift_reports_the_required_caller_entries(
    site, monkeypatch
):
    root, _ = site
    public_sources(
        monkeypatch,
        {
            ("owner/settings", "defaults.json"): {
                "maintenance": {"mode": "security-and-maintenance"},
                "schedule": {"security": ["0 2 * * 1"], "upgrades": ["0 2 1 */3 *"]},
            }
        },
    )
    (root / ".github/workflows").mkdir()
    (root / ".github/workflows/dependency-audit.yml").write_text(
        "'on':\n  schedule:\n  - cron: '0 2 * * 1'\n"
    )
    config = configuration["load_configuration"](root)
    with pytest.raises(ValueError, match=r"resolved schedule.*0 2 1 \*/3 \*"):
        module["SCHEDULING"]["select_mode"](
            root,
            config,
            "security-and-maintenance",
            "auto",
            "schedule",
            {"schedule": "0 2 * * 1"},
        )


def test_legacy_resolver_for_private_v4_installations_ignores_shared_schedule(
    site, monkeypatch
):
    root, _ = site
    public_sources(
        monkeypatch,
        {
            ("owner/settings", "defaults.json"): {
                "schedule": {"security": ["0 2 * * 1"], "upgrades": ["0 2 1 */3 *"]}
            }
        },
    )
    assert "schedule" not in configuration["load_configuration"](
        root, inherit_schedule=False
    )
    configure(root, schedule=["0 2 * * 4"])
    assert configuration["load_configuration"](root, inherit_schedule=False)[
        "schedule"
    ] == ["0 2 * * 4"]


def test_local_explicit_values_override_shared_values(site, monkeypatch):
    root, _ = site
    public_sources(
        monkeypatch,
        {
            ("owner/settings", "defaults.json"): {
                "toolchain": {"node": "22", "pnpm": "11.20.0"},
                "minimumReleaseAgeDays": 14,
            }
        },
    )
    configure(
        root, toolchain={"node": "24", "pnpm": "11.21.0"}, minimumReleaseAgeDays=10
    )
    selected = module["project"](root)[1]
    assert (selected["node"], selected["pnpm"], selected["minimumReleaseAge"]) == (
        "24",
        "11.21.0",
        14400,
    )


def test_inherited_constraint_rejects_project_drift_without_rewriting(
    site, monkeypatch
):
    root, website = site
    public_sources(
        monkeypatch,
        {
            ("owner/settings", "defaults.json"): {
                "toolchain": {"node": "24", "pnpm": "11.21.0"},
            }
        },
    )
    (website / ".nvmrc").write_text("22\n")
    with pytest.raises(ValueError, match="Conflicting Node declarations"):
        module["project"](root)
    assert (website / ".nvmrc").read_text() == "22\n"


def test_nested_defaults_and_commit_cache(site, monkeypatch):
    root, _ = site
    calls = public_sources(
        monkeypatch,
        {
            ("owner/settings", "defaults.json"): {
                "defaults": {**SOURCE, "path": "base.json"},
                "maintenance": {"mode": "security-only"},
            },
            ("owner/settings", "base.json"): {
                "toolchain": {"node": "24", "pnpm": "11.21.0"},
                "maintenance": {
                    "mode": "security-and-maintenance",
                    "upgradeScope": "patch",
                },
            },
        },
    )
    assert module["project"](root)[1]["maintenance"] == {
        "mode": "security-only",
        "upgradeScope": "patch",
    }
    assert sum(url.startswith("https://api.github.com/") for url, _ in calls) == 1


def test_cycles_use_resolved_identity_and_fail_closed(site, monkeypatch):
    root, _ = site
    public_sources(
        monkeypatch,
        {
            ("owner/settings", "defaults.json"): {
                "defaults": {**SOURCE, "ref": "another-branch"},
            }
        },
    )
    with pytest.raises(ValueError, match="cycle"):
        module["project"](root)


def test_depth_is_bounded(site, monkeypatch):
    root, _ = site
    public_sources(
        monkeypatch,
        {
            ("owner/settings", path): {"defaults": {**SOURCE, "path": str(i + 1)}}
            for i, path in enumerate(["defaults.json", *map(str, range(1, 9))])
        },
    )
    with pytest.raises(ValueError, match="exceeds 8"):
        module["project"](root)


@pytest.mark.parametrize(
    "bad",
    [
        {"repository": "https://evil.example/repo", "path": "x", "ref": "main"},
        {**SOURCE, "path": "../private"},
        {**SOURCE, "path": "/etc/passwd"},
        {**SOURCE, "path": "a//b"},
        {**SOURCE, "ref": ""},
        {**SOURCE, "ref": "main\nTOKEN=x"},
        {**SOURCE, "path": "x" * 2049},
        {"repository": "owner/repo", "path": "x"},
        None,
    ],
)
def test_invalid_source_is_rejected_without_network(site, monkeypatch, bad):
    root, _ = site
    configure(root, defaults=bad)
    public_sources(monkeypatch, {})
    with pytest.raises(ValueError, match="defaults"):
        module["project"](root)


@pytest.mark.parametrize(
    "data",
    [
        b"[]",
        b'{"toolchain":null}',
        b'{"maintenance":{"typo":"x"}}',
        b'{"minimumReleaseAgeDays":true}',
        b'{"minimumReleaseAgeDays":-1}',
        b'{"minimumReleaseAgeDays":1.5}',
        b'{"toolchain":{"node":"$(evil)"}}',
        b'{"toolchain":{"pnpm":"latest"}}',
        b'{"minimumReleaseAgeDays":10,"minimumReleaseAgeDays":0}',
        b'{"minimumReleaseAgeDays":NaN}',
        b'{"credentials":"not inherited"}',
        b" " * 65537,
    ],
)
def test_malformed_defaults_are_not_silently_ignored(site, monkeypatch, data):
    root, _ = site
    public_sources(monkeypatch, {("owner/settings", "defaults.json"): data})
    with pytest.raises(ValueError):
        module["project"](root)


@pytest.mark.parametrize(
    "minutes,passes",
    [
        (14400, True),
        (20160, True),
        (14399, False),
        (None, False),
        (True, False),
        (-1, False),
    ],
)
def test_cooldown_is_a_minimum_and_does_not_rewrite(site, minutes, passes):
    _, website = site
    path = website / "pnpm-workspace.yaml"
    before = "minimumReleaseAge: " + json.dumps(minutes) + "\n"
    path.write_text(before)
    if passes:
        module["verify_release_age"](
            website, {"manager": "pnpm", "minimumReleaseAge": 14400}
        )
    else:
        with pytest.raises(ValueError, match="required at least 14400"):
            module["verify_release_age"](
                website, {"manager": "pnpm", "minimumReleaseAge": 14400}
            )
    assert path.read_text() == before


def test_resolution_is_frozen_for_the_audit_and_bound_to_local_inputs(
    site, monkeypatch, tmp_path
):
    root, website = site
    remote = {
        "toolchain": {"node": "24", "pnpm": "11.21.0"},
        "minimumReleaseAgeDays": 10,
    }
    calls = public_sources(monkeypatch, {("owner/settings", "defaults.json"): remote})
    snapshot = tmp_path / "snapshot.json"
    first = module["resolve_for_run"](root, snapshot, [])
    remote["minimumReleaseAgeDays"] = 14
    second = module["resolve_for_run"](root, snapshot, [])
    assert first == second and len(calls) == 2
    (website / ".nvmrc").write_text("24.14.0\n")
    with pytest.raises(ValueError, match="changed after defaults resolution"):
        module["resolve_for_run"](root, snapshot, [])


def test_cli_fails_loudly_with_structured_report_and_no_commands(site, tmp_path):
    root, _ = site
    configure(root, defaults=None)
    report = tmp_path / "configuration-report.json"
    result = subprocess.run(
        [
            sys.executable,
            str(RUNTIME / "project.py"),
            "--root",
            str(root),
            "--configuration-report",
            str(report),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
    assert "::error title=Node audit configuration::" in result.stdout
    data = json.loads(report.read_text())
    assert data["status"] == "error" and "defaults" in data["message"]


def test_publisher_reads_only_local_directory_without_following_defaults(site):
    root, _ = site
    configure(root, defaults={**SOURCE, "repository": "does-not-exist/does-not-exist"})
    result = subprocess.run(
        [
            sys.executable,
            str(RUNTIME / "project.py"),
            "--root",
            str(root),
            "--directory-only",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout == "NPM_PROJECT=website\n"


@pytest.mark.parametrize(
    "field", ["dependencies", "devDependencies", "scripts", "engines"]
)
@pytest.mark.parametrize("value", [None, [], 1])
def test_malformed_manifest_sections_produce_a_configuration_report(
    site, tmp_path, field, value
):
    root, website = site
    (root / ".github/node-maintenance.json").write_text(
        json.dumps(
            {"directory": "website", "toolchain": {"node": "24", "pnpm": "11.21.0"}}
        )
    )
    path = website / "package.json"
    manifest = json.loads(path.read_text())
    manifest[field] = value
    before = json.dumps(manifest)
    path.write_text(before)
    report = tmp_path / "malformed-report.json"
    result = subprocess.run(
        [
            sys.executable,
            str(RUNTIME / "project.py"),
            "--root",
            str(root),
            "--configuration-report",
            str(report),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
    assert "::error title=Node audit configuration::" in result.stdout
    data = json.loads(report.read_text())
    assert data["status"] == "error"
    assert f"package.json {field} must be an object" in data["message"]
    assert path.read_text() == before


def test_public_download_never_uses_tokens_and_bounds_responses(monkeypatch):
    client = runpy.run_path(str(RUNTIME / "configuration.py"))
    requests = []

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self, limit):
            assert limit == 65537
            return b"{}"

    class Opener:
        def open(self, request, timeout):
            requests.append(request)
            assert timeout == 15
            return Response()

    monkeypatch.setenv("GITHUB_TOKEN", "must-not-be-sent")
    monkeypatch.setattr(
        client["urllib"].request, "build_opener", lambda handler: Opener()
    )
    assert client["public_read"]("https://api.github.com/example") == b"{}"
    assert "Authorization" not in requests[0].headers


def test_http_failure_is_actionable_without_a_fallback(monkeypatch):
    client = runpy.run_path(str(RUNTIME / "configuration.py"))

    class Opener:
        def open(self, request, timeout):
            raise urllib.error.HTTPError(request.full_url, 404, "missing", {}, None)

    monkeypatch.setattr(
        client["urllib"].request, "build_opener", lambda handler: Opener()
    )
    with pytest.raises(ValueError, match="HTTP 404.*public access"):
        client["public_read"]("https://api.github.com/example")


def test_pinned_source_uses_the_exact_commit_without_resolving_a_branch(
    site, monkeypatch
):
    root, _ = site
    configure(root, defaults={**SOURCE, "ref": SHA})
    calls = public_sources(
        monkeypatch,
        {("owner/settings", "defaults.json"): {"minimumReleaseAgeDays": 12}},
    )
    assert module["project"](root)[1]["minimumReleaseAge"] == 17280
    assert len(calls) == 1 and SHA in calls[0][0]


def test_documented_examples_resolve_against_the_actual_recommended_defaults(
    site, monkeypatch
):
    root, website = site
    defaults = json.loads(
        (RUNTIME.parents[1] / "defaults/node-maintenance.json").read_text()
    )
    assert defaults["toolchain"] == {"node": "24", "npm": "11.9.0", "pnpm": "11.21.0"}
    assert defaults["minimumReleaseAgeDays"] == 10
    document = (RUNTIME.parents[1] / "docs/shared-defaults.md").read_text()
    examples = [
        json.loads(block)
        for block in re.findall(r"```json\n(.*?)\n```", document, re.S)
    ]
    assert examples[0] == defaults
    public_sources(
        monkeypatch,
        {
            (
                "hydra-ecosystem/github-actions",
                "defaults/node-maintenance.json",
            ): defaults
        },
    )
    manifest = json.loads((website / "package.json").read_text())
    manifest["scripts"]["build"] = "site-owned build"
    manifest["engines"]["node"] = ">=22.13.0"
    (website / "package.json").write_text(json.dumps(manifest))
    for example in examples[1:]:
        (root / ".github/node-maintenance.json").write_text(json.dumps(example))
        (website / ".nvmrc").write_text(example.get("toolchain", {}).get("node", "24"))
        days = example.get("minimumReleaseAgeDays", 10)
        (website / "pnpm-workspace.yaml").write_text(
            f"minimumReleaseAge: {days * 1440}\n"
        )
        directory, selected = module["project"](root)
        module["verify_release_age"](directory, selected)
        assert selected["node"] == example.get("toolchain", {}).get("node", "24")
        assert selected["pnpm"] == "11.21.0"
        assert selected["minimumReleaseAge"] == days * 1440


def test_scheduling_guide_examples_match_effective_shared_schedule(site, monkeypatch):
    root, _ = site
    public_root = RUNTIME.parents[1]
    defaults = json.loads((public_root / "defaults/node-maintenance.json").read_text())
    examples = [
        json.loads(block)
        for block in re.findall(
            r"```json\n(.*?)\n```",
            (public_root / "docs/audit-schedules.md").read_text(),
            re.S,
        )
    ]
    assert (
        examples[0]["schedule"]
        == defaults["schedule"]
        == {"security": ["0 2 * * 1"], "upgrades": ["0 2 1 */3 *"]}
    )
    assert (
        examples[0]["maintenance"]["mode"]
        == defaults["maintenance"]["mode"]
        == "security-and-maintenance"
    )
    public_sources(monkeypatch, {("owner/settings", "defaults.json"): defaults})
    configure(root, **examples[1])
    resolved = configuration["load_configuration"](root)
    assert resolved["schedule"] == {"security": ["0 2 * * 1"], "upgrades": []}
    assert (
        module["project"](root, config=resolved)[1]["maintenance"]["mode"]
        == "security-only"
    )


def test_actual_preflight_report_only_becomes_healthy_after_runtime_validation(
    site, monkeypatch, tmp_path
):
    root, website = site
    (website / "pnpm-lock.yaml").write_text(
        "lockfileVersion: '9.0'\nimporters: {'.': {}}\npackages: {}\n"
    )
    public_sources(
        monkeypatch,
        {
            ("owner/settings", "defaults.json"): {
                "toolchain": {"node": "24", "pnpm": "11.21.0"}
            }
        },
    )
    report = tmp_path / "status.json"
    snapshot = tmp_path / "resolved.json"
    args = [
        "project",
        "--root",
        str(root),
        "--resolved-config",
        str(snapshot),
        "--configuration-report",
        str(report),
    ]
    monkeypatch.setattr(sys, "argv", args)
    module["main"]()
    assert json.loads(report.read_text())["status"] == "pending"

    def runtime(command, **kwargs):
        value = "v24.14.0" if command[0] == "node" else "11.21.0"
        return subprocess.CompletedProcess(command, 0, value, "")

    monkeypatch.setattr(subprocess, "run", runtime)
    monkeypatch.setattr(sys, "argv", [*args, "--verify-runtime"])
    module["main"]()
    healthy = json.loads(report.read_text())
    assert healthy["status"] == "ok" and healthy["sources"][0]["commit"] == SHA
    (website / "pnpm-workspace.yaml").write_text("minimumReleaseAge: 1\n")
    with pytest.raises(SystemExit):
        module["main"]()
    failure = json.loads(report.read_text())
    assert failure["status"] == "error" and failure["sources"][0]["commit"] == SHA
    assert (website / "pnpm-workspace.yaml").read_text() == "minimumReleaseAge: 1\n"


def test_malformed_lockfile_changes_pending_to_error_with_provenance(
    site, monkeypatch, tmp_path
):
    root, website = site
    public_sources(
        monkeypatch,
        {
            ("owner/settings", "defaults.json"): {
                "toolchain": {"node": "24", "pnpm": "11.21.0"}
            }
        },
    )
    report = tmp_path / "status.json"
    snapshot = tmp_path / "resolved.json"
    args = [
        "project",
        "--root",
        str(root),
        "--resolved-config",
        str(snapshot),
        "--configuration-report",
        str(report),
    ]
    monkeypatch.setattr(sys, "argv", args)
    module["main"]()
    assert json.loads(report.read_text())["status"] == "pending"

    (website / "pnpm-lock.yaml").write_text("lockfileVersion: [\n")

    def runtime(command, **kwargs):
        value = "v24.14.0" if command[0] == "node" else "11.21.0"
        return subprocess.CompletedProcess(command, 0, value, "")

    monkeypatch.setattr(subprocess, "run", runtime)
    monkeypatch.setattr(sys, "argv", [*args, "--verify-runtime"])
    with pytest.raises(SystemExit) as error:
        module["main"]()

    assert error.value.code == 2
    failure = json.loads(report.read_text())
    assert failure["status"] == "error"
    assert "pnpm-lock.yaml: invalid lockfile YAML" in failure["message"]
    assert "expected the node content" in failure["message"]
    assert failure["sources"] == [{**SOURCE, "commit": SHA}]
