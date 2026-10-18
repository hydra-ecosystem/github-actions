import json
import os
import runpy
import subprocess
import sys
from pathlib import Path

import pytest
from workflow_source import load_workflow

SHARED = Path(__file__).parents[1] / "runtime"
read_project = runpy.run_path(str(SHARED / "project.py"))["project"]
AUDIT = SHARED / "templates/dependency_audit.py"


def site(root, name="website"):
    directory = root / name
    directory.mkdir(parents=True)
    (directory / "package.json").write_text(
        json.dumps(
            {
                "packageManager": "pnpm@11.21.0",
                "dependencies": {"@docusaurus/core": "^3.10.2"},
                "scripts": {"build": "arbitrary project-owned build"},
            }
        )
    )
    (directory / ".nvmrc").write_text("24\n")
    (root / ".github").mkdir(exist_ok=True)
    (root / ".github/node-maintenance.json").write_text(json.dumps({"directory": name}))
    return directory


def test_project_directory_is_configuration_and_build_is_opaque(tmp_path):
    directory = site(tmp_path, "docs/site with spaces")
    before = (directory / "package.json").read_bytes()
    actual, baseline = read_project(tmp_path)
    assert actual == directory
    assert baseline == {
        "node": "24",
        "pnpm": "11.21.0",
        "manager": "pnpm",
        "minimumReleaseAge": 14400,
        "validationScript": "build",
        "maintenance": {"mode": "security-and-maintenance", "upgradeScope": "major"},
    }
    assert (directory / "package.json").read_bytes() == before
    env = tmp_path / "environment"
    subprocess.run(
        [
            sys.executable,
            str(SHARED / "project.py"),
            "--root",
            str(tmp_path),
            "--github-env",
            str(env),
        ],
        check=True,
    )
    assert (
        env.read_text()
        == "NPM_PROJECT=docs/site with spaces\nNODE_AUDIT_NODE_VERSION=24\nNODE_AUDIT_MANAGER=pnpm\nNODE_AUDIT_MANAGER_VERSION=11.21.0\nNODE_AUDIT_MINIMUM_RELEASE_AGE_DAYS=10\nNODE_AUDIT_VALIDATION_SCRIPT=build\nNODE_AUDIT_MAINTENANCE_MODE=security-and-maintenance\nNODE_AUDIT_UPGRADE_SCOPE=major\n"
    )


@pytest.mark.parametrize(
    "name",
    [
        "../outside",
        "/outside",
        "website\nINJECTED=true",
        "website\rINJECTED=true",
        "docs/site+plus",
        "docs/site\twith-tab",
        "docs/siteé",
        "",
    ],
)
def test_project_rejects_invalid_directory(tmp_path, name):
    (tmp_path / ".github").mkdir()
    (tmp_path / ".github/node-maintenance.json").write_text(
        json.dumps({"directory": name})
    )
    with pytest.raises(ValueError):
        read_project(tmp_path)


def test_reader_cli_output_is_accepted_by_helper_cli_without_network(
    tmp_path, monkeypatch
):
    directory = site(tmp_path, "docs/site with spaces")
    (directory / "pnpm-workspace.yaml").write_text("packages:\n  - .\n")
    (directory / "pnpm-lock.yaml").write_text(
        "lockfileVersion: '9.0'\nimporters:\n  .: {}\npackages: {}\n"
    )
    environment = tmp_path / "environment"
    subprocess.run(
        [
            sys.executable,
            str(SHARED / "project.py"),
            "--root",
            str(tmp_path),
            "--github-env",
            str(environment),
        ],
        check=True,
    )
    npm_project = environment.read_text().splitlines()[0].removeprefix("NPM_PROJECT=")

    audit = runpy.run_path(str(AUDIT))
    monkeypatch.setitem(
        audit["main"].__globals__,
        "prepare",
        lambda selected, **kwargs: "mocked report\n",
    )
    report = tmp_path / "report.md"
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(AUDIT),
            "--directory",
            npm_project,
            "--report",
            str(report),
        ],
    )
    audit["main"]()
    assert report.read_text() == "mocked report\n"


@pytest.mark.parametrize(
    "name", ["docs/site+plus", "docs/site\twith-tab", "docs/siteé"]
)
def test_dependency_audit_rejects_unsupported_directory_syntax(tmp_path, name):
    result = subprocess.run(
        [
            sys.executable,
            str(AUDIT),
            "--directory",
            name,
            "--report",
            str(tmp_path / "report.md"),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
    assert "directory must be a relative npm project path" in result.stderr


def test_project_rejects_configuration_overriding_standard(tmp_path):
    site(tmp_path)
    (tmp_path / ".github/node-maintenance.json").write_text(
        json.dumps({"directory": "website", "pnpm": "latest"})
    )
    with pytest.raises(ValueError, match="unknown configuration fields.*pnpm"):
        read_project(tmp_path)


def test_project_rejects_symlink_outside_checkout(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "website").symlink_to(outside, target_is_directory=True)
    (root / ".github").mkdir()
    (root / ".github/node-maintenance.json").write_text('{"directory": "website"}')
    with pytest.raises(ValueError, match="outside"):
        read_project(root)


@pytest.mark.parametrize(
    "event, ref, succeeds",
    [
        ("workflow_dispatch", "refs/heads/main", True),
        ("workflow_dispatch", "refs/heads/feature", False),
        ("schedule", "refs/heads/main", True),
        ("schedule", "refs/heads/feature", True),
    ],
)
def test_manual_audit_requires_default_branch(event, ref, succeeds):
    workflow = load_workflow()
    guard = workflow["jobs"]["audit"]["steps"][0]
    assert guard["name"] == "Validate manual dispatch ref"
    result = subprocess.run(
        ["bash", "-c", guard["run"]],
        env={
            **os.environ,
            "DEFAULT_BRANCH": "main",
            "GITHUB_EVENT_NAME": event,
            "GITHUB_REF": ref,
        },
        capture_output=True,
    )
    assert (result.returncode == 0) is succeeds


def test_publisher_loads_config_after_guard_before_download():
    steps = load_workflow()["jobs"]["pull-request"]["steps"]
    guard = next(
        i
        for i, step in enumerate(steps)
        if step.get("name") == "Verify audit dependency state"
    )
    config = next(
        i
        for i, step in enumerate(steps)
        if step.get("name") == "Read project configuration"
    )
    download = next(
        i
        for i, step in enumerate(steps)
        if "download-artifact@" in step.get("uses", "")
    )
    assert guard < config < download


module = runpy.run_path(str(SHARED / "project.py"))


@pytest.fixture
def website(tmp_path):
    site = tmp_path / "website"
    site.mkdir()
    (tmp_path / ".github").mkdir()
    (tmp_path / ".github/node-maintenance.json").write_text(
        json.dumps({"directory": "website", "toolchain": {}})
    )
    (site / "package.json").write_text(
        json.dumps(
            {
                "packageManager": "pnpm@11.20.0",
                "engines": {"node": ">=22.13"},
                "dependencies": {"@docusaurus/core": "3.10.2"},
                "scripts": {"build": "docusaurus build"},
            }
        )
    )
    (site / ".nvmrc").write_text("22\n")
    (site / "pnpm-lock.yaml").write_text(
        "lockfileVersion: '9.0'\nimporters: {'.': {}}\npackages: {}\n"
    )
    (site / "pnpm-workspace.yaml").write_text(
        "packages: ['.']\nminimumReleaseAge: 14400\n"
    )
    return tmp_path, site


def configure(root, **settings):
    path = root / ".github/node-maintenance.json"
    data = json.loads(path.read_text())
    data["toolchain"] = settings
    path.write_text(json.dumps(data))


@pytest.mark.parametrize("node", ["22", "24"])
@pytest.mark.parametrize("pnpm", ["11.20.0", "11.21.0"])
def test_follow_project_supported_matrix(website, node, pnpm):
    root, site = website
    (site / ".nvmrc").write_text(node)
    path = site / "package.json"
    data = json.loads(path.read_text())
    data["packageManager"] = f"pnpm@{pnpm}"
    path.write_text(json.dumps(data))
    _, selected = module["project"](root)
    assert selected == {
        "node": node,
        "pnpm": pnpm,
        "manager": "pnpm",
        "minimumReleaseAge": 14400,
        "validationScript": "build",
        "maintenance": {"mode": "security-and-maintenance", "upgradeScope": "major"},
    }


def test_closest_runtime_declaration_wins_and_root_is_fallback(website):
    root, site = website
    (root / ".node-version").write_text("24")
    assert module["project"](root)[1]["node"] == "22"
    (site / ".nvmrc").unlink()
    assert module["project"](root)[1]["node"] == "24"


@pytest.mark.parametrize("node, pnpm", [("24", "project"), ("project", "11.21.0")])
def test_explicit_setting_conflicts_with_project_without_writes(website, node, pnpm):
    root, site = website
    configure(root, node=node, pnpm=pnpm)
    before = {path: path.read_bytes() for path in root.rglob("*") if path.is_file()}
    with pytest.raises(ValueError, match="[Cc]onflict"):
        module["project"](root)
    assert all(path.read_bytes() == data for path, data in before.items())


def test_explicit_node_satisfying_project_major_is_exact(website):
    root, site = website
    configure(root, node="22.14.0")
    assert module["project"](root)[1]["node"] == "22.14.0"
    (site / ".node-version").write_text("22.15.0")
    with pytest.raises(ValueError, match="Conflicting Node"):
        module["project"](root)


@pytest.mark.parametrize(
    "declaration", ["lts/*", "latest", ">=22", "22\nINJECTED=true", "22.0.0"]
)
def test_invalid_or_too_old_node_declaration_is_actionable(website, declaration):
    root, site = website
    (site / ".nvmrc").write_text(declaration)
    with pytest.raises(ValueError, match="Node"):
        module["project"](root)


def test_missing_runtime_declaration_does_not_guess_from_engine_range(website):
    root, site = website
    (site / ".nvmrc").unlink()
    with pytest.raises(ValueError, match="add .nvmrc or .node-version"):
        module["project"](root)
    configure(root, node="24")
    assert module["project"](root)[1]["node"] == "24"


@pytest.mark.parametrize(
    "manager",
    [
        None,
        "pnpm@latest",
        "pnpm@^11.20.0",
        "npm@11.0.0",
        "yarn@4.0.0",
        "pnpm@10.0.0",
        "pnpm@12.0.0",
    ],
)
def test_unsupported_package_manager_does_not_trigger_migration(website, manager):
    root, site = website
    path = site / "package.json"
    data = json.loads(path.read_text())
    data["packageManager"] = manager
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="packageManager|Unsupported toolchain"):
        module["project"](root)


def test_corepack_integrity_suffix_is_preserved(website):
    root, site = website
    path = site / "package.json"
    data = json.loads(path.read_text())
    data["packageManager"] = "pnpm@11.20.0+sha512." + "a" * 128
    path.write_text(json.dumps(data))
    before = path.read_bytes()
    assert module["project"](root)[1]["pnpm"] == "11.20.0"
    assert path.read_bytes() == before


@pytest.mark.parametrize(
    "version, expression, expected",
    [
        ((22, 14, 0), ">=22.13", True),
        ((22, 12, 0), ">=22.13", False),
        ((24, 1, 0), "^22.13.0 || ^24.0.0", True),
        ((24, 1, 0), "22.x", False),
        ((22, 14, 0), "22.x", True),
        ((22, 14, 0), ">=22 <23", True),
        ((24, 1, 0), ">22", True),
        ((22, 14, 0), "<=22", True),
        ((22, 14, 0), "~22.13.0", False),
        ((24, 1, 0), "24.1.0", True),
    ],
)
def test_node_engine_requirements(version, expression, expected):
    assert module["node_satisfies"](version, expression) is expected


@pytest.mark.parametrize(
    "expression",
    [">=22 || garbage", "22 - 24", "|| 24", "24 ||", "latest", "24.1.0.x", "024.x"],
)
def test_unsupported_engine_syntax_is_not_silently_ignored(expression):
    with pytest.raises(ValueError, match="range"):
        module["node_satisfies"]((24, 1, 0), expression)


@pytest.mark.parametrize(
    "node, pnpm, lock, engine, error",
    [
        ("v24.14.0", "11.20.0", "9.0", ">=22.13", "Installed Node"),
        ("v22.14.0", "11.21.0", "9.0", ">=22.13", "Installed pnpm"),
        ("v22.14.0", "11.20.0", "6.0", ">=22.13", "lockfileVersion"),
        ("v22.14.0", "11.20.0", "9.0", ">=24", "engines.node"),
        ("v22.14.0", "11.20.0", "9.0", ">=22.13", None),
    ],
)
def test_runtime_verified_before_dependency_changes(
    website, monkeypatch, node, pnpm, lock, engine, error
):
    root, site = website
    path = site / "package.json"
    data = json.loads(path.read_text())
    data["engines"]["node"] = engine
    path.write_text(json.dumps(data))
    (site / "pnpm-lock.yaml").write_text(
        f"lockfileVersion: '{lock}'\nimporters: {{'.': {{}}}}\npackages: {{}}\n"
    )
    commands = []

    def invoke(command, **kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(
            command, 0, node if command[0] == "node" else pnpm, ""
        )

    monkeypatch.setattr(subprocess, "run", invoke)
    before = {path: path.read_bytes() for path in root.rglob("*") if path.is_file()}
    if error:
        with pytest.raises(ValueError, match=error):
            module["verify_runtime"](site, module["project"](root)[1])
    else:
        module["verify_runtime"](site, module["project"](root)[1])
    assert all(
        command in (["node", "--version"], ["corepack", "pnpm", "--version"])
        for command in commands
    )
    assert all(path.read_bytes() == contents for path, contents in before.items())
