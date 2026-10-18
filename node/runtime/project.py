"""Resolve and verify the calling Node project's declared toolchain."""

import argparse
import hashlib
import json
import os
import re
import runpy
import subprocess
from pathlib import Path

DIRECTORY_PATTERN = re.compile(r"[A-Za-z0-9_./ -]+")
CONFIGURATION = runpy.run_path(str(Path(__file__).with_name("configuration.py")))
SCHEDULING = CONFIGURATION["SCHEDULING"]


def node_version(value, location):
    if not isinstance(value, str) or not re.fullmatch(r"v?\d+(?:\.\d+\.\d+)?", value):
        raise ValueError(f"{location}: use a Node major or exact stable version")
    value = value.removeprefix("v")
    if any(len(part) > 1 and part.startswith("0") for part in value.split(".")):
        raise ValueError(f"{location}: Node versions must not have leading zeroes")
    return value


def node_satisfies(version, expression):
    """Check stable Node engine ranges; reject unsupported syntax explicitly."""
    if not isinstance(expression, str) or not expression.strip():
        raise ValueError("package.json engines.node must be a nonempty range")
    alternatives = []
    for alternative in expression.split("||"):
        terms = re.sub(r"([<>]=?|[~^=])\s+", r"\1", alternative).split()
        if not terms:
            raise ValueError("package.json engines.node contains an empty range")
        matches = []
        for term in terms:
            match = re.fullmatch(
                r"(>=|<=|>|<|\^|~|=)?(v?\d+(?:\.\d+){0,2})(?:\.[xX*])?|([xX*])", term
            )
            if not match:
                raise ValueError(
                    f"Unsupported package.json engines.node range: {expression!r}; use stable numeric comparators or ||"
                )
            if match[3]:
                matches.append(True)
                continue
            operator = match[1] or ""
            parts = tuple(map(int, match[2].removeprefix("v").split(".")))
            raw_parts = match[2].removeprefix("v").split(".")
            if (term[-1] in "xX*" and len(parts) == 3) or any(
                len(part) > 1 and part.startswith("0") for part in raw_parts
            ):
                raise ValueError(
                    f"Unsupported package.json engines.node range: {expression!r}"
                )
            low = parts + (0,) * (3 - len(parts))
            upper = (*parts[:-1], parts[-1] + 1) + (0,) * (3 - len(parts))
            if operator == "^":
                upper = (parts[0] + 1, 0, 0)
                matches.append(low <= version < upper)
            elif operator == "~":
                upper = (parts[0], parts[1] + 1, 0) if len(parts) > 1 else upper
                matches.append(low <= version < upper)
            elif operator in ("", "="):
                matches.append(
                    version == low if len(parts) == 3 else low <= version < upper
                )
            elif operator == ">=":
                matches.append(version >= low)
            elif operator == "<":
                matches.append(version < low)
            elif operator == ">":
                matches.append(version > low if len(parts) == 3 else version >= upper)
            else:
                matches.append(version <= low if len(parts) == 3 else version < upper)
        alternatives.append(all(matches))
    return any(alternatives)


def resolve_toolchain(root, directory, manifest, settings, baseline):
    selected = {"minimumReleaseAge": baseline["minimumReleaseAge"]}
    settings = {} if settings is None else settings
    if not isinstance(settings, dict) or not set(settings) <= {"node", "npm", "pnpm"}:
        raise ValueError(
            "node-maintenance.json toolchain accepts only node, npm and pnpm"
        )
    node = settings.get("node", "project")
    constraints = []
    if node != "project":
        constraints.append(
            (
                "node-maintenance.json toolchain.node",
                node_version(node, "toolchain.node"),
            )
        )
    # Project declarations take precedence over repository-wide declarations.
    for parent in (directory, *directory.parents):
        if not parent.is_relative_to(root):
            break
        declarations = [
            path
            for path in (parent / ".nvmrc", parent / ".node-version")
            if path.exists()
        ]
        if declarations:
            for path in declarations:
                if not path.resolve().is_relative_to(root):
                    raise ValueError(
                        f"{path}: Node declaration resolves outside the repository"
                    )
                constraints.append(
                    (
                        str(path.relative_to(root)),
                        node_version(
                            path.read_text().strip(), str(path.relative_to(root))
                        ),
                    )
                )
            break
    if not constraints:
        raise ValueError(
            "Node version is undeclared: add .nvmrc or .node-version in the project or repository, or set toolchain.node explicitly"
        )
    majors = {value.split(".")[0] for _, value in constraints}
    exact = {value for _, value in constraints if "." in value}
    if len(majors) != 1 or len(exact) > 1:
        raise ValueError(
            "Conflicting Node declarations: "
            + ", ".join(f"{location}={value}" for location, value in constraints)
        )
    selected["node"] = next(iter(exact or majors))
    manager = manifest.get("packageManager", "")
    match = (
        re.fullmatch(
            r"(npm|pnpm)@(\d+\.\d+\.\d+)(?:\+sha(?:224|256|384|512)\.[0-9a-f]+)?",
            manager,
        )
        if isinstance(manager, str)
        else None
    )
    if not match:
        raise ValueError(
            "package.json packageManager must pin an exact supported npm or pnpm version; Yarn and package-manager migrations are not supported"
        )
    kind, version = match[1], match[2]
    if kind == "npm" and "+" in manager:
        raise ValueError(
            "package.json packageManager npm integrity suffixes are not supported by this workflow"
        )
    selected.update(manager=kind, **{kind: version})
    requested = settings.get(kind, "project")
    if requested != "project" and requested != version:
        raise ValueError(
            f"package.json packageManager={manager} conflicts with node-maintenance.json toolchain.{kind}={requested!r}; align the declarations before running"
        )
    supported = baseline["supported"]
    if (
        selected["node"].split(".")[0] not in supported["node"]
        or version not in supported[kind]
    ):
        raise ValueError(
            f"Unsupported toolchain Node {selected['node']} / {kind} {version}; supported Node majors: {', '.join(supported['node'])}; {kind} versions: {', '.join(supported[kind])}. Review the project toolchain; this workflow does not migrate it."
        )
    if "." in selected["node"] and tuple(map(int, selected["node"].split("."))) < (
        22,
        13,
        0,
    ):
        raise ValueError(
            "Supported package managers require Node >=22.13.0; align the Node declaration before running"
        )
    engine = manifest.get("engines", {}).get("node")
    if engine is not None:
        # Validate the complete syntax before setup; check the installed patch below.
        node_satisfies((24, 0, 0), engine)
        if "." in selected["node"] and not node_satisfies(
            tuple(map(int, selected["node"].split("."))), engine
        ):
            raise ValueError(
                f"Selected Node {selected['node']} conflicts with package.json engines.node={engine!r}"
            )
    return selected


def project_directory(root, config):
    root = root.resolve()
    name = config.get("directory")
    schedules = config.get("schedule", ["0 2 30 1 *"])
    SCHEDULING["validate_schedule"](schedules)
    if (
        not isinstance(name, str)
        or not name
        or DIRECTORY_PATTERN.fullmatch(name) is None
        or "\n" in name
        or "\r" in name
    ):
        raise ValueError("project directory must be a nonempty relative path")
    relative = Path(name)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("project directory must stay inside the repository")
    directory = (root / relative).resolve()
    if not directory.is_relative_to(root):
        raise ValueError("project directory resolves outside the repository")
    manifest_path = directory / "package.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ValueError("package.json must be a regular file inside the project")
    if not manifest_path.resolve().is_relative_to(root):
        raise ValueError("package.json resolves outside the repository")
    manifest = json.loads(manifest_path.read_text())
    if not isinstance(manifest, dict):
        raise ValueError("package.json must be an object")
    for field in ("dependencies", "devDependencies", "scripts", "engines"):
        if field in manifest and not isinstance(manifest[field], dict):
            raise ValueError(f"package.json {field} must be an object")
    if "workspaces" in manifest:
        raise ValueError(
            "multi-package workspaces are not supported; select a standalone project"
        )
    for parent in directory.parents:
        if not parent.is_relative_to(root):
            break
        ancestor_manifest = parent / "package.json"
        if ancestor_manifest.exists():
            ancestor = json.loads(ancestor_manifest.read_text())
            if isinstance(ancestor, dict) and "workspaces" in ancestor:
                raise ValueError(
                    "project is inside an ancestor workspace; only standalone projects are supported"
                )
        if (parent / "pnpm-workspace.yaml").exists():
            raise ValueError(
                "project is inside an ancestor pnpm workspace; only standalone projects are supported"
            )
    return directory, manifest


def project(root: Path, config=None, sources=None) -> tuple[Path, dict]:
    root = root.resolve()
    if config is None:
        config = CONFIGURATION["load_configuration"](root, sources)
    CONFIGURATION["validate_settings"](config, "resolved configuration")
    directory, manifest = project_directory(root, config)
    script = config.get("validationScript", "build")
    scripts = manifest.get("scripts", {})
    if (
        not isinstance(script, str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9:_.-]*", script) is None
        or not isinstance(scripts, dict)
        or not isinstance(scripts.get(script), str)
        or not scripts[script].strip()
    ):
        raise ValueError(
            "node-maintenance.json validationScript must name an existing nonempty package.json script; default is build"
        )
    maintenance = config.get("maintenance", {})
    if not isinstance(maintenance, dict) or not set(maintenance) <= {
        "mode",
        "upgradeScope",
    }:
        raise ValueError(
            "node-maintenance.json maintenance accepts only mode and upgradeScope"
        )
    mode = maintenance.get(
        "mode",
        "security-only"
        if isinstance(config.get("schedule"), dict)
        else "security-and-maintenance",
    )
    scope = maintenance.get("upgradeScope", "major")
    if mode not in ("security-only", "security-and-maintenance"):
        raise ValueError(
            "node-maintenance.json maintenance.mode must be security-only or security-and-maintenance"
        )
    if scope not in ("patch", "minor", "major"):
        raise ValueError(
            "node-maintenance.json maintenance.upgradeScope must be patch, minor or major"
        )
    if (
        isinstance(config.get("schedule"), dict)
        and config["schedule"].get("upgrades")
        and mode == "security-only"
    ):
        raise ValueError(
            "schedule.upgrades requires maintenance.mode=security-and-maintenance; use an empty upgrades list for manual-only upgrades"
        )
    baseline = json.loads(Path(__file__).with_name("toolchain.json").read_text())
    if "toolchain" in config and config["toolchain"] is None:
        raise ValueError("node-maintenance.json toolchain must be an object")
    selected = resolve_toolchain(
        root, directory, manifest, config.get("toolchain"), baseline
    )
    if "minimumReleaseAgeDays" in config:
        selected["minimumReleaseAge"] = config["minimumReleaseAgeDays"] * 1440
    selected.update(
        validationScript=script, maintenance={"mode": mode, "upgradeScope": scope}
    )
    return directory, selected


def verify_release_age(directory, selected):
    import yaml

    if selected["manager"] != "pnpm":
        return
    path = directory / "pnpm-workspace.yaml"
    if not path.resolve().is_relative_to(directory):
        raise ValueError("pnpm-workspace.yaml resolves outside the project")
    try:
        policy = yaml.safe_load(path.read_text())
    except yaml.YAMLError as error:
        raise ValueError(f"{path}: invalid workspace YAML") from error
    actual = policy.get("minimumReleaseAge") if isinstance(policy, dict) else None
    required = selected["minimumReleaseAge"]
    if type(actual) is not int or actual < required:
        raise ValueError(
            f"{path}: minimumReleaseAge={actual!r}; required at least {required} "
            f"minutes ({required // 1440} days). Align the workspace or explicitly "
            "override minimumReleaseAgeDays in .github/node-maintenance.json"
        )


def verify_runtime(directory, selected):
    def output(command):
        result = subprocess.run(
            command,
            cwd=directory,
            capture_output=True,
            text=True,
            timeout=120,
            check=True,
        )
        return result.stdout.strip()

    actual = node_version(output(["node", "--version"]), "installed Node")
    expected = selected["node"]
    if actual != expected and ("." in expected or actual.split(".")[0] != expected):
        raise ValueError(
            f"Installed Node {actual} does not satisfy declared Node {expected}"
        )
    if tuple(map(int, actual.split("."))) < (22, 13, 0):
        raise ValueError("Installed Node must be >=22.13.0 for pnpm 11")
    manifest = json.loads((directory / "package.json").read_text())
    engine = manifest.get("engines", {}).get("node")
    if engine is not None and not node_satisfies(
        tuple(map(int, actual.split("."))), engine
    ):
        raise ValueError(
            f"Installed Node {actual} conflicts with package.json engines.node={engine!r}"
        )
    kind = selected["manager"]
    command = (
        ["corepack", "pnpm", "--version"] if kind == "pnpm" else ["npm", "--version"]
    )
    actual_manager = output(command)
    if actual_manager != selected[kind]:
        raise ValueError(
            f"Installed {kind} {actual_manager} differs from package.json/toolchain {kind} {selected[kind]}"
        )
    verify_package_files(directory, selected)


def verify_package_files(directory, selected):
    """Verify package declarations and lockfiles without invoking project tools."""
    import yaml

    kind = selected["manager"]
    shrinkwrap = directory / "npm-shrinkwrap.json"
    if shrinkwrap.is_symlink() or shrinkwrap.exists():
        raise ValueError(
            "npm-shrinkwrap.json is unsupported; mixed npm lockfiles are not supported; remove it and use package-lock.json only"
        )
    for name in ("package-lock.json", "pnpm-lock.yaml", "pnpm-workspace.yaml"):
        path = directory / name
        if path.is_symlink():
            raise ValueError(
                f"{name}: package files must be regular files inside the project"
            )
    if kind == "pnpm":
        lock_path = directory / "pnpm-lock.yaml"
        try:
            lock = yaml.safe_load(lock_path.read_text())
        except yaml.YAMLError as error:
            raise ValueError(f"{lock_path}: invalid lockfile YAML: {error}") from error
        if not isinstance(lock, dict) or str(lock.get("lockfileVersion")) != "9.0":
            raise ValueError(
                "pnpm-lock.yaml must use lockfileVersion 9.0; migrate and verify it before running maintenance"
            )
        verify_release_age(directory, selected)
    else:
        lock = json.loads((directory / "package-lock.json").read_text())
        if (
            not isinstance(lock, dict)
            or lock.get("lockfileVersion") != 3
            or not isinstance(lock.get("packages"), dict)
            or "" not in lock["packages"]
        ):
            raise ValueError(
                "package-lock.json must use lockfileVersion 3; migrate and verify it before running maintenance"
            )
    audit = runpy.run_path(str(Path(__file__).parent / "templates/dependency_audit.py"))
    if audit["valid_snapshot"](directory) is None:
        raise ValueError(
            "Expected one standalone manifest, lockfile and package-manager policy; multi-package workspaces and mixed lockfiles are not supported"
        )


def write_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


def configuration_inputs(root, directory):
    paths = [
        root / ".github/node-maintenance.json",
        directory / "package.json",
        *[
            directory / name
            for name in ("pnpm-workspace.yaml",)
            if (directory / name).exists()
        ],
    ]
    for parent in (directory, *directory.parents):
        if not parent.is_relative_to(root):
            break
        declared = [parent / name for name in (".nvmrc", ".node-version")]
        declared = [path for path in declared if path.exists()]
        if declared:
            paths.extend(declared)
            break
    result = {}
    for path in paths:
        if not path.resolve().is_relative_to(root):
            raise ValueError(
                f"{path}: configuration input resolves outside the repository"
            )
        result[str(path.relative_to(root))] = hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
    return result


def resolve_for_run(root, snapshot_path, sources):
    if snapshot_path is not None and snapshot_path.exists():
        # The snapshot includes provenance from several bounded source files.
        with snapshot_path.open("rb") as stream:
            snapshot = CONFIGURATION["json_object"](
                stream.read(1_048_577), "resolved snapshot", max_bytes=1_048_576
            )
        if snapshot.get("root") != str(root) or snapshot.get("schema_version") != 1:
            raise ValueError(
                "resolved configuration snapshot belongs to a different project"
            )
        if (
            set(snapshot)
            != {"schema_version", "root", "configuration", "sources", "inputs"}
            or not isinstance(snapshot["sources"], list)
            or len(snapshot["sources"]) > 8
            or not isinstance(snapshot["inputs"], dict)
        ):
            raise ValueError("invalid resolved configuration snapshot")
        for source in snapshot["sources"]:
            if not isinstance(source, dict) or set(source) != {
                "repository",
                "path",
                "ref",
                "commit",
            }:
                raise ValueError("invalid source in resolved configuration snapshot")
            CONFIGURATION["validate_source"](
                {key: source[key] for key in ("repository", "path", "ref")}
            )
            if not isinstance(source["commit"], str) or not re.fullmatch(
                r"[0-9a-f]{40}", source["commit"]
            ):
                raise ValueError(
                    "invalid source commit in resolved configuration snapshot"
                )
        sources.extend(snapshot["sources"])
        config = snapshot["configuration"]
        CONFIGURATION["validate_settings"](config, "resolved configuration snapshot")
        directory, selected = project(root, config=config)
        if snapshot["inputs"] != configuration_inputs(root, directory):
            raise ValueError(
                "project declarations changed after defaults resolution; rerun the audit"
            )
        return directory, selected
    config = CONFIGURATION["load_configuration"](root, sources)
    directory, selected = project(root, config=config)
    if snapshot_path is not None:
        write_json(
            snapshot_path,
            {
                "schema_version": 1,
                "root": str(root),
                "configuration": config,
                "sources": sources,
                "inputs": configuration_inputs(root, directory),
            },
        )
    return directory, selected


def write_configuration_report(path, status, message, sources, selected=None):
    if path is not None:
        write_json(
            path,
            {
                "schema_version": 1,
                "status": status,
                "message": message[:8000],
                "sources": sources,
                "required": {
                    key: selected[key]
                    for key in (
                        "node",
                        "manager",
                        selected["manager"],
                        "minimumReleaseAge",
                    )
                }
                if selected is not None
                else {},
            },
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--github-env", type=Path)
    parser.add_argument("--verify-runtime", action="store_true")
    parser.add_argument("--directory-only", action="store_true")
    parser.add_argument("--resolved-config", type=Path)
    parser.add_argument("--configuration-report", type=Path)
    parser.add_argument("--audit-kind", choices=("auto", "security", "upgrades"))
    args = parser.parse_args()
    sources = []
    selected = None
    try:
        root = args.root.resolve()
        if args.directory_only:
            directory, _ = project_directory(
                root, CONFIGURATION["local_configuration"](root)
            )
            values = f"NPM_PROJECT={directory.relative_to(root).as_posix()}\n"
            if args.github_env:
                with args.github_env.open("a") as output:
                    output.write(values)
            else:
                print(values, end="")
            return
        directory, selected = resolve_for_run(root, args.resolved_config, sources)
        if args.audit_kind is not None:
            if args.resolved_config is None:
                raise ValueError(
                    "audit selection requires a resolved configuration snapshot"
                )
            config = json.loads(args.resolved_config.read_text())["configuration"]
            selected["maintenance"]["mode"] = SCHEDULING["select_mode"](
                root,
                config,
                selected["maintenance"]["mode"],
                args.audit_kind,
                os.environ.get("GITHUB_EVENT_NAME", ""),
                SCHEDULING["event_payload"](os.environ.get("GITHUB_EVENT_PATH")),
            )
        if args.verify_runtime:
            verify_runtime(directory, selected)
        elif args.configuration_report:
            verify_release_age(directory, selected)
    except (OSError, ValueError, RecursionError, subprocess.SubprocessError) as error:
        message = str(error)
        if sources:
            message += "\nDefaults sources: " + ", ".join(
                f"{source['repository']}/{source['path']}@{source['ref']} "
                f"(resolved {source['commit']})"
                for source in sources
            )
        write_configuration_report(
            args.configuration_report, "error", message, sources, selected
        )
        annotation = (
            message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        )
        print(f"::error title=Node audit configuration::{annotation}")
        parser.exit(2, message + "\n")
    write_configuration_report(
        args.configuration_report,
        "ok" if args.verify_runtime else "pending",
        "Configuration and installed toolchain satisfy the resolved settings."
        if args.verify_runtime
        else "Configuration resolved; runtime verification is pending.",
        sources,
        selected,
    )
    values = (
        f"NPM_PROJECT={directory.relative_to(args.root.resolve()).as_posix()}\n"
        f"NODE_AUDIT_NODE_VERSION={selected['node']}\n"
        f"NODE_AUDIT_MANAGER={selected['manager']}\n"
        f"NODE_AUDIT_MANAGER_VERSION={selected[selected['manager']]}\n"
        f"NODE_AUDIT_MINIMUM_RELEASE_AGE_DAYS={selected['minimumReleaseAge'] // 1440}\n"
        f"NODE_AUDIT_VALIDATION_SCRIPT={selected['validationScript']}\n"
        f"NODE_AUDIT_MAINTENANCE_MODE={selected['maintenance']['mode']}\n"
        f"NODE_AUDIT_UPGRADE_SCOPE={selected['maintenance']['upgradeScope']}\n"
    )
    if args.github_env:
        with args.github_env.open("a") as output:
            output.write(values)
    else:
        print(values, end="")


if __name__ == "__main__":
    main()
