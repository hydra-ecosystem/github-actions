"""Resolve and verify the calling website's declared toolchain."""

import argparse
import json
import re
import subprocess
from pathlib import Path

DIRECTORY_PATTERN = re.compile(r"[A-Za-z0-9_./ -]+")


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
    selected = {key: baseline[key] for key in ("node", "pnpm", "minimumReleaseAge")}
    if settings is None:
        if manifest.get("packageManager") != f"pnpm@{selected['pnpm']}":
            raise ValueError("project packageManager differs from the shared pnpm pin")
        return selected
    if not isinstance(settings, dict) or not set(settings) <= {"node", "pnpm"}:
        raise ValueError("docusaurus.json toolchain accepts only node and pnpm")
    node, pnpm = settings.get("node", "project"), settings.get("pnpm", "project")
    constraints = []
    if node != "project":
        constraints.append(
            ("docusaurus.json toolchain.node", node_version(node, "toolchain.node"))
        )
    # Website declarations take precedence over repository-wide declarations.
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
            "Node version is undeclared: add .nvmrc or .node-version in the website or repository, or set toolchain.node explicitly"
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
            r"pnpm@(\d+\.\d+\.\d+)(?:\+sha(?:224|256|384|512)\.[0-9a-f]+)?", manager
        )
        if isinstance(manager, str)
        else None
    )
    if not match:
        raise ValueError(
            "package.json packageManager must pin an exact stable pnpm version; npm/Yarn and package-manager migrations are not supported"
        )
    selected["pnpm"] = match[1]
    if pnpm != "project" and pnpm != selected["pnpm"]:
        raise ValueError(
            f"package.json packageManager={manager} conflicts with docusaurus.json toolchain.pnpm={pnpm!r}; align the declarations before running"
        )
    supported = baseline["supported"]
    if (
        selected["node"].split(".")[0] not in supported["node"]
        or selected["pnpm"] not in supported["pnpm"]
    ):
        raise ValueError(
            f"Unsupported toolchain Node {selected['node']} / pnpm {selected['pnpm']}; supported Node majors: {', '.join(supported['node'])}; pnpm versions: {', '.join(supported['pnpm'])}. Review the project toolchain; this workflow does not migrate it."
        )
    if "." in selected["node"] and tuple(map(int, selected["node"].split("."))) < (
        22,
        13,
        0,
    ):
        raise ValueError(
            "pnpm 11 requires Node >=22.13.0; align the Node declaration before running"
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


def project(root: Path) -> tuple[Path, dict]:
    root = root.resolve()
    config = json.loads((root / ".github/docusaurus.json").read_text())
    if (
        not isinstance(config, dict)
        or not set(config)
        <= {"directory", "schedule", "toolchain", "buildScript", "maintenance"}
        or "directory" not in config
    ):
        raise ValueError(
            "docusaurus.json accepts only project directory and schedule, plus toolchain, buildScript and maintenance"
        )
    name = config["directory"]
    schedules = config.get("schedule", ["0 2 30 1 *"])
    if (
        not isinstance(schedules, list)
        or not schedules
        or any(not isinstance(value, str) or not value.strip() for value in schedules)
    ):
        raise ValueError("schedule must be a nonempty list of cron expressions")
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
    manifest = json.loads((directory / "package.json").read_text())
    dependencies = {
        **manifest.get("dependencies", {}),
        **manifest.get("devDependencies", {}),
    }
    if "@docusaurus/core" not in dependencies:
        raise ValueError("configured project does not declare @docusaurus/core")
    script = config.get("buildScript", "build")
    scripts = manifest.get("scripts", {})
    if (
        not isinstance(script, str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9:_.-]*", script) is None
        or not isinstance(scripts, dict)
        or not isinstance(scripts.get(script), str)
        or not scripts[script].strip()
    ):
        raise ValueError(
            "docusaurus.json buildScript must name an existing nonempty package.json script; default is build"
        )
    maintenance = config.get("maintenance", {})
    if not isinstance(maintenance, dict) or not set(maintenance) <= {
        "mode",
        "upgradeScope",
    }:
        raise ValueError(
            "docusaurus.json maintenance accepts only mode and upgradeScope"
        )
    mode = maintenance.get("mode", "security-and-maintenance")
    scope = maintenance.get("upgradeScope", "major")
    if mode not in ("security-only", "security-and-maintenance"):
        raise ValueError(
            "docusaurus.json maintenance.mode must be security-only or security-and-maintenance"
        )
    if scope not in ("patch", "minor", "major"):
        raise ValueError(
            "docusaurus.json maintenance.upgradeScope must be patch, minor or major"
        )
    baseline = json.loads(Path(__file__).with_name("toolchain.json").read_text())
    if "toolchain" in config and config["toolchain"] is None:
        raise ValueError("docusaurus.json toolchain must be an object")
    selected = resolve_toolchain(
        root, directory, manifest, config.get("toolchain"), baseline
    )
    selected.update(
        buildScript=script, maintenance={"mode": mode, "upgradeScope": scope}
    )
    return directory, selected


def verify_runtime(directory, selected):
    import yaml

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
    pnpm = output(["corepack", "pnpm", "--version"])
    if pnpm != selected["pnpm"]:
        raise ValueError(
            f"Installed pnpm {pnpm} differs from package.json/toolchain pnpm {selected['pnpm']}"
        )
    lock = yaml.safe_load((directory / "pnpm-lock.yaml").read_text())
    if not isinstance(lock, dict) or str(lock.get("lockfileVersion")) != "9.0":
        raise ValueError(
            "pnpm-lock.yaml must use lockfileVersion 9.0; migrate and verify it before running maintenance"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--github-env", type=Path)
    parser.add_argument("--verify-runtime", action="store_true")
    args = parser.parse_args()
    try:
        directory, selected = project(args.root)
        if args.verify_runtime:
            verify_runtime(directory, selected)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.error(str(error))
    values = (
        f"NPM_PROJECT={directory.relative_to(args.root.resolve()).as_posix()}\n"
        f"DOCUSAURUS_NODE_VERSION={selected['node']}\n"
        f"DOCUSAURUS_PNPM_VERSION={selected['pnpm']}\n"
        f"DOCUSAURUS_BUILD_SCRIPT={selected['buildScript']}\n"
        f"DOCUSAURUS_MAINTENANCE_MODE={selected['maintenance']['mode']}\n"
        f"DOCUSAURUS_UPGRADE_SCOPE={selected['maintenance']['upgradeScope']}\n"
    )
    if args.github_env:
        with args.github_env.open("a") as output:
            output.write(values)
    else:
        print(values, end="")


if __name__ == "__main__":
    main()
