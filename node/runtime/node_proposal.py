"""Prepare and publish narrowly scoped, same-major Node security updates."""

import argparse
import json
import re
import runpy
import subprocess
from pathlib import Path

CONFIGURATION = runpy.run_path(str(Path(__file__).with_name("configuration.py")))
SECURITY = runpy.run_path(str(Path(__file__).with_name("node_security.py")))
MAX_PLAN_BYTES = 262144


def local_project(root):
    config = CONFIGURATION["local_configuration"](root)
    name = config.get("directory")
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_./ -]+", name):
        raise ValueError("Invalid Node proposal project directory")
    path = Path(name)
    directory = (root / path).resolve()
    if path.is_absolute() or ".." in path.parts or not directory.is_relative_to(root):
        raise ValueError("Node proposal project directory escapes the repository")
    return directory, config


def declaration_changes(root, directory, target):
    """Derive every permitted edit from the original checkout, never artifact paths."""
    target_version = SECURITY["version_tuple"](target)
    _, local = local_project(root)
    paths = []
    for parent in (directory, *directory.parents):
        if not parent.is_relative_to(root):
            break
        declared = [parent / name for name in (".nvmrc", ".node-version")]
        declared = [path for path in declared if path.exists() or path.is_symlink()]
        if declared:
            paths = declared
            break
    changes = []
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise ValueError("Node proposal declarations must be regular files")
        before = path.read_text()
        current = before.strip().removeprefix("v")
        if not re.fullmatch(r"\d+(?:\.\d+\.\d+)?", current):
            raise ValueError(
                "Node proposal requires a major or exact stable declaration"
            )
        if int(current.split(".")[0]) != target_version[0]:
            raise ValueError("Node security proposals cannot change the Node major")
        if "." in current and SECURITY["version_tuple"](current) >= target_version:
            continue
        prefix = "v" if before.strip().startswith("v") else ""
        changes.append(
            {
                "path": path.relative_to(root).as_posix(),
                "before": before,
                "after": prefix + target + "\n",
            }
        )
    local_node = local.get("toolchain", {}).get("node", "project")
    if local_node != "project":
        current = local_node.removeprefix("v")
        if int(current.split(".")[0]) != target_version[0]:
            raise ValueError("Node security proposals cannot change the Node major")
        # Preserve a local major constraint when a version file owns the pin.
        if (not paths or "." in current) and (
            "." not in current or SECURITY["version_tuple"](current) < target_version
        ):
            path = root / ".github/node-maintenance.json"
            if path.is_symlink():
                raise ValueError("Node proposal configuration must be a regular file")
            before = path.read_text()
            local["toolchain"]["node"] = target
            changes.append(
                {
                    "path": ".github/node-maintenance.json",
                    "before": before,
                    "after": json.dumps(local, indent=2) + "\n",
                }
            )
    return changes


def prepare(root, directory, selected, *, enabled):
    plan = {
        "schema_version": 1,
        "directory": directory.relative_to(root).as_posix(),
        "version": None,
        "changes": [],
        "message": "",
    }
    if not enabled:
        return plan
    declared = selected["node"]
    target = SECURITY["latest_security_release"](declared.split(".")[0])
    if "." in declared and SECURITY["version_tuple"](declared) >= SECURITY[
        "version_tuple"
    ](target):
        return plan
    plan["version"] = target
    plan["changes"] = declaration_changes(root, directory, target)
    if not plan["changes"]:
        plan["message"] = (
            "Node security update needs a local Node declaration; inherited defaults are not rewritten."
        )
    return plan


def write_changes(root, plan, *, restore=False):
    for change in plan["changes"]:
        (root / change["path"]).write_text(change["before" if restore else "after"])


def read_plan(path):
    with path.open("rb") as stream:
        plan = CONFIGURATION["json_object"](
            stream.read(MAX_PLAN_BYTES + 1),
            "Node update plan",
            max_bytes=MAX_PLAN_BYTES,
        )
    if (
        set(plan) != {"schema_version", "directory", "version", "changes", "message"}
        or plan["schema_version"] != 1
    ):
        raise ValueError("Invalid Node update plan")
    if not isinstance(plan["changes"], list) or len(plan["changes"]) > 3:
        raise ValueError("Invalid Node update changes")
    for change in plan["changes"]:
        if (
            not isinstance(change, dict)
            or set(change) != {"path", "before", "after"}
            or any(not isinstance(value, str) for value in change.values())
        ):
            raise ValueError("Invalid Node update change")
    return plan


def verify_candidate(root, plan):
    for change in plan["changes"]:
        path = root / change["path"]
        if (
            path.is_symlink()
            or not path.is_file()
            or path.read_text() != change["after"]
        ):
            raise ValueError("Project validation changed a proposed Node declaration")


def publish(root, plan):
    directory, _ = local_project(root)
    if plan["directory"] != directory.relative_to(root).as_posix():
        raise ValueError("Node proposal directory differs from the checked-out project")
    if not plan["changes"]:
        return ""
    target = plan["version"]
    major = SECURITY["version_tuple"](target)[0]
    if target != SECURITY["latest_security_release"](major):
        raise ValueError(
            "Node proposal is not the latest security release; rerun the audit"
        )
    expected = declaration_changes(root, directory, target)
    if not expected or plan["changes"] != expected:
        raise ValueError("Node proposal edits do not match the permitted declarations")
    write_changes(root, plan)
    subprocess.run(
        ["git", "add", "--", *[c["path"] for c in expected]], cwd=root, check=True
    )
    return target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--github-env", type=Path, required=True)
    args = parser.parse_args()
    target = publish(Path.cwd().resolve(), read_plan(args.plan))
    with args.github_env.open("a") as output:
        output.write(f"NODE_UPDATE_VERSION={target}\n")


if __name__ == "__main__":
    main()
