"""Prepare a best-effort npm or pnpm upgrade report for one standalone Node project."""

import argparse
import base64
import copy
import hashlib
import html
import json
import os
import re
import runpy
import subprocess
import time
import zipfile
from io import BytesIO
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import quote

import yaml

LOCAL_PATCHES = runpy.run_path(str(Path(__file__).parents[1] / "local_patches.py"))
NODE_RELEASES = runpy.run_path(str(Path(__file__).parents[1] / "node_releases.py"))
REPAIR_CHOICES = runpy.run_path(str(Path(__file__).parents[1] / "repair_choices.py"))

SEVERITY_ORDER = {"critical": 0, "high": 1, "moderate": 2, "low": 3, "info": 4}
DIRECTORY_PATTERN = re.compile(r"[A-Za-z0-9_./ -]+")
NPM_AUDIT_INCLUDES = (
    "--include=prod",
    "--include=dev",
    "--include=optional",
    "--include=peer",
)


def npm_shrinkwrap_path(directory: Path) -> Path:
    return directory / "npm-shrinkwrap.json"


def unsupported_npm_shrinkwrap(directory: Path) -> Path | None:
    path = npm_shrinkwrap_path(directory)
    return path if path.is_symlink() or path.exists() else None


def manager(directory: Path) -> str:
    try:
        declared = json.loads((directory / "package.json").read_bytes()).get(
            "packageManager", ""
        )
    except (OSError, ValueError, AttributeError):
        declared = ""
    return (
        "pnpm"
        if declared.startswith("pnpm@") or (directory / "pnpm-workspace.yaml").exists()
        else "npm"
    )


def valid_snapshot(
    directory: Path,
) -> tuple[bytes, dict[str, bytes], dict, dict] | None:
    """Retain manifest, lockfile and pnpm policy together for safe restoration."""
    try:
        if unsupported_npm_shrinkwrap(directory) is not None:
            return None
        manifest_path = directory / "package.json"
        if manifest_path.is_symlink() or not manifest_path.is_file():
            return None
        manifest_bytes = manifest_path.read_bytes()
        manifest = json.loads(manifest_bytes)
        if manager(directory) == "pnpm":
            if (directory / "package-lock.json").exists():
                return None
            files = {
                name: (directory / name).read_bytes()
                for name in ("pnpm-lock.yaml", "pnpm-workspace.yaml")
            }
            policy = yaml.safe_load(files["pnpm-workspace.yaml"])
            lock = yaml.safe_load(files["pnpm-lock.yaml"])
            if (
                not isinstance(policy, dict)
                or policy.get("packages") != ["."]
                or not isinstance(policy.get("minimumReleaseAgeExclude", []), list)
                or any(
                    not isinstance(item, str)
                    for item in policy.get("minimumReleaseAgeExclude", [])
                )
                or not isinstance(lock, dict)
                or "lockfileVersion" not in lock
                or set(lock.get("importers", {})) != {"."}
                or not isinstance(lock.get("packages", {}), dict)
            ):
                return None
            packages = {}
            for key in lock.get("packages", {}):
                name, version = key.split("(", 1)[0].rsplit("@", 1)
                packages[f"{name}@{version}"] = {"name": name, "version": version}
            lock = {"packages": packages}
        else:
            if (directory / "pnpm-lock.yaml").exists():
                return None
            files = {
                "package-lock.json": (directory / "package-lock.json").read_bytes()
            }
            lock = json.loads(files["package-lock.json"])
    except (OSError, UnicodeDecodeError, ValueError, TypeError, yaml.YAMLError):
        return None
    if not isinstance(manifest, dict) or not isinstance(lock, dict):
        return None
    if "workspaces" in manifest:
        return None
    if manager(directory) == "npm":
        packages = lock.get("packages", {})
        if not isinstance(packages, dict) or any(
            not isinstance(package, dict)
            or package.get("link")
            or (path and not path.startswith("node_modules/"))
            for path, package in packages.items()
        ):
            return None
    return manifest_bytes, files, manifest, lock


def restore_snapshot(
    directory: Path, snapshot: tuple[bytes, dict[str, bytes], dict, dict]
) -> None:
    files = {"package.json": snapshot[0], **snapshot[1]}
    paths = [
        directory / name
        for name in (
            "package.json",
            "package-lock.json",
            "pnpm-lock.yaml",
            "pnpm-workspace.yaml",
        )
    ]
    shrinkwrap = npm_shrinkwrap_path(directory)
    if shrinkwrap.exists() and not shrinkwrap.is_file() and not shrinkwrap.is_symlink():
        raise ValueError(f"refusing to restore unsafe package path: {shrinkwrap}")
    for path in paths:
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise ValueError(f"refusing to restore unsafe package path: {path}")
    for path in paths:
        if path.name in files:
            path.write_bytes(files[path.name])
        else:
            path.unlink(missing_ok=True)
    if shrinkwrap.is_symlink() or shrinkwrap.exists():
        shrinkwrap.unlink()
    if valid_snapshot(directory) != snapshot:
        raise ValueError("restored package files do not match the accepted snapshot")


def exclusion_versions(exclusions: list[str]) -> set[str]:
    """Expand pnpm's exact-version unions without allowing broader new rules."""
    expanded = set()
    for exclusion in exclusions:
        name, separator, versions = exclusion.rpartition("@")
        if not separator or not name:
            expanded.add(exclusion)
        else:
            expanded.update(
                f"{name}@{version.strip()}" for version in versions.split("||")
            )
    return expanded


def stable_version(value: object) -> tuple[int, int, int] | None:
    if not isinstance(value, str):
        return None
    value = value.split("(", 1)[0]
    if not re.fullmatch(r"\d+\.\d+\.\d+", value):
        return None
    major, minor, patch = value.split(".")
    return int(major), int(minor), int(patch)


def stable_manifest_minimum(value: object) -> tuple[int, int, int] | None:
    if not isinstance(value, str) or not re.fullmatch(r"[~^]?\d+\.\d+\.\d+", value):
        return None
    return stable_version(value.lstrip("~^"))


def direct_pnpm_versions(
    files: dict[str, bytes],
) -> dict[tuple[str, str], tuple[int, int, int]]:
    try:
        lock = yaml.safe_load(files["pnpm-lock.yaml"])
        importer = lock["importers"]["."]
    except (KeyError, TypeError, ValueError, yaml.YAMLError):
        return {}
    versions = {}
    if not isinstance(importer, dict):
        return versions
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        entries = importer.get(section, {})
        if not isinstance(entries, dict):
            continue
        for name, entry in entries.items():
            if isinstance(name, str) and isinstance(entry, dict):
                version = stable_version(entry.get("version"))
                if version is not None:
                    versions[(section, name)] = version
    return versions


def direct_dependency_regressed(
    snapshot: tuple[bytes, dict[str, bytes], dict, dict],
    current: tuple[bytes, dict[str, bytes], dict, dict],
) -> bool:
    before_manifest = snapshot[2]
    after_manifest = current[2]
    before_locked = direct_pnpm_versions(snapshot[1])
    after_locked = direct_pnpm_versions(current[1])
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        before_entries = before_manifest.get(section, {})
        after_entries = after_manifest.get(section, {})
        if not isinstance(before_entries, dict):
            continue
        if not isinstance(after_entries, dict):
            after_entries = {}
        names = set(before_entries) | {
            name for section_name, name in before_locked if section_name == section
        }
        for name in names:
            before_specifier = before_entries.get(name)
            before_floor = stable_manifest_minimum(before_specifier)
            if before_floor is not None:
                after_floor = stable_manifest_minimum(after_entries.get(name))
                if after_floor is None or after_floor < before_floor:
                    return True
            before_version = before_locked.get((section, name))
            if before_version is not None:
                after_version = after_locked.get((section, name))
                if after_version is None or after_version < before_version:
                    return True
    return False


def restore_invalid_state(
    directory: Path,
    snapshot: tuple[bytes, dict[str, bytes], dict, dict],
    notes: list[str],
    operation: str,
    *,
    security_fix: bool = False,
    frozen: bool = False,
    allowed_security_exclusions: set[str] | None = None,
) -> bool:
    """Restore a valid snapshot when a command damaged package files or policy."""
    current = valid_snapshot(directory)
    if (
        current is not None
        and current[1].keys() == snapshot[1].keys()
        and (not frozen or (current[0] == snapshot[0] and current[1] == snapshot[1]))
    ):
        dependency_sections = {
            "dependencies",
            "devDependencies",
            "optionalDependencies",
        }
        if {
            key: value
            for key, value in current[2].items()
            if key not in dependency_sections
        } != {
            key: value
            for key, value in snapshot[2].items()
            if key not in dependency_sections
        }:
            restore_snapshot(directory, snapshot)
            notes.append(
                f"{operation} changed package.json fields outside dependencies, "
                "devDependencies, or optionalDependencies; restored the last "
                "valid snapshot and did not claim its changes."
            )
            return True
        if "pnpm-workspace.yaml" not in current[1]:
            before_packages = snapshot[3].get("packages", {})
            after_packages = current[3].get("packages", {})
            regressed = any(
                stable_version(package.get("version")) is not None
                and path in after_packages
                and stable_version(after_packages[path].get("version")) is not None
                and stable_version(after_packages[path]["version"])
                < stable_version(package["version"])
                for path, package in before_packages.items()
            )
            if regressed:
                restore_snapshot(directory, snapshot)
                notes.append(
                    f"{operation} lowered a known locked npm version; restored the last valid snapshot."
                )
                return True
            return False
        policy = yaml.safe_load(current[1]["pnpm-workspace.yaml"])
        reference = yaml.safe_load(snapshot[1]["pnpm-workspace.yaml"])
        pins = reference.get("overrides", {})
        bypassed_pin = isinstance(pins, dict) and any(
            stable_version(pins.get(name)) not in (None, version)
            for (_, name), version in direct_versions(current).items()
        )
        if direct_dependency_regressed(snapshot, current) or bypassed_pin:
            restore_snapshot(directory, snapshot)
            notes.append(
                f"{operation} changed protected pnpm policy, bypassed an exact pin or lowered a known direct "
                "pnpm dependency manifest floor or locked version; restored the last "
                "valid snapshot and did not claim its changes."
            )
            return True
        existing = reference.pop("minimumReleaseAgeExclude", [])
        exclusions = policy.pop("minimumReleaseAgeExclude", [])
        preserved_exclusions = exclusions == existing
        if security_fix:
            allowed = (
                allowed_security_exclusions
                if allowed_security_exclusions is not None
                else changed_pnpm_targets(snapshot[1], current[1])
            )
            existing_versions = exclusion_versions(existing)
            current_versions = exclusion_versions(exclusions)
            preserved_exclusions = existing_versions <= current_versions and all(
                re.fullmatch(r".+@\d+\.\d+\.\d+(?:-[\w.-]+)?(?:\+[\w.-]+)?", item)
                for item in current_versions - existing_versions
            )
            unused = current_versions - existing_versions - allowed
            if policy == reference and preserved_exclusions:
                retained = existing + sorted(
                    (current_versions - existing_versions) & allowed
                )
                workspace = directory / "pnpm-workspace.yaml"
                if retained == existing:
                    workspace.write_bytes(snapshot[1]["pnpm-workspace.yaml"])
                else:
                    # Reuse the original policy text: serializing the whole mapping
                    # would discard comments and reformat unrelated settings.
                    text = snapshot[1]["pnpm-workspace.yaml"].decode()
                    document = yaml.compose(text)
                    entry = next(
                        (
                            (key, value)
                            for key, value in document.value
                            if key.value == "minimumReleaseAgeExclude"
                        ),
                        None,
                    )
                    additions = sorted((current_versions - existing_versions) & allowed)
                    if entry is None:
                        index = end = document.end_mark.index
                        addition = "minimumReleaseAgeExclude:\n" + yaml.safe_dump(
                            additions
                        )
                    else:
                        key, sequence = entry
                        tokens = list(yaml.scan(text))
                        start = next(
                            token
                            for token in tokens
                            if token.start_mark.index >= key.end_mark.index
                            and isinstance(
                                token,
                                (
                                    yaml.AliasToken,
                                    yaml.FlowSequenceStartToken,
                                    yaml.BlockEntryToken,
                                ),
                            )
                        )
                        if isinstance(start, yaml.AliasToken):
                            index, end = start.start_mark.index, start.end_mark.index
                            addition = json.dumps(retained)
                        else:
                            flow = isinstance(start, yaml.FlowSequenceStartToken)
                            if flow:
                                closing_index = sequence.end_mark.index - 1
                                closing = next(
                                    index
                                    for index, token in enumerate(tokens)
                                    if isinstance(token, yaml.FlowSequenceEndToken)
                                    and token.start_mark.index == closing_index
                                )
                                trailing_comma = closing > 0 and isinstance(
                                    tokens[closing - 1], yaml.FlowEntryToken
                                )
                                items = json.dumps(additions)[1:-1]
                                if trailing_comma:
                                    index = end = closing_index
                                    addition = " " + items
                                elif sequence.value:
                                    index = end = sequence.value[-1].end_mark.index
                                    addition = ", " + items
                                else:
                                    index = end = closing_index
                                    addition = items
                            else:
                                index = end = sequence.end_mark.index
                                addition = "".join(
                                    " " * start.start_mark.column + line
                                    for line in yaml.safe_dump(additions).splitlines(
                                        keepends=True
                                    )
                                )
                    if addition.endswith("\n") and index and text[index - 1] != "\n":
                        addition = "\n" + addition
                    workspace.write_text(text[:index] + addition + text[end:])
                repaired = valid_snapshot(directory)
                repaired_policy = (
                    yaml.safe_load(repaired[1]["pnpm-workspace.yaml"])
                    if repaired is not None
                    else None
                )
                repaired_exclusions = (
                    repaired_policy.pop("minimumReleaseAgeExclude", [])
                    if isinstance(repaired_policy, dict)
                    else None
                )
                if (
                    repaired is None
                    or repaired_exclusions != retained
                    or repaired_policy != reference
                ):
                    restore_snapshot(directory, snapshot)
                    notes.append(
                        f"{operation} reconstructed an invalid pnpm policy; restored "
                        "the last valid snapshot and did not claim its changes."
                    )
                    return True
                if unused:
                    notes.append(
                        f"{operation}: removed unused release-age exceptions "
                        f"({', '.join(sorted(unused))}); retained resolved dependency changes."
                    )
                return False
        if policy == reference and preserved_exclusions:
            return False
    restore_snapshot(directory, snapshot)
    notes.append(
        f"{operation} changed protected pnpm policy, changed frozen package files, "
        "or left invalid package files; restored "
        "the last valid snapshot and did not claim its changes."
    )
    return True


def run(
    directory: Path, *args: str, deadline: float | None = None
) -> subprocess.CompletedProcess[str]:
    unsupported = unsupported_npm_shrinkwrap(directory)
    command = (
        ["corepack", "pnpm"] if manager(directory) == "pnpm" else ["npm"]
    ) + list(args)
    if unsupported is not None:
        result = subprocess.CompletedProcess(
            command,
            1,
            "",
            "npm-shrinkwrap.json is unsupported; mixed npm lockfiles are not supported; use package-lock.json only",
        )
        print(f"{' '.join(command)}: exit {result.returncode}")
        print(f"::group::{' '.join(command)} output")
        print(result.stdout)
        print(result.stderr)
        print("::endgroup::")
        return result
    timeout = min(900, deadline - time.monotonic()) if deadline is not None else 900
    if timeout <= 0:
        return subprocess.CompletedProcess(
            command, 124, "", "Dependency audit time budget exhausted."
        )
    # GNU timeout owns the process group and kills npm and lifecycle/build children.
    result = subprocess.run(
        ["timeout", "--signal=KILL", f"{timeout}s", *command],
        cwd=directory,
        capture_output=True,
        text=True,
    )
    if result.returncode in (-9, 137):
        result = subprocess.CompletedProcess(
            command, 124, result.stdout, result.stderr + "\nCommand timed out."
        )
    introduced = unsupported_npm_shrinkwrap(directory)
    if introduced is not None:
        result = subprocess.CompletedProcess(
            command,
            result.returncode or 1,
            result.stdout,
            (result.stderr.rstrip() + "\n" if result.stderr else "")
            + "npm-shrinkwrap.json was introduced during the command; mixed npm lockfiles are not supported; "
            "only package-lock.json is supported",
        )
    print(f"{' '.join(command)}: exit {result.returncode}")
    print(f"::group::{' '.join(command)} output")
    print(result.stdout)
    print(result.stderr)
    print("::endgroup::")
    return result


def valid_npm_fix(candidate: object) -> bool:
    if isinstance(candidate, bool):
        return True
    return (
        isinstance(candidate, dict)
        and isinstance(candidate.get("name"), str)
        and bool(candidate["name"])
        and ("version" not in candidate or isinstance(candidate["version"], str))
        and (
            "isSemVerMajor" not in candidate or type(candidate["isSemVerMajor"]) is bool
        )
    )


def valid_npm_vulnerability(vulnerability: object) -> bool:
    if not isinstance(vulnerability, dict):
        return False
    if (
        not isinstance(vulnerability.get("severity"), str)
        or vulnerability["severity"] not in SEVERITY_ORDER
        or not isinstance(vulnerability.get("range"), str)
        or not vulnerability["range"]
        or not isinstance(vulnerability.get("nodes"), list)
        or any(not isinstance(node, str) or not node for node in vulnerability["nodes"])
        or not isinstance(vulnerability.get("via"), list)
        or "fixAvailable" not in vulnerability
        or not valid_npm_fix(vulnerability["fixAvailable"])
    ):
        return False
    for via in vulnerability["via"]:
        if isinstance(via, str):
            if not via:
                return False
        elif (
            not isinstance(via, dict)
            or not isinstance(via.get("title"), str)
            or not via["title"]
            or not isinstance(via.get("url"), str)
            or not via["url"]
            or not isinstance(via.get("severity"), str)
            or via.get("severity") not in SEVERITY_ORDER
            or not isinstance(via.get("range"), str)
            or not via["range"]
        ):
            return False
    return True


def counts_match_details(
    counts: object,
    vulnerabilities: dict,
    package_manager: str,
    advisories: dict | None = None,
) -> bool:
    if (
        not isinstance(counts, dict)
        or not counts
        or any(level not in SEVERITY_ORDER and level != "total" for level in counts)
        or any(type(count) is not int or count < 0 for count in counts.values())
    ):
        return False
    if package_manager == "npm":
        if "total" not in counts or counts["total"] != len(vulnerabilities):
            return False
        observed = {
            level: sum(
                vulnerability.get("severity") == level
                for vulnerability in vulnerabilities.values()
            )
            for level in SEVERITY_ORDER
        }
    else:
        if advisories is None:
            return False
        if "total" in counts and counts["total"] != len(advisories):
            return False
        observed = {
            level: sum(
                advisory.get("severity") == level
                for advisory in advisories.values()
                if isinstance(advisory, dict)
            )
            for level in SEVERITY_ORDER
        }
    return all(
        counts.get(level, 0) == observed[level] for level in SEVERITY_ORDER
    ) and ("total" not in counts or counts["total"] == sum(observed.values()))


def audit(directory: Path, *, deadline: float | None = None) -> dict | str:
    package_manager = manager(directory)
    if package_manager == "pnpm":
        # Audit all advisories without rewriting the project's ignore decisions.
        # Override whole objects: dotted CLI keys do not clear YAML ignore lists.
        flags = [
            "--audit-level",
            "info",
            '--config.audit={"ignore":[]}',
            '--config.auditConfig={"ignoreGhsas":[]}',
        ]
    else:
        # CLI includes override project, user and environment omission settings.
        flags = ["--audit", "--package-lock-only", *NPM_AUDIT_INCLUDES]
    result = run(
        directory,
        "audit",
        "--json",
        *flags,
        deadline=deadline,
    )
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return f"Audit unavailable (exit {result.returncode})."
    if not isinstance(data, dict):
        return f"Audit unavailable (exit {result.returncode})."
    if package_manager == "pnpm" and not isinstance(data.get("advisories"), dict):
        return "Audit unavailable: malformed pnpm advisory response."
    advisories = data.get("advisories") if package_manager == "pnpm" else None
    if package_manager == "pnpm":
        assert isinstance(advisories, dict)
        vulnerabilities: dict = {}
        for advisory in advisories.values():
            if (
                not isinstance(advisory, dict)
                or any(
                    not isinstance(advisory.get(key), str) or not advisory[key]
                    for key in (
                        "module_name",
                        "severity",
                        "title",
                        "url",
                        "vulnerable_versions",
                    )
                )
                or advisory["severity"] not in SEVERITY_ORDER
                or not isinstance(advisory.get("findings"), list)
                or any(
                    not isinstance(finding, dict)
                    or not isinstance(finding.get("version"), str)
                    or not finding["version"]
                    for finding in advisory["findings"]
                )
                or (
                    "patched_versions" not in advisory
                    or (
                        advisory["patched_versions"] is not None
                        and not isinstance(advisory["patched_versions"], str)
                    )
                )
            ):
                return "Audit unavailable: malformed pnpm advisory response."
            name = advisory["module_name"]
            ranges = {
                advisory["vulnerable_versions"],
            }
            vulnerability = vulnerabilities.setdefault(
                name,
                {
                    "severity": advisory["severity"],
                    "range": advisory["vulnerable_versions"],
                    "nodes": [],
                    "via": [],
                    "fixAvailable": False,
                },
            )
            if vulnerability["severity"] not in SEVERITY_ORDER or (
                SEVERITY_ORDER[advisory["severity"]]
                < SEVERITY_ORDER[vulnerability["severity"]]
            ):
                vulnerability["severity"] = advisory["severity"]
            ranges.update(vulnerability["range"].split(" || "))
            vulnerability["range"] = " || ".join(sorted(ranges))
            nodes = [
                f"{name}@{finding['version']}"
                for finding in advisory.get("findings", [])
            ]
            vulnerability["via"].append(
                {
                    "title": advisory["title"],
                    "url": advisory["url"],
                    "severity": advisory["severity"],
                    "range": advisory["vulnerable_versions"],
                    "nodes": nodes,
                    "patchedRange": advisory["patched_versions"],
                }
            )
            vulnerability["nodes"].extend(nodes)
            vulnerability["fixAvailable"] = vulnerability["fixAvailable"] or bool(
                advisory.get("patched_versions") not in (None, "<0.0.0")
            )
        data["vulnerabilities"] = vulnerabilities
        data["package_manager"] = package_manager
    metadata = data.get("metadata")
    counts = metadata.get("vulnerabilities") if isinstance(metadata, dict) else None
    if (
        result.returncode not in (0, 1)
        or data.get("error")
        or not isinstance(data.get("vulnerabilities"), dict)
    ):
        return f"Audit unavailable (exit {result.returncode})."
    if package_manager == "npm" and any(
        not isinstance(name, str)
        or not name
        or not valid_npm_vulnerability(vulnerability)
        for name, vulnerability in data["vulnerabilities"].items()
    ):
        return "Audit unavailable: malformed npm vulnerability response."
    if not counts_match_details(
        counts,
        data["vulnerabilities"],
        package_manager,
        advisories,
    ):
        return "Audit unavailable: vulnerability counts do not match advisory details."
    return data


def fix_security(
    directory: Path,
    deadline: float,
    notes: list[str] | None = None,
    cache: dict | None = None,
    *,
    before: dict | str | None = None,
    release_before: str | None = None,
) -> subprocess.CompletedProcess[str]:
    if manager(directory) == "pnpm":
        snapshot = valid_snapshot(directory)
        result = run(
            directory,
            "audit",
            "--fix=update",
            "--audit-level",
            "info",
            "--ignore-scripts",
            deadline=deadline,
        )
        current = valid_snapshot(directory)
        diagnostics = notes if notes is not None else []
        metadata_cache = cache if cache is not None else {}
        if isinstance(before, dict) and snapshot is not None:
            describe_pnpm_fixes(
                directory,
                before,
                snapshot[1],
                diagnostics,
                deadline,
                metadata_cache,
                collect_proof=True,
            )
        if result.returncode != 1 or snapshot is None or current is None:
            return result
        reference = yaml.safe_load(snapshot[1]["pnpm-workspace.yaml"])
        policy = yaml.safe_load(current[1]["pnpm-workspace.yaml"])
        existing = exclusion_versions(reference.pop("minimumReleaseAgeExclude", []))
        exclusions = exclusion_versions(policy.pop("minimumReleaseAgeExclude", []))
        # Refuse weakened policy before executing another dependency command.
        if (
            policy != reference
            or not existing <= exclusions
            or any(
                not re.fullmatch(r".+@\d+\.\d+\.\d+(?:-[\w.-]+)?(?:\+[\w.-]+)?", item)
                for item in exclusions - existing
            )
        ):
            return result
        # Advisory ranges can start at an unpublished version. Resolve their
        # actual published, compatible patches before bypassing the age window.
        # Attribute patches to the original advisories. An independent advisory
        # can still affect a target that successfully fixed another one.
        original: dict = (
            copy.deepcopy(before)
            if isinstance(before, dict)
            else {"package_manager": "pnpm", "vulnerabilities": {}}
        )
        applied: dict = {"package_manager": "pnpm", "vulnerabilities": {}}
        resolved_targets = changed_pnpm_targets(snapshot[1], current[1])
        for specifier in (exclusions - existing) & resolved_targets:
            name, _, version = specifier.rpartition("@")
            for detail in original["vulnerabilities"].get(name, {}).get("via", []):
                patched = detail.get("patchedRange")
                if patched in (None, "", "<0.0.0"):
                    continue
                # Verify the exact installed target belongs to this advisory's
                # patched range, including every arm of a disjunctive range.
                applied["vulnerabilities"].setdefault(name, {"via": []})["via"].append(
                    {
                        "patchedRange": " || ".join(
                            f"{version} {arm.strip()}" for arm in patched.split("||")
                        ),
                        "nodes": [specifier],
                    }
                )
        for findings, files in ((original, snapshot[1]), (applied, current[1])):
            describe_pnpm_fixes(
                directory, findings, files, diagnostics, deadline, metadata_cache
            )
        verified = {
            f"{name}@{detail['fixVersion']}"
            for findings in (original, applied)
            for name, vulnerability in findings["vulnerabilities"].items()
            for detail in vulnerability["via"]
            if detail.get("fixVersion")
        }
        additions = verified - existing
        workspace = directory / "pnpm-workspace.yaml"
        policy = yaml.safe_load(workspace.read_bytes())
        trusted = yaml.safe_load(snapshot[1]["pnpm-workspace.yaml"])
        policy["minimumReleaseAgeExclude"] = trusted.get(
            "minimumReleaseAgeExclude", []
        ) + sorted(additions)
        workspace.write_text(yaml.safe_dump(policy, sort_keys=False))
        if restore_invalid_state(
            directory,
            snapshot,
            diagnostics,
            "Security proposal policy",
            security_fix=True,
            allowed_security_exclusions=additions,
        ):
            return result
        current = valid_snapshot(directory)
        assert current is not None
        # pnpm can reintroduce vulnerable pins during automatic peer resolution.
        # A fresh compatible resolution avoids those pins, including the installed
        # virtual store's lockfile, without adding overrides or running scripts.
        (directory / "pnpm-lock.yaml").unlink()
        with TemporaryDirectory(prefix="dependency-audit-resolution-") as modules:
            resolved = run(
                directory,
                "install",
                "--lockfile-only",
                "--no-frozen-lockfile",
                "--ignore-scripts",
                "--config.optimistic-repeat-install=false",
                "--modules-dir",
                modules,
                "--virtual-store-dir",
                str(Path(modules) / ".pnpm"),
                deadline=deadline,
            )
        failed = bool(resolved.returncode) or valid_snapshot(directory) is None
        if failed:
            restore_snapshot(directory, current)
        if notes is not None:
            notes.append(
                "Regenerated the pnpm lockfile within existing manifest constraints "
                "using isolated module metadata after audit --fix=update left findings."
                if not failed
                else f"Compatible lockfile regeneration failed (exit {resolved.returncode}); "
                "restored the preceding security-fix proposal."
            )
        return result if failed else resolved
    snapshot = valid_snapshot(directory)
    result = run(
        directory,
        "audit",
        "fix",
        "--package-lock-only",
        "--ignore-scripts",
        "--audit",
        "--no-force",
        *NPM_AUDIT_INCLUDES,
        *(["--before", release_before] if release_before else []),
        deadline=deadline,
    )
    current = valid_snapshot(directory)
    if isinstance(before, dict) and snapshot is not None and current is not None:
        describe_npm_fixes(
            directory,
            before,
            snapshot,
            current,
            notes if notes is not None else [],
            deadline,
            cache if cache is not None else {},
        )
    return result


def versions(lock: dict, vulnerability: dict) -> str:
    packages = lock.get("packages", {})
    found = {
        packages[node]["version"]
        for node in vulnerability.get("nodes", [])
        if node in packages and "version" in packages[node]
    }
    return ", ".join(sorted(found)) or "not recorded in lockfile"


def package_paths(lock: dict, name: str, package_manager: str) -> dict[str, str]:
    """Retain package locations and pnpm references lost by version deduplication."""
    if package_manager == "npm":
        return {
            node: package["version"]
            for node, package in lock.get("packages", {}).items()
            if "version" in package
            and (
                node == f"node_modules/{name}"
                or node.endswith(f"/node_modules/{name}")
                or package.get("name") == name
            )
        }
    paths = {}
    for group in ("packages", "snapshots", "importers"):
        entries = lock.get(group, {})
        if not isinstance(entries, dict):
            continue
        for node, entry in entries.items():
            if not isinstance(node, str):
                continue
            plain = node.split("(", 1)[0]
            if group != "importers" and plain.rsplit("@", 1)[0] == name:
                paths[f"{group}/{node}"] = plain.rsplit("@", 1)[-1]
            if group == "packages" or not isinstance(entry, dict):
                continue
            for section in ("dependencies", "devDependencies", "optionalDependencies"):
                references = entry.get(section, {})
                if not isinstance(references, dict):
                    continue
                for dependency, reference in references.items():
                    version = (
                        reference.get("version")
                        if isinstance(reference, dict)
                        else reference
                    )
                    if isinstance(version, str) and (
                        dependency == name or version.startswith(f"{name}@")
                    ):
                        paths[f"{group}/{node}/{section}/{dependency}"] = (
                            version.removeprefix(f"{name}@")
                        )
    return paths


def describe_npm_fixes(
    directory: Path,
    data: dict | str,
    before_snapshot: tuple[bytes, dict[str, bytes], dict, dict],
    after_snapshot: tuple[bytes, dict[str, bytes], dict, dict],
    notes: list[str],
    deadline: float,
    cache: dict,
) -> None:
    """Collect npm registry membership proof without changing audit reports."""
    if not isinstance(data, dict) or data.get("package_manager", "npm") != "npm":
        return
    before_lock, after_lock = before_snapshot[3], after_snapshot[3]

    def published(specifier: str, *, no_match_constraint=None) -> set[str] | None:
        key = ("npm", specifier, "version", no_match_constraint)
        if key not in cache:
            snapshot = valid_snapshot(directory)
            result = run(
                directory, "view", specifier, "version", "--json", deadline=deadline
            )
            if snapshot is None or restore_invalid_state(
                directory,
                snapshot,
                notes,
                f"Security proof lookup for {specifier}",
                frozen=True,
            ):
                cache[key] = None
            else:
                try:
                    value = json.loads(result.stdout)
                except (TypeError, ValueError):
                    value = None
                error = value.get("error") if isinstance(value, dict) else None
                values = [value] if isinstance(value, str) else value
                cache[key] = (
                    set()
                    if no_match_constraint is not None
                    and result.returncode == 1
                    and isinstance(error, dict)
                    and error.get("code") == "E404"
                    and error.get("summary")
                    == f"No match found for version {no_match_constraint}"
                    else set(values)
                    if result.returncode == 0
                    and isinstance(values, list)
                    and values
                    and all(stable_version(version) is not None for version in values)
                    else None
                )
        value = cache[key]
        return value if isinstance(value, set) else None

    for name, vulnerability in data.get("vulnerabilities", {}).items():
        if not isinstance(vulnerability, dict) or not vulnerability.get("fixAvailable"):
            continue
        detail = vulnerability
        detail.pop("_verifiedVulnerableVersions", None)
        detail.pop("_verifiedPatchedVersions", None)
        vulnerable_range = detail.get("range")
        nodes = detail.get("nodes")
        old_paths = package_paths(before_lock, name, "npm")
        new_paths = package_paths(after_lock, name, "npm")
        if (
            not isinstance(vulnerable_range, str)
            or not vulnerable_range
            or not isinstance(nodes, list)
            or not nodes
        ):
            continue
        affected_nodes = [node for node in nodes if node in old_paths]
        if len(affected_nodes) != len(nodes):
            continue
        affected_versions = {old_paths[node] for node in affected_nodes}
        vulnerable_versions = published(f"{name}@{vulnerable_range}")
        if vulnerable_versions is None or not affected_versions <= vulnerable_versions:
            continue
        detail["_verifiedVulnerableVersions"] = sorted(vulnerable_versions)
        selected_versions = {version.split("(", 1)[0] for version in new_paths.values()}
        if not selected_versions:
            continue
        patched_versions = set()
        for version in selected_versions:
            published_version = published(f"{name}@{version}")
            if published_version != {version}:
                patched_versions = set()
                break
            # Let npm evaluate the exact version against each original range
            # arm. Publication and a missing entry in a range listing do not
            # establish safety. Only npm's exact no-match response does.
            intersections = [
                published(
                    f"{name}@{version} {arm.strip()}",
                    no_match_constraint=f"{version} {arm.strip()}",
                )
                for arm in vulnerable_range.split("||")
            ]
            if any(matches != set() for matches in intersections):
                patched_versions = set()
                break
            patched_versions.add(version)
        if patched_versions == selected_versions:
            detail["_verifiedPatchedVersions"] = sorted(patched_versions)


def changed_pnpm_targets(before: dict[str, bytes], after: dict[str, bytes]) -> set[str]:
    """Include patches reused by changed paths as well as newly locked versions."""
    old_lock = yaml.safe_load(before["pnpm-lock.yaml"])
    new_lock = yaml.safe_load(after["pnpm-lock.yaml"])
    targets = {key.split("(", 1)[0] for key in new_lock["packages"]} - {
        key.split("(", 1)[0] for key in old_lock["packages"]
    }

    def edges(paths: dict[str, str]) -> dict[tuple[str, str, str], set[str]]:
        result: dict[tuple[str, str, str], set[str]] = {}
        for path, reference in paths.items():
            parts = re.split(
                r"/(dependencies|devDependencies|optionalDependencies)/",
                path,
                maxsplit=1,
            )
            if len(parts) == 3:
                # Different peer contexts can share a logical dependency edge.
                key = (parts[0].split("(", 1)[0], parts[1], parts[2])
                result.setdefault(key, set()).add(reference.split("(", 1)[0])
        return result

    names = {key.split("(", 1)[0].rsplit("@", 1)[0] for key in new_lock["packages"]}
    for name in names:
        old_paths = package_paths(old_lock, name, "pnpm")
        new_paths = package_paths(new_lock, name, "pnpm")
        old_edges = edges(old_paths)
        for path, references in edges(new_paths).items():
            for version in references - old_edges.get(path, set()):
                targets.add(f"{name}@{version}")
        # Retain an exact-path repoint even when another peer context already
        # uses the destination version on the same logical dependency edge.
        for path, reference in new_paths.items():
            version = reference.split("(", 1)[0]
            if path in old_paths and old_paths[path].split("(", 1)[0] != version:
                targets.add(f"{name}@{version}")
    return targets


def describe_pnpm_fixes(
    directory: Path,
    data: dict | str,
    files: dict[str, bytes],
    notes: list[str],
    deadline: float,
    cache: dict,
    *,
    collect_proof: bool = False,
) -> None:
    """Verify published patches and explain constraints using registry metadata."""
    if not isinstance(data, dict) or data.get("package_manager") != "pnpm":
        return
    lock = yaml.safe_load(files["pnpm-lock.yaml"])
    overrides = yaml.safe_load(files["pnpm-workspace.yaml"]).get("overrides", {})

    def query(package: str, *fields: str) -> object:
        key = (package, fields)
        if key not in cache:
            snapshot = valid_snapshot(directory)
            result = run(
                directory, "view", package, *fields, "--json", deadline=deadline
            )
            if snapshot is None or restore_invalid_state(
                directory,
                snapshot,
                notes,
                f"Patch metadata lookup for {package}",
                frozen=True,
            ):
                cache[key] = None
            else:
                try:
                    value = json.loads(result.stdout)
                except ValueError:
                    value = None
                error = value.get("error", {}) if isinstance(value, dict) else {}
                if not isinstance(error, dict):
                    error = {}
                cache[key] = (
                    []
                    if error.get("code")
                    in ("ERR_PNPM_PACKAGE_NOT_FOUND", "ERR_PNPM_NO_MATCHING_VERSION")
                    else value
                    if result.returncode == 0
                    else None
                )
        return cache[key]

    def published(specifier: str) -> set[str] | None:
        value = query(specifier, "version")
        values = [value] if isinstance(value, str) else value
        if not isinstance(values, list) or any(not isinstance(v, str) for v in values):
            return None
        return {v for v in values if re.fullmatch(r"\d+\.\d+\.\d+", v)}

    for name, vulnerability in data["vulnerabilities"].items():
        vulnerability["fixAvailable"] = False
        for detail in vulnerability["via"]:
            detail.pop("fixVersion", None)
            detail.pop("_repairCandidate", None)
            detail.pop("_repairFrom", None)
            detail.pop("_verifiedRepairVersions", None)
            detail.pop("_checkedParentConstraints", None)
            detail.pop("_verifiedPatchedVersions", None)
            if collect_proof:
                detail.pop("_verifiedVulnerableVersions", None)
            patched = detail.get("patchedRange")
            vulnerable_range = detail.get("range")
            if collect_proof and isinstance(vulnerable_range, str) and vulnerable_range:
                vulnerable_versions = published(f"{name}@{vulnerable_range}")
                affected_versions = {
                    node.rsplit("@", 1)[-1].split("(", 1)[0]
                    for node in detail.get("nodes", [])
                    if isinstance(node, str) and "@" in node
                }
                if (
                    vulnerable_versions
                    and affected_versions
                    and affected_versions <= vulnerable_versions
                ):
                    detail["_verifiedVulnerableVersions"] = sorted(vulnerable_versions)
            if patched in (None, "<0.0.0", ""):
                detail["fixStatus"] = "No patched version declared by the registry."
                continue
            patches = published(f"{name}@{patched}")
            if patches is None:
                detail["fixStatus"] = (
                    f"Could not verify publication of patched range `{patched}`."
                )
                continue
            if not patches:
                detail["fixStatus"] = (
                    f"No published stable patch matches registry range `{patched}`."
                )
                continue
            # Candidate selection needs the same verified publication set that
            # the audit report used. Keep this evidence internal; the normal
            # report continues to use fixStatus/fixVersion below.
            detail["_verifiedPatchedVersions"] = sorted(patches)
            vulnerability["fixAvailable"] = True
            blocked = []
            checked_parents = []
            unknown = False
            compatible_patches = None
            for parent, snapshot in lock.get("snapshots", {}).items():
                edges = {
                    **snapshot.get("dependencies", {}),
                    **snapshot.get("optionalDependencies", {}),
                }
                reference = edges.get(name)
                if (
                    not isinstance(reference, str)
                    or f"{name}@{reference.split('(', 1)[0]}" not in detail["nodes"]
                ):
                    continue
                parent = parent.split("(", 1)[0]
                metadata = query(parent, "dependencies", "optionalDependencies")
                if not isinstance(metadata, dict) or any(
                    not isinstance(metadata.get(field, {}), dict)
                    for field in ("dependencies", "optionalDependencies")
                ):
                    unknown = True
                    continue
                constraint = {
                    **metadata.get("dependencies", {}),
                    **metadata.get("optionalDependencies", {}),
                }.get(name)
                if not isinstance(constraint, str):
                    unknown = True
                    continue
                checked_parents.append(f"{parent} declares {name}: {constraint}")
                intersections = [
                    published(f"{name}@{parent_range.strip()} {patch_range.strip()}")
                    for parent_range in constraint.split("||")
                    for patch_range in patched.split("||")
                ]
                if any(versions is None for versions in intersections):
                    unknown = True
                else:
                    parent_patches = {
                        version
                        for matches in intersections
                        if matches is not None
                        for version in matches
                    }
                    if not parent_patches:
                        blocked.append(f"`{parent}` requires `{name} {constraint}`")
                    compatible_patches = (
                        parent_patches
                        if compatible_patches is None
                        else compatible_patches & parent_patches
                    )
            detail["_checkedParentConstraints"] = sorted(set(checked_parents))
            parent_compatible_patches = compatible_patches
            override = overrides.get(name) if isinstance(overrides, dict) else None
            override_status = ""
            override_patches = None
            if isinstance(override, str):
                intersections = [
                    published(f"{name}@{local_range.strip()} {patch_range.strip()}")
                    for local_range in override.split("||")
                    for patch_range in patched.split("||")
                ]
                if any(matches is None for matches in intersections):
                    unknown = True
                    override_status = (
                        f"Could not verify compatibility of retained override "
                        f"`pnpm-workspace.yaml overrides.{name}` = `{override}`. "
                        "Override preserved for manual review."
                    )
                else:
                    override_patches = {
                        version
                        for matches in intersections
                        if matches is not None
                        for version in matches
                    }
                    if not override_patches:
                        override_status = (
                            f"Blocked by retained override "
                            f"`pnpm-workspace.yaml overrides.{name}` = `{override}`. "
                            "Override preserved for manual compatibility review."
                        )
                    elif compatible_patches is not None:
                        compatible_patches &= override_patches
            # Qualified rules match declared dependency ranges and parent
            # versions, with precedence between overlapping selectors. Registry
            # patch intersections alone do not prove their applicability. Retain
            # all potentially relevant rules and withhold automatic exceptions.
            qualified = []
            for selector, value in (
                overrides.items() if isinstance(overrides, dict) else []
            ):
                delimiter = re.search(r"[^ |@]>", selector)
                target = selector[delimiter.end() :] if delimiter else selector
                target_name = target.rsplit("@", 1)[0] if "@" in target[1:] else target
                if selector != name and target_name == name:
                    qualified.append(
                        f"`pnpm-workspace.yaml overrides.{selector}` = `{value}`"
                    )
            if qualified:
                unknown = True
                override_status += (
                    " Retained qualified overrides require manual applicability "
                    "and compatibility review: " + "; ".join(sorted(qualified)) + "."
                )
            if compatible_patches == set():
                detail["fixStatus"] = (
                    "Published patches exist, but no single patch satisfies all "
                    "checked parent constraints. "
                    + (
                        "Blocked by existing parent constraints: "
                        + "; ".join(sorted(set(blocked)))
                        + "."
                        if blocked
                        else "Review patches per affected dependency path."
                    )
                    + (
                        " Parent compatibility could not be fully verified; manual review required."
                        if unknown
                        else ""
                    )
                    + (f" {override_status}" if override_status else "")
                )
                continue
            candidates = compatible_patches
            if candidates is None:
                candidates = override_patches or patches
            # A repair updates one exact, unqualified override. Its current
            # value must not constrain the candidate set: that is the pin being
            # repaired. Parent-compatible published versions remain eligible,
            # while unknown evidence is withheld below.
            if (
                isinstance(override, str)
                and stable_version(override) is not None
                and not unknown
                and not qualified
            ):
                repair_versions = parent_compatible_patches
                if repair_versions is None:
                    repair_versions = patches
                if repair_versions:
                    detail["_repairFrom"] = override
                    detail["_verifiedRepairVersions"] = sorted(repair_versions)
            version = min(candidates, key=lambda v: tuple(map(int, v.split("."))))
            if not unknown and not override_status:
                detail["fixVersion"] = version
            detail["fixStatus"] = f"Published patch: `{name}@{version}`. " + (
                override_status
                or (
                    "Parent compatibility could not be fully verified; manual review required."
                    if unknown
                    else "No checked parent constraint excludes published patches; review "
                    "manifest constraints and resolution logs."
                )
            )


def format_audit(data: dict | str, lock: dict) -> str:
    if isinstance(data, str):
        return data
    source = data.get("package_manager", "npm")
    summary = ", ".join(
        f"{level}: {count}"
        for level, count in data["metadata"]["vulnerabilities"].items()
    )
    findings = []
    for name, vulnerability in sorted(
        data.get("vulnerabilities", {}).items(),
        key=lambda item: (SEVERITY_ORDER.get(item[1]["severity"], 5), item[0]),
    ):
        candidate = vulnerability.get("fixAvailable")
        fix = "available" if candidate else f"not offered by {source}"
        if source == "pnpm":
            fix = (
                "published stable patch verified"
                if candidate
                else "publication not verified; see advisory details"
            )
        if isinstance(candidate, dict):
            fix = f"`{candidate['name']}@{candidate.get('version', 'unspecified')}`"
            if candidate.get("isSemVerMajor"):
                fix += "; requires breaking changes; manual review"
        findings.append(
            f"- **{name}**: {vulnerability['severity']}; locked versions "
            f"`{versions(lock, vulnerability)}`; affected range "
            f"`{vulnerability['range']}`; {source} fix candidate {fix}."
        )
        for via in vulnerability.get("via", []):
            if isinstance(via, dict):
                findings.append(
                    f"  - [{via['title']}]({via['url']}); "
                    f"{via['severity']}; "
                    + (
                        f"locked `{name}@{versions(lock, via)}`; "
                        if source == "pnpm"
                        else ""
                    )
                    + f"affected range `{via['range']}`."
                    + (f" {via['fixStatus']}" if via.get("fixStatus") else "")
                )
            else:
                findings.append(f"  - Depends on affected `{via}` (see its entry).")
    return (
        summary
        + "\n\n"
        + (
            "\n".join(findings)
            if findings
            else f"No known vulnerabilities reported by {source}."
        )
    )


def format_remaining_audit(data: dict | str, lock: dict) -> str:
    if isinstance(data, str):
        return data
    source = data.get("package_manager", "npm")
    counts = ", ".join(
        f"{level}: {count}"
        for level, count in data["metadata"]["vulnerabilities"].items()
    )
    vulnerabilities = data.get("vulnerabilities", {})
    if not vulnerabilities:
        return f"No known vulnerabilities reported by {source}."
    advisories: dict = {}
    for name, vulnerability in vulnerabilities.items():
        for via in vulnerability.get("via", []):
            if isinstance(via, dict):
                advisory = advisories.setdefault(
                    via["url"], {"detail": via, "packages": set()}
                )
                affected = via if source == "pnpm" else vulnerability
                advisory["packages"].add(f"{name}@{versions(lock, affected)}")
    lines = []
    for advisory in sorted(
        advisories.values(),
        key=lambda item: (
            SEVERITY_ORDER.get(item["detail"]["severity"], 5),
            item["detail"]["url"],
        ),
    ):
        detail = advisory["detail"]
        packages = ", ".join(sorted(advisory["packages"]))
        lines.append(
            f"- [{detail['title']}]({detail['url']}): {detail['severity']}; "
            f"locked `{packages}`; affected range `{detail['range']}`."
            + (f" {detail['fixStatus']}" if detail.get("fixStatus") else "")
        )
    heading = (
        f"Registry advisory counts: {counts}.\n\n"
        if data.get("package_manager") == "pnpm"
        else f"Affected package entries: {counts}. These are not distinct advisory counts.\n\n"
    )
    return heading + (
        "\n".join(lines)
        or f"{source} supplied no direct advisory details; see the full findings below."
    )


def finding_ids(data, source):
    """Return comparable finding identities, or None for incomplete evidence."""
    if not isinstance(data, dict):
        return None
    vulnerabilities = data.get("vulnerabilities", {})
    identities = (
        {
            detail["url"]
            for vulnerability in vulnerabilities.values()
            for detail in vulnerability.get("via", [])
            if isinstance(detail, dict) and detail.get("url")
        }
        if source == "pnpm"
        else set(vulnerabilities)
    )
    counts = data.get("metadata", {}).get("vulnerabilities", {})
    if not identities and (
        vulnerabilities or any(counts.get(level, 0) for level in SEVERITY_ORDER)
    ):
        return None
    return identities


def confirmed_fixes(before, after, source, before_snapshot, after_snapshot):
    old, current = finding_ids(before, source), finding_ids(after, source)
    if old is None or current is None:
        return set()
    locks = [
        yaml.safe_load(snapshot[1]["pnpm-lock.yaml"])
        if source == "pnpm"
        else snapshot[3]
        for snapshot in (before_snapshot, after_snapshot)
    ]
    # Registry withdrawals and changing audit responses are not dependency fixes.
    confirmed = set()
    for name, vulnerability in before.get("vulnerabilities", {}).items():
        old_paths = package_paths(locks[0], name, source)
        new_paths = package_paths(locks[1], name, source)
        if old_paths == new_paths:
            continue
        new_versions = set(new_paths.values())
        details = vulnerability.get("via", []) if source == "pnpm" else [vulnerability]
        for detail in details:
            if not isinstance(detail, dict):
                continue
            identity = detail.get("url") if source == "pnpm" else name
            if identity not in old - current:
                continue
            proof = detail.get("_verifiedVulnerableVersions")
            if not isinstance(proof, (list, tuple, set)) or not all(
                isinstance(version, str) for version in proof
            ):
                continue
            vulnerable_versions = set(proof)
            nodes = detail.get("nodes")
            if source == "npm":
                affected_nodes = (
                    [node for node in nodes if node in old_paths]
                    if isinstance(nodes, list)
                    else []
                )
                affected_versions = {
                    old_paths[node].split("(", 1)[0] for node in affected_nodes
                }
                if len(affected_nodes) != len(nodes or []):
                    continue
            else:
                affected_versions = (
                    {
                        node.rsplit("@", 1)[-1].split("(", 1)[0]
                        for node in nodes
                        if isinstance(node, str) and "@" in node
                    }
                    if isinstance(nodes, list)
                    else set()
                )
                old_versions = {
                    version.split("(", 1)[0] for version in old_paths.values()
                }
                if not affected_versions <= old_versions:
                    continue
            if not affected_versions or not affected_versions <= vulnerable_versions:
                continue
            if not new_versions:
                confirmed.add(identity)
                continue
            normalized_new = {version.split("(", 1)[0] for version in new_versions}
            if normalized_new & vulnerable_versions:
                continue
            # Unchanged instances outside the vulnerable set are baseline state.
            # Every changed or added instance still needs published patch proof.
            changed_versions = {
                version.split("(", 1)[0]
                for path, version in new_paths.items()
                if old_paths.get(path) != version
            }
            if not changed_versions:
                confirmed.add(identity)
                continue
            patched = detail.get("_verifiedPatchedVersions")
            if not isinstance(patched, (list, tuple, set)) or not all(
                isinstance(version, str) for version in patched
            ):
                continue
            if changed_versions <= set(patched):
                confirmed.add(identity)

    return confirmed


def _confirmed_package_names(data, source, confirmed_ids):
    """Map confirmed finding identities back to their audited package names."""
    if not isinstance(data, dict) or not isinstance(confirmed_ids, set):
        return set()
    names = set()
    for name, vulnerability in data.get("vulnerabilities", {}).items():
        details = vulnerability.get("via", []) if source == "pnpm" else [vulnerability]
        for detail in details:
            if not isinstance(detail, dict):
                continue
            identity = detail.get("url") if source == "pnpm" else name
            if identity in confirmed_ids:
                names.add(name)
    return names


def _npm_dependency_node(packages, parent, dependency):
    location = parent
    while True:
        candidate = (
            f"{location}/node_modules/{dependency}"
            if location
            else f"node_modules/{dependency}"
        )
        if candidate in packages:
            return candidate
        if not location:
            return None
        location = (
            location.rsplit("/node_modules/", 1)[0]
            if "/node_modules/" in location
            else ""
        )


def _npm_dependency_reaches(
    lock,
    root_name,
    target_name,
    target_nodes,
    *,
    root_nodes=None,
    include_peer_dependencies=False,
):
    """Follow npm edges from a direct package or exact installed nodes."""
    packages = lock.get("packages", {})
    if not isinstance(packages, dict):
        return False
    roots = [
        node
        for node, package in packages.items()
        if node == f"node_modules/{root_name}" and isinstance(package, dict)
    ]
    if root_nodes is not None:
        roots = [node for node in root_nodes if isinstance(packages.get(node), dict)]
    if not roots:
        return False

    queue, visited = list(roots), set()
    while queue:
        node = queue.pop()
        if node in visited:
            continue
        visited.add(node)
        package = packages.get(node)
        if not isinstance(package, dict):
            continue
        if node in target_nodes and node.rsplit("node_modules/", 1)[-1] == target_name:
            return True
        sections = ("dependencies", "optionalDependencies")
        if include_peer_dependencies:
            sections += ("peerDependencies",)
        for section in sections:
            dependencies = package.get(section, {})
            if not isinstance(dependencies, dict):
                continue
            for dependency in dependencies:
                child = _npm_dependency_node(packages, node, dependency)
                if child is None:
                    continue
                if dependency == target_name and child in target_nodes:
                    return True
                queue.append(child)
    return False


def _pnpm_package_key(entries, name, reference):
    if not isinstance(reference, str):
        return None
    candidate = reference if reference.startswith(f"{name}@") else f"{name}@{reference}"
    if candidate in entries:
        return candidate
    plain = candidate.split("(", 1)[0]
    matches = [key for key in entries if key.split("(", 1)[0] == plain]
    return matches[0] if len(matches) == 1 else None


def _pnpm_dependency_reaches(
    lock, root_name, target_name, target_nodes, verified_versions=(), *, root_nodes=None
):
    """Follow pnpm edges from a direct package or exact installed nodes."""
    if root_nodes is None:
        importer = lock.get("importers", {}).get(".", {})
        if not isinstance(importer, dict):
            return False
        direct_version = None
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            entry = importer.get(section, {}).get(root_name)
            if isinstance(entry, dict):
                direct_version = entry.get("version")
            elif isinstance(entry, str):
                direct_version = entry
            if isinstance(direct_version, str):
                break
        if not isinstance(direct_version, str):
            return False
    snapshot_entries = lock.get("snapshots", {})
    if not isinstance(snapshot_entries, dict):
        snapshot_entries = {}
    entries = {
        key: entry
        for key, entry in snapshot_entries.items()
        if isinstance(key, str) and isinstance(entry, dict)
    }
    if not entries:
        package_entries = lock.get("packages", {})
        if isinstance(package_entries, dict):
            entries = {
                key: entry
                for key, entry in package_entries.items()
                if isinstance(key, str) and isinstance(entry, dict)
            }

    verified_versions = {
        version.split("(", 1)[0]
        for version in verified_versions
        if isinstance(version, str)
    }

    if root_nodes is not None:
        roots = [node for node in root_nodes if node in entries]
    else:
        root_reference = (
            direct_version
            if direct_version.startswith(f"{root_name}@")
            else f"{root_name}@{direct_version}"
        )
        roots = [key for key in entries if key == root_reference]
        if not roots:
            plain_root = root_reference.split("(", 1)[0]
            matches = [key for key in entries if key.split("(", 1)[0] == plain_root]
            roots = matches if len(matches) == 1 else []
    if not roots:
        return False
    queue, visited = list(roots), set()
    while queue:
        node = queue.pop()
        if node in visited:
            continue
        visited.add(node)
        entry = entries.get(node)
        if not isinstance(entry, dict):
            continue
        plain_node = node.split("(", 1)[0]
        plain_targets = {target for target in target_nodes if "(" not in target}
        if plain_node.rsplit("@", 1)[0] == target_name and (
            node in target_nodes
            or (
                plain_node in plain_targets
                and plain_node.rsplit("@", 1)[-1] in verified_versions
            )
        ):
            return True
        for section in ("dependencies", "optionalDependencies"):
            dependencies = entry.get(section, {})
            if not isinstance(dependencies, dict):
                continue
            for dependency, reference in dependencies.items():
                child = _pnpm_package_key(entries, dependency, reference)
                if child is None:
                    continue
                plain_child = child.split("(", 1)[0]
                plain_targets = {target for target in target_nodes if "(" not in target}
                exact_match = child in target_nodes
                plain_version_match = (
                    plain_child in plain_targets
                    and plain_child.rsplit("@", 1)[-1] in verified_versions
                )
                if dependency == target_name and (exact_match or plain_version_match):
                    return True
                queue.append(child)
    return False


def _package_nodes_for_versions(lock, name, source, versions):
    """Return exact installed package nodes for verified patched versions."""
    versions = {version.split("(", 1)[0] for version in versions}
    if not versions:
        return set()
    if source == "npm":
        return {
            node
            for node, version in package_paths(lock, name, source).items()
            if version.split("(", 1)[0] in versions
        }
    return {
        path.split("/", 1)[1]
        for path, version in package_paths(lock, name, source).items()
        if path.split("/", 1)[0] in ("packages", "snapshots")
        and version.split("(", 1)[0] in versions
    }


def _confirmed_parent_change(
    data, confirmed_ids, before_snapshot, after_snapshot, source, direct_name
):
    """Prove a changed direct parent was needed for a confirmed child fix."""
    if not isinstance(data, dict) or not isinstance(confirmed_ids, set):
        return False
    if source == "pnpm":
        before_lock = yaml.safe_load(before_snapshot[1]["pnpm-lock.yaml"])
        after_lock = yaml.safe_load(after_snapshot[1]["pnpm-lock.yaml"])
    else:
        before_lock, after_lock = before_snapshot[3], after_snapshot[3]
    for child_name, vulnerability in data.get("vulnerabilities", {}).items():
        details = vulnerability.get("via", []) if source == "pnpm" else [vulnerability]
        for detail in details:
            if not isinstance(detail, dict):
                continue
            identity = detail.get("url") if source == "pnpm" else child_name
            if identity not in confirmed_ids or child_name == direct_name:
                continue
            if package_paths(before_lock, child_name, source) == package_paths(
                after_lock, child_name, source
            ):
                continue
            target_nodes = {
                node for node in detail.get("nodes", []) if isinstance(node, str)
            }
            if not target_nodes:
                continue
            patched_nodes = _package_nodes_for_versions(
                after_lock,
                child_name,
                source,
                detail.get("_verifiedPatchedVersions", []),
            )
            remaining_versions = set(
                package_paths(after_lock, child_name, source).values()
            )
            remaining_nodes = _package_nodes_for_versions(
                after_lock, child_name, source, remaining_versions
            )
            removed = not (
                _npm_dependency_reaches(
                    after_lock, direct_name, child_name, remaining_nodes
                )
                if source == "npm"
                else _pnpm_dependency_reaches(
                    after_lock,
                    direct_name,
                    child_name,
                    remaining_nodes,
                    remaining_versions,
                )
            )
            if not patched_nodes and not removed:
                continue
            if source == "npm":
                if _npm_dependency_reaches(
                    before_lock, direct_name, child_name, target_nodes
                ) and (
                    removed
                    or _npm_dependency_reaches(
                        after_lock, direct_name, child_name, patched_nodes
                    )
                ):
                    return True
                continue
            if _pnpm_dependency_reaches(
                before_lock,
                direct_name,
                child_name,
                target_nodes,
                detail.get("_verifiedVulnerableVersions", []),
            ) and (
                removed
                or _pnpm_dependency_reaches(
                    after_lock,
                    direct_name,
                    child_name,
                    patched_nodes,
                    detail.get("_verifiedPatchedVersions", []),
                )
            ):
                return True
    return False


def security_only_direct_violation(
    before,
    after,
    affected,
    *,
    confirmed_ids=None,
    audit_before=None,
    source=None,
):
    """Reject direct changes that a security run cannot attribute to a fix."""
    confirmed_ids = set(confirmed_ids or ())
    source = source or (
        audit_before.get("package_manager", "npm")
        if isinstance(audit_before, dict)
        else "npm"
    )
    confirmed_names = _confirmed_package_names(audit_before, source, confirmed_ids)

    def attributable(name):
        return name in confirmed_names or _confirmed_parent_change(
            audit_before,
            confirmed_ids,
            before,
            after,
            source,
            name,
        )

    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        old = before[2].get(section, {})
        new = after[2].get(section, {})
        for name in set(old) | set(new):
            if name not in old or name not in new or old[name] != new[name]:
                if attributable(name):
                    continue
                if name in affected:
                    return (
                        f"{section}.{name} direct dependency changed during "
                        "security-only maintenance without a confirmed security fix"
                    )
                return f"{section}.{name} manifest changed during security-only maintenance"
            old_version = direct_versions(before).get((section, name))
            new_version = direct_versions(after).get((section, name))
            if old_version != new_version:
                if attributable(name):
                    continue
                if name in affected:
                    return (
                        f"{section}.{name} direct dependency resolved version changed "
                        "during security-only maintenance without a confirmed security fix"
                    )
                return (
                    f"{section}.{name} resolved version changed during security-only "
                    "maintenance"
                )
            if direct_reference(before, section, name) != direct_reference(
                after, section, name
            ):
                if attributable(name):
                    continue
                if name in affected:
                    return (
                        f"{section}.{name} direct reference changed during security-only "
                        "maintenance without a confirmed security fix"
                    )
                return (
                    f"{section}.{name} direct reference changed during security-only "
                    "maintenance"
                )

    before_lock = (
        yaml.safe_load(before[1]["pnpm-lock.yaml"]) if source == "pnpm" else before[3]
    )
    after_lock = (
        yaml.safe_load(after[1]["pnpm-lock.yaml"]) if source == "pnpm" else after[3]
    )
    dependency_reaches = (
        _pnpm_dependency_reaches if source == "pnpm" else _npm_dependency_reaches
    )

    def installed_entries(lock):
        """Return concrete installed nodes from the native lockfile."""
        snapshots = lock.get("snapshots", {})
        if source == "pnpm" and isinstance(snapshots, dict) and snapshots:
            entries = snapshots
        else:
            entries = lock.get("packages", {})
        if not isinstance(entries, dict):
            return {}
        return {
            node: entry
            for node, entry in entries.items()
            if isinstance(node, str)
            and ("@" in node if source == "pnpm" else "node_modules/" in node)
        }

    direct_names = {
        name
        for section in ("dependencies", "devDependencies", "optionalDependencies")
        for manifest in (before[2], after[2])
        for name in manifest.get(section, {})
    }
    old_direct_versions, new_direct_versions = (
        direct_versions(before),
        direct_versions(after),
    )
    allowed_roots = {
        name
        for name in direct_names
        if attributable(name)
        and any(
            old_direct_versions.get((section, name))
            != new_direct_versions.get((section, name))
            for section in ("dependencies", "devDependencies", "optionalDependencies")
        )
    }

    def on_remediation_path(lock, nodes, *, patched):
        if not isinstance(audit_before, dict):
            return False
        for child_name, vulnerability in audit_before.get(
            "vulnerabilities", {}
        ).items():
            details = (
                vulnerability.get("via", []) if source == "pnpm" else [vulnerability]
            )
            for detail in details:
                if not isinstance(detail, dict):
                    continue
                identity = detail.get("url") if source == "pnpm" else child_name
                if identity not in confirmed_ids:
                    continue
                versions = detail.get(
                    "_verifiedPatchedVersions"
                    if patched
                    else "_verifiedVulnerableVersions",
                    [],
                )
                targets = (
                    _package_nodes_for_versions(lock, child_name, source, versions)
                    if patched
                    else {
                        node
                        for node in detail.get("nodes", [])
                        if isinstance(node, str)
                    }
                )
                if not targets:
                    continue
                if source == "pnpm":
                    reaches = _pnpm_dependency_reaches(
                        lock, None, child_name, targets, versions, root_nodes=nodes
                    )
                else:
                    reaches = _npm_dependency_reaches(
                        lock, None, child_name, targets, root_nodes=nodes
                    )
                if reaches:
                    return True
        return False

    before_entries = installed_entries(before_lock)
    after_entries = installed_entries(after_lock)

    remediation_roots_before, remediation_roots_after = set(), set()

    def unrelated_reference(node, *, after_node=None):
        after_node = after_node or node
        old_entry, new_entry = before_entries.get(node), after_entries.get(after_node)
        if not isinstance(old_entry, dict) or not isinstance(new_entry, dict):
            return None
        if source == "npm" and old_entry.get("version") != new_entry.get("version"):
            return None
        for section in ("dependencies", "optionalDependencies"):
            old_edges, new_edges = (
                old_entry.get(section, {}),
                new_entry.get(section, {}),
            )
            if not isinstance(old_edges, dict) or not isinstance(new_edges, dict):
                return f"{node} has unverifiable dependency references during security-only maintenance"
            for dependency in old_edges.keys() | new_edges.keys():
                if source == "pnpm":
                    old_child = _pnpm_package_key(
                        before_entries, dependency, old_edges.get(dependency)
                    )
                    new_child = _pnpm_package_key(
                        after_entries, dependency, new_edges.get(dependency)
                    )
                else:
                    old_child = (
                        _npm_dependency_node(
                            before_lock.get("packages", {}), node, dependency
                        )
                        if dependency in old_edges
                        else None
                    )
                    new_child = (
                        _npm_dependency_node(
                            after_lock.get("packages", {}), after_node, dependency
                        )
                        if dependency in new_edges
                        else None
                    )
                old_package = before_entries.get(old_child, {})
                new_package = after_entries.get(new_child, {})
                resolved_change = old_child != new_child
                if (
                    source == "npm"
                    and isinstance(old_package, dict)
                    and isinstance(new_package, dict)
                ):
                    resolved_change = resolved_change or any(
                        old_package.get(key) != new_package.get(key)
                        for key in ("version", "resolved", "integrity")
                    )
                if (
                    old_edges.get(dependency) == new_edges.get(dependency)
                    and not resolved_change
                ):
                    continue
                if on_remediation_path(
                    before_lock, {old_child} if old_child else set(), patched=False
                ) and (
                    dependency not in new_edges
                    or on_remediation_path(
                        after_lock, {new_child} if new_child else set(), patched=True
                    )
                ):
                    if source == "pnpm":
                        old_version = (
                            stable_version(
                                old_child.split("(", 1)[0].rsplit("@", 1)[-1]
                            )
                            if old_child
                            else None
                        )
                        new_version = (
                            stable_version(
                                new_child.split("(", 1)[0].rsplit("@", 1)[-1]
                            )
                            if new_child
                            else None
                        )
                    else:
                        old_version = (
                            stable_version(old_package.get("version"))
                            if isinstance(old_package, dict)
                            else None
                        )
                        new_version = (
                            stable_version(new_package.get("version"))
                            if isinstance(new_package, dict)
                            else None
                        )
                    if old_version is not None and dependency not in new_edges:
                        remediation_roots_before.add(old_child)
                    elif (
                        old_version is not None
                        and new_version is not None
                        and old_version != new_version
                    ):
                        remediation_roots_before.add(old_child)
                        remediation_roots_after.add(new_child)
                    continue
                return (
                    f"{dependency} dependency reference changed during security-only "
                    "maintenance without a confirmed security fix"
                )
        return None

    if source == "pnpm":
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            for name in before[2].get(section, {}):
                if old_direct_versions.get((section, name)) != new_direct_versions.get(
                    (section, name)
                ):
                    continue
                old_reference = direct_reference(before, section, name)
                new_reference = direct_reference(after, section, name)
                if old_reference == new_reference:
                    continue
                old_root = _pnpm_package_key(
                    before_entries,
                    name,
                    old_reference.get("version")
                    if isinstance(old_reference, dict)
                    else old_reference,
                )
                new_root = _pnpm_package_key(
                    after_entries,
                    name,
                    new_reference.get("version")
                    if isinstance(new_reference, dict)
                    else new_reference,
                )
                if old_root is None or new_root is None:
                    return f"{section}.{name} has an unverifiable direct dependency reference"
                violation = unrelated_reference(old_root, after_node=new_root)
                if violation:
                    return violation

    reference_violations = {
        node: unrelated_reference(node)
        for node in before_entries.keys() | after_entries.keys()
    }
    for node in before_entries.keys() | after_entries.keys():
        reference_violation = reference_violations[node]
        if (
            before_entries.get(node) == after_entries.get(node)
            and not reference_violation
        ):
            continue
        name = (
            node.split("(", 1)[0].rsplit("@", 1)[0]
            if source == "pnpm"
            else node.rsplit("node_modules/", 1)[-1]
        )
        old_nodes = {node} if node in before_entries else set()
        new_nodes = {node} if node in after_entries else set()

        def reaches_from(roots):
            return any(
                (old_nodes and dependency_reaches(before_lock, root, name, old_nodes))
                or (new_nodes and dependency_reaches(after_lock, root, name, new_nodes))
                for root in roots
            )

        if reaches_from(allowed_roots):
            continue
        if reference_violation:
            if reaches_from(direct_names):
                return reference_violation
            continue
        if (
            old_nodes
            and dependency_reaches(
                before_lock, None, name, old_nodes, root_nodes=remediation_roots_before
            )
        ) or (
            new_nodes
            and dependency_reaches(
                after_lock, None, name, new_nodes, root_nodes=remediation_roots_after
            )
        ):
            continue
        if on_remediation_path(
            before_lock, old_nodes, patched=False
        ) or on_remediation_path(after_lock, new_nodes, patched=True):
            continue
        if not reaches_from(direct_names):
            continue
        return (
            f"{name} transitive dependency changed during security-only "
            "maintenance without a confirmed security fix"
        )

    return None


def audit_entries(data, source):
    if isinstance(data, str):
        return []
    return [
        (detail["url"] if source == "pnpm" else name, name, detail)
        for name, vulnerability in data.get("vulnerabilities", {}).items()
        for detail in (
            [via for via in vulnerability.get("via", []) if isinstance(via, dict)]
            if source == "pnpm"
            else [vulnerability]
        )
    ]


def newly_reported_findings(before, after, source):
    old, current = finding_ids(before, source), finding_ids(after, source)
    if old is None or current is None:
        return set()
    added = current - old
    if source == "npm":
        # npm counts affected packages, but an existing entry can gain advisories.
        for name, vulnerability in after.get("vulnerabilities", {}).items():
            previous = before.get("vulnerabilities", {}).get(name, {})
            old_urls, current_urls = (
                {via["url"] for via in entry.get("via", []) if isinstance(via, dict)}
                for entry in (previous, vulnerability)
            )
            if current_urls - old_urls:
                added.add(name)
    return added


def npm_advisory_sources(data, name):
    """Follow propagated npm findings to their direct advisory records."""
    if not isinstance(data, dict):
        return {}, False
    findings = data.get("vulnerabilities", {})
    pending, visited, sources = [name], set(), {}
    complete = True
    while pending:
        package = pending.pop()
        if package in visited:
            continue
        visited.add(package)
        via = findings.get(package, {}).get("via", [])
        if not via:
            complete = False
        for detail in via:
            if isinstance(detail, str):
                pending.append(detail)
            elif (
                isinstance(detail, dict)
                and isinstance(detail.get("url"), str)
                and detail["url"]
            ):
                sources.setdefault(package, {})[detail["url"]] = detail
            else:
                complete = False
    return sources, complete and bool(sources)


def _npm_vulnerable_nodes(data, lock, name):
    vulnerability = data.get("vulnerabilities", {}).get(name, {})
    nodes = vulnerability.get("nodes")
    if isinstance(nodes, list):
        recorded = {node for node in nodes if isinstance(node, str) and node}
        if recorded:
            return recorded
    return set(package_paths(lock, name, "npm"))


def _npm_reachable_nodes(lock, root, target_name, target_nodes):
    return {
        node
        for node in target_nodes
        if _npm_dependency_reaches(
            lock,
            None,
            target_name,
            {node},
            root_nodes=[root],
            include_peer_dependencies=True,
        )
    }


def reported_parent_findings(before, after, source, before_lock, after_lock):
    """Identify new parent entries backed only by unchanged existing findings."""
    if source != "npm" or not isinstance(before, dict) or not isinstance(after, dict):
        return {}
    parents = {}
    for name in newly_reported_findings(before, after, source):
        if name in before.get("vulnerabilities", {}):
            continue
        via = after["vulnerabilities"][name].get("via", [])
        if not via or not all(isinstance(detail, str) for detail in via):
            continue
        old_paths = package_paths(before_lock, name, source)
        if not old_paths or old_paths != package_paths(after_lock, name, source):
            continue
        if any(
            before_lock["packages"][node] != after_lock["packages"][node]
            for node in old_paths
        ):
            continue
        parent_after = set(package_paths(after_lock, name, source))
        recorded_parent_nodes = after["vulnerabilities"][name].get("nodes")
        if isinstance(recorded_parent_nodes, list):
            parent_roots = {
                node for node in recorded_parent_nodes if isinstance(node, str) and node
            }
            if not parent_roots or not parent_roots <= parent_after:
                continue
        else:
            parent_roots = parent_after
        # A previously unrelated dependency can become vulnerable through an
        # already installed advisory source. Retain the warning for that case.
        existing_chain = True
        for dependency in via:
            previous_sources, previous_complete = npm_advisory_sources(
                before, dependency
            )
            current_sources, current_complete = npm_advisory_sources(after, dependency)
            if (
                not previous_complete
                or not current_complete
                or any(
                    not details.keys() <= previous_sources.get(package, {}).keys()
                    for package, details in current_sources.items()
                )
            ):
                existing_chain = False
                break
        if not existing_chain:
            continue
        sources, complete = npm_advisory_sources(after, name)
        if not complete:
            continue
        for package, advisories in sources.items():
            previous, previous_complete = npm_advisory_sources(before, package)
            existing = previous.get(package, {})
            paths = package_paths(before_lock, package, source)
            if (
                not previous_complete
                or not advisories.keys() <= existing.keys()
                or not paths
                or paths != package_paths(after_lock, package, source)
                or before["vulnerabilities"][package].get("nodes")
                != after["vulnerabilities"][package].get("nodes")
            ):
                break
            before_nodes = _npm_vulnerable_nodes(before, before_lock, package)
            after_nodes = _npm_vulnerable_nodes(after, after_lock, package)
            if not before_nodes or not after_nodes:
                break
            for root in parent_roots:
                before_reachable = _npm_reachable_nodes(
                    before_lock, root, package, before_nodes
                )
                after_reachable = _npm_reachable_nodes(
                    after_lock, root, package, after_nodes
                )
                if (
                    not before_reachable
                    or not after_reachable
                    or before_reachable != after_reachable
                ):
                    break
            else:
                continue
            break
        else:
            parents[name] = sorted(sources)
    return parents


def _advisory_link_items(data, name, source, fixed_ids):
    if source == "npm":
        sources, _ = npm_advisory_sources(data, name)
        urls = {url for details in sources.values() for url in details}
    else:
        urls = {
            identity
            for identity, package, _ in audit_entries(data, source)
            if package == name and identity in fixed_ids
        }
    links = []
    for url in sorted(urls):
        # Keep registry-supplied URLs inside one Markdown table cell and link.
        if not re.fullmatch(r"https?://[^\s<>()\[\]|`]+", url):
            continue
        label = url.rstrip("/").rsplit("/", 1)[-1]
        if not re.fullmatch(r"GHSA-[a-z0-9-]+", label):
            label = "Advisory"
        links.append(f"[{label}]({url})")
    return links


def advisory_links(data, name, source, fixed_ids):
    links = _advisory_link_items(data, name, source, fixed_ids)
    return ", ".join(links) or f"Advisory URL not supplied by {source}."


def compact_advisory_links(data, name, source, fixed_ids):
    links = _advisory_link_items(data, name, source, fixed_ids)
    if not links:
        return f"Advisory URL not supplied by {source}."
    additional = len(links) - 1
    if additional:
        unit = "advisory" if additional == 1 else "advisories"
        return f"{links[0]} (+{additional} additional {unit}; see full audit details)"
    return links[0]


def package_advisory_links(before, after, name, source, resolved, pending):
    links = sorted(
        set(
            (_advisory_link_items(before, name, source, resolved) if resolved else [])
            + (_advisory_link_items(after, name, source, pending) if pending else [])
        )
    )
    if not links:
        return f"Not supplied by {source}."
    count = len(links) - 1
    return links[0] + (
        f" (+{count} additional {'advisory' if count == 1 else 'advisories'}; see full audit details)"
        if count
        else ""
    )


def audit_fix_reason(detail, source):
    status = detail.get("fixStatus", "")
    if "no single patch satisfies all" in status:
        parents = sorted(set(re.findall(r"`([^`]+)` requires `[^`]+`", status)))
        if len(parents) == 1:
            return (
                "blocked",
                f"Blocked by the `{parents[0].rsplit('@', 1)[0]}` version constraint.",
            )
        return "blocked", "No published patch fits all checked parent constraints."
    if "Blocked by retained override" in status:
        return "review", "A retained override blocks the published patch."
    if status.startswith("No published stable patch"):
        return "blocked", "No published patch matches the fix range."
    if status.startswith("No patched version declared"):
        return "blocked", "The registry supplies no patched version."
    if "could not be fully verified" in status:
        return "unconfirmed", "Patch compatibility still needs verification."
    if status.startswith("Published patch:"):
        return "review", "A published patch is available; selection needs review."
    candidate = detail.get("fixAvailable")
    if isinstance(candidate, dict) and candidate.get("isSemVerMajor"):
        return "review", "The offered fix requires a major upgrade."
    if source == "npm" and not candidate:
        return "blocked", "No fix offered by npm."
    return "unconfirmed", "Fix availability or resolution is unconfirmed."


def format_blocked_findings(data, source):
    """Return a neutral table only when every reported finding has a known blocker."""
    entries = audit_entries(data, source)
    if not entries or any(
        audit_fix_reason(detail, source)[0] != "blocked" for _, _, detail in entries
    ):
        return None
    groups: dict = {}
    for identity, name, detail in entries:
        groups.setdefault(name, {})[identity] = detail
    unit = "Blocked advisories" if source == "pnpm" else "Blocked package entries"
    rows = [f"| Package | {unit} | Reason |", "| --- | --- | --- |"]
    for name, findings in sorted(
        groups.items(),
        key=lambda item: (
            min(
                SEVERITY_ORDER.get(detail.get("severity"), 5)
                for detail in item[1].values()
            ),
            item[0],
        ),
    ):
        counts = {}
        for detail in findings.values():
            severity = detail.get("severity", "unknown")
            counts[severity] = counts.get(severity, 0) + 1
        severities = " · ".join(
            f"{counts[level]} {level}"
            for level in sorted(counts, key=lambda level: SEVERITY_ORDER.get(level, 5))
        )
        reasons = " ".join(
            dict.fromkeys(
                audit_fix_reason(detail, source)[1] for detail in findings.values()
            )
        )
        rows.append(f"| `{name}` | {severities} | {reasons} |")
    return "\n".join(rows)


def format_audit_summary(
    before: dict | str,
    after: dict | str,
    source: str,
    *,
    fixed_ids=None,
    fixes_only=False,
    reported_parents=None,
    locks=None,
    summary=None,
    repair_options=None,
    repair_revision=None,
) -> str:
    if isinstance(after, str):
        return "" if fixes_only else f"⚪ **Security:** {after}"

    def complete(data, rows):
        return isinstance(data, dict) and (
            bool(rows)
            or not any(
                data["metadata"]["vulnerabilities"].get(level, 0)
                for level in SEVERITY_ORDER
            )
        )

    old, current = audit_entries(before, source), audit_entries(after, source)
    old_ids, current_ids = {row[0] for row in old}, {row[0] for row in current}
    comparable = complete(before, old) and complete(after, current)
    resolved_ids = old_ids - current_ids if comparable else set()
    if fixed_ids is not None:
        resolved_ids &= fixed_ids
    unconfirmed_ids = (
        (old_ids - current_ids) - resolved_ids if fixed_ids is not None else set()
    )
    reported_parents = reported_parents or {}
    new_ids = (
        newly_reported_findings(before, after, source) - reported_parents.keys()
        if comparable
        else set()
    )
    old_groups: dict = {}
    groups: dict = {}
    for rows, target in ((old, old_groups), (current, groups)):
        for identity, name, detail in rows:
            target.setdefault(name, {})[identity] = detail

    rows = []
    old_versions, new_versions = (
        (locked_version_sets(lock) for lock in locks) if locks else ({}, {})
    )
    fixed_packages, review_packages, blocked_packages = set(), set(), set()
    new_packages, unconfirmed_packages = set(), set()
    repair_options = REPAIR_CHOICES["validate"](repair_options or [])
    repair_names = {item["name"] for item in repair_options}
    selection_block = (
        REPAIR_CHOICES["render"](repair_options, **repair_revision)
        if repair_revision is not None
        else ""
    )
    for name in old_groups.keys() | groups.keys():
        previous, pending = old_groups.get(name, {}), groups.get(name, {})
        fixed = len(resolved_ids.intersection(previous))
        if fixes_only and not fixed:
            continue
        unconfirmed_disappeared = set(previous).intersection(unconfirmed_ids)
        unconfirmed_details = [
            previous[identity] for identity in unconfirmed_disappeared
        ]
        # An advisory reported under another path is still open, not resolved.
        moved = set(previous).intersection(current_ids) - pending.keys()
        pending_count = len(pending.keys() | moved)
        details = list(pending.values())
        outcomes = [audit_fix_reason(detail, source) for detail in details]
        statuses = [detail.get("fixStatus", "") for detail in details]
        pinned = any("Blocked by retained override" in status for status in statuses)
        review = pinned or any(kind == "review" for kind, _ in outcomes)
        blocked = any(kind == "blocked" for kind, _ in outcomes) or any(
            "no single patch satisfies all" in status for status in statuses
        )
        unconfirmed = any(kind == "unconfirmed" for kind, _ in outcomes)
        if fixed:
            fixed_packages.add(name)
        if review:
            review_packages.add(name)
        if blocked:
            blocked_packages.add(name)
        if unconfirmed:
            unconfirmed_packages.add(name)
        if unconfirmed_disappeared:
            unconfirmed_packages.add(name)
        action = " ".join(dict.fromkeys(text for _, text in outcomes))
        if unconfirmed_disappeared:
            ranges = sorted(
                {
                    detail.get("range")
                    for detail in unconfirmed_details
                    if isinstance(detail.get("range"), str) and detail.get("range")
                }
            )
            action = (
                (action + " ") if action else ""
            ) + "No longer reported; fix could not be confirmed."
            if ranges:
                action += (
                    " Original affected range: "
                    + ", ".join(f"`{value}`" for value in ranges)
                    + "."
                )
        if pinned:
            pins = sorted(
                {
                    match
                    for status in statuses
                    for match in re.findall(
                        rf"`pnpm-workspace\.yaml overrides\.{re.escape(name)}` = `([^`]+)`",
                        status,
                    )
                }
            )
            patches = sorted(
                {
                    match
                    for status in statuses
                    for match in re.findall(
                        rf"Published patch: `{re.escape(name)}@([^`]+)`", status
                    )
                }
            )
            pin, candidate = (
                (", ".join(values) or "see advisory details").replace("|", "&#124;")
                for values in (pins, patches)
            )
            action = f"Pin `{pin}` blocks fix `{candidate}`; review removing or updating the pin."
            if any("no single patch satisfies all" in status for status in statuses):
                action += " Parent constraints also block the fix; see details."
            extra = [
                audit_fix_reason(detail, source)[1]
                for detail in details
                if "Blocked by retained override" not in detail.get("fixStatus", "")
            ]
            if extra:
                action += " " + " ".join(dict.fromkeys(extra))
        if moved:
            locations = sorted(
                {other for identity, other, _ in current if identity in moved}
            )
            action += (
                " Still reported under "
                + ", ".join(f"`{other}`" for other in locations)
                + "."
            )
        if name in repair_names:
            action = "Likely feasible. Repair validation has not run. " + action
        new_count = len(new_ids.intersection(pending))
        if new_count:
            new_packages.add(name)
            unit = (
                ("advisory" if new_count == 1 else "advisories")
                if source == "pnpm"
                else (
                    "affected package entry"
                    if new_count == 1
                    else "affected package entries"
                )
            )
            action = (
                "New advisories reported for this affected package entry. "
                if source == "npm" and name in old_groups
                else f"{new_count} new {unit}. "
            ) + action
        if name in reported_parents:
            source_packages = ", ".join(
                f"`{package}`" for package in reported_parents[name]
            )
            action = (
                f"Newly reported parent of an existing finding in {source_packages}; "
                "affected versions and installed paths are unchanged. "
            ) + action
        counts = []
        if fixed:
            counts.append(f"{fixed} fixed")
        if pending_count:
            counts.append(f"{pending_count} pending")
        if unconfirmed_disappeared:
            counts.append(f"{len(unconfirmed_disappeared)} unconfirmed")
        if not comparable:
            counts.insert(0, "fixes unconfirmed")
        if comparable and not pending_count and not unconfirmed_disappeared:
            badge, rank, action = "🟢", 0, "Resolved."
        elif new_count:
            badge, rank = "🔴", 2
        elif blocked:
            badge, rank = "", 2
        elif review:
            badge, rank = "🟠", 1
        else:
            badge, rank = "⚪", 3
        severity_details = details + unconfirmed_details + list(previous.values())
        severity = min(
            (SEVERITY_ORDER.get(detail["severity"], 5) for detail in severity_details),
            default=5,
        )
        severity_label = next(
            (
                level.title()
                for level, order in SEVERITY_ORDER.items()
                if order == severity
            ),
            "Unknown",
        )
        old_version = ", ".join(sorted(old_versions.get(name, set())))
        new_version = ", ".join(sorted(new_versions.get(name, set())))
        version_change = (
            f"`{old_version or 'not installed'}` → `{new_version or 'not installed'}`"
            if old_version != new_version
            else f"`{new_version}` (unchanged)"
            if new_version
            else "Not recorded"
        )
        label = {
            "🟢": "✅ Fix proposed. ",
            "🟠": "🟡 Needs review. ",
            "🔴": "🔴 New findings. ",
            "⚪": "⚪ Needs verification. ",
            "": "🔴 Blocked. ",
        }[badge]
        if blocked and review:
            label += "🟡 Needs review. "
        rows.append(
            (
                (rank, severity, name),
                [
                    f"`{name}`",
                    version_change,
                    severity_label,
                    " · ".join(counts),
                    label + action.strip(),
                    package_advisory_links(
                        before,
                        after,
                        name,
                        source,
                        resolved_ids.intersection(previous)
                        if fixes_only
                        else set(previous),
                        set() if fixes_only else set(pending),
                    ),
                ],
            )
        )

    def packages(number):
        return f"{number} package" + ("" if number == 1 else "s")

    if fixes_only and not fixed_packages:
        return ""
    if not comparable:
        headline = "⚪ **Fixes unconfirmed**"
    elif fixed_packages:
        headline = f"🟢 **Fixes in {packages(len(fixed_packages))}**"
    elif current_ids:
        headline = "⚪ **No security fixes**"
    else:
        headline = "🟢 **No security findings**"
    if new_packages:
        headline += f" · 🔴 **New findings in {packages(len(new_packages))}**"
    if review_packages:
        verb = "needs" if len(review_packages) == 1 else "need"
        headline += f" · 🟡 **{packages(len(review_packages))} {verb} your review**"
    if blocked_packages:
        headline += f" · 🔴 **Fixes blocked for {packages(len(blocked_packages))}**"
    if unconfirmed_packages:
        verb = "needs" if len(unconfirmed_packages) == 1 else "need"
        headline += (
            f" · ⚪ **{packages(len(unconfirmed_packages))} {verb} verification**"
        )
    if not comparable:
        headline += "\n\nResolution unconfirmed; initial or detailed audit evidence unavailable."
    if summary is not None:
        summary.update(
            review_count=len(review_packages), fixed_packages=len(fixed_packages)
        )
    if rows:
        unit = "Advisories" if source == "pnpm" else "Affected package entries"
        if repair_options:

            def cell(value):
                escaped = html.escape(html.unescape(value))
                escaped = re.sub(r"`([^`]+)`", r"<code>\1</code>", escaped)
                return re.sub(
                    r"\[([^\]]+)\]\((https?://[^ )]+)\)",
                    r'<a href="\2">\1</a>',
                    escaped,
                )

            options = {item["name"]: item for item in repair_options}
            table = [
                "<table>\n<thead><tr>"
                + "".join(
                    f"<th>{value}</th>"
                    for value in (
                        "Package",
                        "Update",
                        "Severity",
                        unit,
                        "Action / blocker",
                        "Security evidence",
                    )
                )
                + "</tr></thead>\n<tbody>"
            ]
            for (_, _, name), columns in sorted(rows):
                table.append(
                    "<tr>"
                    + "".join(f"<td>{cell(value)}</td>" for value in columns)
                    + "</tr>"
                )
                if name not in options:
                    continue
                item = options[name]
                evidence = []
                for detail in groups.get(name, {}).values():
                    evidence.extend(
                        html.escape(value)
                        for value in detail.get("_checkedParentConstraints", [])
                    )
                    url = detail.get("url", "")
                    if isinstance(url, str) and re.fullmatch(
                        r"https?://[^\s<>()\[\]|`]+", url
                    ):
                        evidence.append(
                            f'<a href="{html.escape(url, quote=True)}">{html.escape(detail.get("title", "Advisory"))}</a>'
                        )
                table.append(
                    '<tr><td colspan="6"><details><summary>Pin repair assessment for '
                    + html.escape(name)
                    + "</summary><p>A compatible published patch was found: <code>"
                    + html.escape(item["to"])
                    + "</code>. Repair validation has not run. "
                    "An attempt must pass a frozen install, the configured project checks and a fresh audit before publication.</p>"
                    "<p>The existing pin remains unchanged. Historical rationale has not been collected automatically.</p><ul>"
                    + "".join(f"<li>{value}</li>" for value in dict.fromkeys(evidence))
                    + "</ul></details></td></tr>"
                )
            return (
                headline
                + "\n\n"
                + "\n".join(table)
                + "\n</tbody>\n</table>\n"
                + selection_block
            )
        headline += (
            f"\n\n| Package | Update | Severity | {unit} | Action / blocker | Security evidence |"
            + "\n| --- | --- | --- | --- | --- | --- |"
            + "\n"
        )
        headline += "\n".join(
            "| " + " | ".join(columns) + " |" for _, columns in sorted(rows)
        )
    return headline + selection_block


def format_platform_security(platform, passed):
    if not platform:
        return "No platform upgrade is proposed.\n\n"
    if not platform["target"]:
        return "⚪ " + platform["message"] + "\n\n"
    previous = platform["previous"] or "previous patch not pinned"
    status = (
        "✅ Upgrade validated"
        if passed
        else "⚪ Upgrade validation failed or unavailable"
    )
    text = f"{status}: **Node.js** `{previous} → {platform['target']}`.\n\n"
    if platform["message"]:
        text += platform["message"] + "\n\n"
    text += (
        "| Security release | Highest severity | CVE summary | Details |\n"
        "| --- | --- | --- | --- |\n"
    )
    for release in platform["releases"]:
        version = release["version"]
        severity = (release["severity"] or "unavailable").title()
        cves = release["cves"]
        count = len(cves) if cves is not None else None
        description = (
            f"{count} named CVE" + ("" if count == 1 else "s")
            if count is not None
            else release["message"]
        )
        url = f"https://nodejs.org/en/blog/release/v{version}/"
        text += f"| `{version}` | {severity} | {description} | [CVE list]({url}#notable-changes) · [Release notes]({url}) |\n"
    return text + (
        "\nCVE counts describe each release's notes, not confirmed vulnerabilities in "
        "the starting runtime. They are not added together as a unique-CVE total. "
        "Bundled dependency fixes may address additional vulnerabilities.\n\n"
    )


def format_security_overview(
    *,
    platform,
    package_report,
    package_fixes,
    package_updates,
    review_count,
    passed,
    routine_only=False,
):
    platform_count = int(bool(platform and platform["target"]))
    parts = [
        f"{platform_count} platform security update"
        + ("" if platform_count == 1 else "s")
    ]
    if package_updates:
        parts.append(
            f"{package_updates} {'routine ' if routine_only else ''}dependency update"
            + ("" if package_updates == 1 else "s")
        )
    parts.append(
        f"{package_fixes} package security fix" + ("" if package_fixes == 1 else "es")
        if package_fixes is not None
        else "Package security fixes unconfirmed"
    )
    if review_count:
        parts.append(
            f"🟡 {review_count} package"
            + (" needs" if review_count == 1 else "s need")
            + " your review"
        )
    parts.append("Validation " + ("passed" if passed else "failed or unavailable"))
    return (
        "**"
        + " · ".join(parts)
        + "**\n\n"
        + "## Platform security\n\n"
        + format_platform_security(platform, passed)
        + "## Package security\n\n"
        + package_report
        + "\n\n"
    )


def format_validation(install_status, check_status):
    return (
        "## Validation\n\n"
        f"- Frozen install: {install_status[0].lower() + install_status[1:]}\n"
        f"- Project checks: {check_status[0].lower() + check_status[1:]}\n\n"
    )


def format_change_report(
    proposed_changes: str, security_fixes: str, routine_upgrades: str = ""
) -> str:
    """Keep confirmed fixes visible and the complete version list expandable."""
    return (
        (f"## Security fixes\n\n{security_fixes}\n\n" if security_fixes else "")
        + (
            f"## Direct dependency upgrades\n\n{routine_upgrades}\n\n"
            if routine_upgrades
            else ""
        )
        + "<details>\n<summary>All dependency changes</summary>\n\n"
        + f"{proposed_changes}\n\n</details>\n\n"
    )


def routine_upgrade_rows(initial, security, final, targets):
    """List intentionally selected direct upgrades retained in the final proposal."""
    rows = []
    for section, name in sorted(targets, key=lambda item: (item[1], item[0])):
        current = initial[2].get(section, {}).get(name)
        baseline = security[2].get(section, {}).get(name)
        proposed = final[2].get(section, {}).get(name)
        if proposed is not None and proposed != baseline and proposed != current:
            rows.append((section, name, current, proposed))
    return rows


def release_notes_link(directory, name, version, snapshot, notes, deadline):
    fallback = f"[Package details](https://www.npmjs.com/package/{quote(name, safe='@/')}/v/{quote(version, safe='.')})"
    if stable_version(version) is None or time.monotonic() >= deadline:
        return fallback
    result = run(
        directory,
        "view",
        f"{name}@{version}",
        "repository.url",
        "--json",
        deadline=min(deadline, time.monotonic() + 10),
    )
    if restore_invalid_state(
        directory, snapshot, notes, f"Release notes lookup for {name}", frozen=True
    ):
        return fallback
    try:
        repository = json.loads(result.stdout)
    except ValueError:
        return fallback
    if result.returncode or not isinstance(repository, str):
        return fallback
    match = re.fullmatch(
        r"(?:git\+)?(?:https?|git)://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?",
        repository,
    )
    if match and all(part not in {".", ".."} for part in match.groups()):
        return f"[Releases](https://github.com/{match[1]}/{match[2]}/releases)"
    return fallback


def format_routine_upgrades(rows, links):
    if not rows:
        return ""
    labels = {
        "dependencies": "",
        "devDependencies": " (dev)",
        "optionalDependencies": " (optional)",
    }
    return (
        "| Package | Current | Proposed | Release notes |\n| --- | --- | --- | --- |\n"
        + "\n".join(
            f"| `{name}`{labels[section]} | `{current}` | `{proposed}` | {links[(name, proposed)]} |"
            for section, name, current, proposed in rows
        )
    )


def within_upgrade_scope(before, after, scope):
    return after >= before and (
        scope == "major"
        or (scope == "minor" and after[0] == before[0])
        or (scope == "patch" and after[:2] == before[:2])
    )


def direct_versions(snapshot):
    if "pnpm-lock.yaml" in snapshot[1]:
        return direct_pnpm_versions(snapshot[1])
    packages = snapshot[3].get("packages", {})
    result = {}
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for name in snapshot[2].get(section, {}):
            version = stable_version(
                packages.get(f"node_modules/{name}", {}).get("version")
            )
            if version is not None:
                result[(section, name)] = version
    return result


def direct_reference(snapshot, section, name):
    if "pnpm-lock.yaml" in snapshot[1]:
        lock = yaml.safe_load(snapshot[1]["pnpm-lock.yaml"])
        return lock.get("importers", {}).get(".", {}).get(section, {}).get(name)
    return snapshot[3].get("packages", {}).get(f"node_modules/{name}")


def routine_scope_violation(before, after, scope):
    """Check actual direct specifiers and resolved versions, not just lookups."""
    if scope == "major":
        return None
    old_versions, new_versions = direct_versions(before), direct_versions(after)
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        old, new = before[2].get(section, {}), after[2].get(section, {})
        if set(old) != set(new):
            return f"{section} membership changed"
        for name, specifier in old.items():
            key = (section, name)
            old_floor, new_floor = (
                stable_manifest_minimum(specifier),
                stable_manifest_minimum(new[name]),
            )
            baseline = old_versions.get(key)
            if specifier != new[name] and (
                baseline is None
                or old_floor is None
                or new_floor is None
                or not within_upgrade_scope(max(baseline, old_floor), new_floor, scope)
            ):
                return (
                    f"{section}.{name} manifest requirement exceeds the selected scope"
                )
            resolved = new_versions.get(key)
            if (
                baseline is None
                and resolved is None
                and (
                    direct_reference(before, section, name)
                    != direct_reference(after, section, name)
                )
            ):
                return f"{section}.{name} changed an unverifiable direct reference"
            if baseline != resolved and (
                baseline is None
                or resolved is None
                or not within_upgrade_scope(baseline, resolved, scope)
            ):
                return f"{section}.{name} resolved version exceeds the selected scope"
    return None


def eligible_version(
    directory,
    name,
    latest,
    snapshot,
    notes,
    deadline,
    *,
    baseline=None,
    upgrade_scope="major",
    minimum_release_age=None,
):
    """Select a stable release within the deployment's publication-age policy."""
    result = run(directory, "view", name, "time", "--json", deadline=deadline)
    if restore_invalid_state(
        directory, snapshot, notes, f"Release-time lookup for {name}", frozen=True
    ):
        return None
    try:
        age = (
            yaml.safe_load(snapshot[1]["pnpm-workspace.yaml"])["minimumReleaseAge"]
            if minimum_release_age is None
            else minimum_release_age
        )
        releases = json.loads(result.stdout)
        if (
            result.returncode
            or type(age) is not int
            or age < 0
            or not isinstance(releases, dict)
        ):
            return None
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=age)
        limit = tuple(map(int, latest.split(".")))
        candidates = []
        for version, published in releases.items():
            if not re.fullmatch(r"\d+\.\d+\.\d+", version):
                continue
            number = tuple(map(int, version.split(".")))
            if (
                number <= limit
                and (
                    baseline is None
                    or within_upgrade_scope(baseline, number, upgrade_scope)
                )
                and datetime.fromisoformat(published.replace("Z", "+00:00")) <= cutoff
            ):
                candidates.append((number, version))
        return max(candidates)[1] if candidates else None
    except (KeyError, ValueError, TypeError, AttributeError, OverflowError):
        return None


def locked_version_sets(lock: dict) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for path, package in lock.get("packages", {}).items():
        version = package.get("version")
        name = package.get("name") or (
            path.rsplit("node_modules/", 1)[-1] if "node_modules/" in path else None
        )
        if name and version:
            result.setdefault(name, set()).add(version)
    return result


def locked_changes(before: dict, after: dict) -> list[str]:
    """Compare all locked version sets, independent of advisory attribution."""

    old, new = locked_version_sets(before), locked_version_sets(after)
    return [
        f"- {name}: `{', '.join(sorted(old.get(name, set()))) or 'not installed'}` → "
        f"`{', '.join(sorted(new.get(name, set()))) or 'not installed'}`"
        for name in sorted(old.keys() | new.keys())
        if old.get(name, set()) != new.get(name, set())
    ]


def prepare(
    directory: Path,
    *,
    validation: dict | None = None,
    validation_script="build",
    minimum_release_age_days=10,
    maintenance_mode="security-and-maintenance",
    upgrade_scope="major",
    local_patches=None,
    validate_only=False,
    prepare_only=False,
    platform=None,
) -> str:
    # Leave time in the 60-minute job to write and upload a partial report.
    deadline = time.monotonic() + 45 * 60
    manifest_path = directory / "package.json"
    package_manager = manager(directory)
    if type(minimum_release_age_days) is not int or minimum_release_age_days < 0:
        raise ValueError("minimum release age must be a nonnegative number of days")
    release_before = (
        (
            datetime.now(timezone.utc) - timedelta(days=minimum_release_age_days)
        ).isoformat()
        if package_manager == "npm" and minimum_release_age_days
        else None
    )
    notes = []
    if (unsupported := unsupported_npm_shrinkwrap(directory)) is not None:
        raise ValueError(
            f"{unsupported.name} is unsupported; mixed npm lockfiles are not supported; remove it and use package-lock.json only"
        )
    initial_snapshot = valid_snapshot(directory)
    if initial_snapshot is None:
        raise ValueError(
            "Valid manifest, one deployment lockfile and package-manager policy are required"
        )
    declared_patches = LOCAL_PATCHES["validate_declarations"](local_patches or [])
    scripts = initial_snapshot[2].get("scripts", {})
    if (
        not isinstance(validation_script, str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9:_.-]*", validation_script) is None
        or not isinstance(scripts, dict)
        or not isinstance(scripts.get(validation_script), str)
        or not scripts[validation_script].strip()
    ):
        raise ValueError(
            "Selected validation script must name an existing nonempty package.json script"
        )
    if maintenance_mode not in ("security-only", "security-and-maintenance"):
        raise ValueError("Invalid maintenance mode")
    if upgrade_scope not in ("patch", "minor", "major"):
        raise ValueError("Invalid maintenance upgrade scope")
    before_lock = initial_snapshot[3]
    before = audit(directory, deadline=deadline)
    if restore_invalid_state(
        directory, initial_snapshot, notes, "Initial audit", frozen=True
    ):
        before = f"Audit unavailable: {package_manager} changed package files; restored the initial snapshot."
    initial_audit_available = isinstance(before, dict)
    if not initial_audit_available:
        notes.append(
            "Initial audit evidence was unavailable; retained security-fix changes "
            "are unconfirmed."
        )
    last_valid_snapshot = valid_snapshot(directory) or initial_snapshot
    affected = (
        set(before.get("vulnerabilities", {})) if isinstance(before, dict) else set()
    )
    changes = []
    routine_targets = set()
    cache: dict = {}
    proposal_complete = True

    # Give compatible security fixes the first use of the shared time budget.
    fixed = (
        subprocess.CompletedProcess([], 0, "", "")
        if validate_only
        or maintenance_mode == "security-only"
        and isinstance(before, dict)
        and not affected
        else fix_security(
            directory,
            deadline,
            notes,
            cache,
            before=before,
            release_before=release_before,
        )
    )
    if restore_invalid_state(
        directory, last_valid_snapshot, notes, "Initial security fix", security_fix=True
    ):
        proposal_complete = False
    if fixed.returncode:
        proposal_complete = False
        notes.append(
            f"Initial security fix returned exit {fixed.returncode}; remaining findings "
            "or a tool error require manual review."
        )
    # Preserve those fixes if the wider stable-version upgrade cannot resolve.
    security_snapshot = valid_snapshot(directory) or last_valid_snapshot
    if maintenance_mode == "security-only" and security_snapshot != initial_snapshot:
        evidence = audit(directory, deadline=deadline)
        if restore_invalid_state(
            directory,
            security_snapshot,
            notes,
            "Security fix confirmation",
            frozen=True,
        ):
            evidence = "Audit unavailable: confirmation changed package files."
        confirmation = confirmed_fixes(
            before, evidence, package_manager, initial_snapshot, security_snapshot
        )
        direct_violation = security_only_direct_violation(
            initial_snapshot,
            security_snapshot,
            affected,
            confirmed_ids=confirmation,
            audit_before=before,
            source=package_manager,
        )
        if not confirmation or direct_violation:
            proposal_complete = False
            restore_snapshot(directory, initial_snapshot)
            security_snapshot = initial_snapshot
            notes.append(
                "Discarded dependency changes: "
                + (
                    direct_violation + "."
                    if direct_violation
                    else "no confirmed security fixes."
                )
                + " Routine upgrades require an upgrades run."
            )
    last_valid_snapshot = security_snapshot
    if maintenance_mode == "security-and-maintenance" and not validate_only:
        manifest = json.loads(security_snapshot[0])

        # Preserve overrides and peer constraints for a maintainer to review.
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            for name, current in sorted(
                manifest.get(section, {}).items(),
                key=lambda item: (item[0] not in affected, item[0]),
            ):
                if not re.fullmatch(r"[~^]?\d+\.\d+\.\d+", current):
                    notes.append(
                        f"Retained {name} specifier `{current}` for manual review."
                    )
                    continue
                resolved = direct_versions(security_snapshot).get((section, name))
                if upgrade_scope != "major" and resolved is None:
                    notes.append(
                        f"Retained {name}: resolved direct version is unavailable for maintenance.upgradeScope={upgrade_scope}."
                    )
                    continue
                floor = max(
                    stable_manifest_minimum(current),
                    resolved or stable_manifest_minimum(current),
                )
                lookup = (
                    (f"{name}@latest", "version")
                    if upgrade_scope == "major"
                    else (name, "versions")
                )
                result = run(
                    directory,
                    "view",
                    *lookup,
                    "--json",
                    deadline=deadline,
                )
                if restore_invalid_state(
                    directory,
                    security_snapshot,
                    notes,
                    f"Version lookup for {name}",
                    frozen=True,
                ):
                    continue
                try:
                    latest = json.loads(result.stdout)
                except json.JSONDecodeError:
                    latest = None
                if upgrade_scope != "major":
                    candidates = latest if isinstance(latest, list) else [latest]
                    eligible = [
                        value
                        for value in candidates
                        if stable_version(value) is not None
                        and within_upgrade_scope(
                            floor, stable_version(value), upgrade_scope
                        )
                    ]
                    latest = max(eligible, key=stable_version) if eligible else None
                if (
                    result.returncode
                    or not isinstance(latest, str)
                    or not re.fullmatch(r"\d+\.\d+\.\d+", latest)
                ):
                    proposal_complete = False
                    notes.append(f"Could not look up {name}; retained `{current}`.")
                    continue
                if latest != current.lstrip("~^") and (
                    package_manager == "pnpm" or minimum_release_age_days
                ):
                    latest = eligible_version(
                        directory,
                        name,
                        latest,
                        security_snapshot,
                        notes,
                        deadline,
                        baseline=floor if upgrade_scope != "major" else None,
                        upgrade_scope=upgrade_scope,
                        minimum_release_age=(
                            minimum_release_age_days * 1440
                            if package_manager == "npm"
                            else None
                        ),
                    )
                    if latest is None:
                        proposal_complete = False
                        notes.append(
                            f"No eligible stable release verified for {name}; retained `{current}`."
                        )
                        continue
                if tuple(map(int, latest.split("."))) > floor:
                    manifest[section][name] = latest
                    changes.append((name, f"- {name}: `{current}` → `{latest}`"))
                    routine_targets.add((section, name))

        if changes:
            manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
        lock_flags = (
            ["--lockfile-only", "--no-frozen-lockfile", "--ignore-scripts"]
            if package_manager == "pnpm"
            else [
                "--package-lock-only",
                "--ignore-scripts",
                "--no-audit",
                *(["--before", release_before] if release_before else []),
            ]
        )
        lock = run(
            directory,
            "install",
            *lock_flags,
            deadline=deadline,
        )
        invalid_stable_state = restore_invalid_state(
            directory, security_snapshot, notes, "Stable install"
        )
        stable_candidate = valid_snapshot(directory)
        violation = (
            routine_scope_violation(security_snapshot, stable_candidate, upgrade_scope)
            if stable_candidate is not None
            else None
        )
        if violation:
            restore_snapshot(directory, security_snapshot)
            invalid_stable_state = True
            notes.append(
                f"Rejected routine proposal: maintenance.upgradeScope={upgrade_scope}; {violation}. Restored accepted security fixes."
            )
        if lock.returncode or invalid_stable_state:
            proposal_complete = False
            restore_snapshot(directory, security_snapshot)
            notes.append(
                f"Stable upgrade resolution failed (exit {lock.returncode}); restored "
                "the manifest and lockfile from the initial security fix attempt."
            )
            changes = []
            routine_targets.clear()
        else:
            stable_snapshot = valid_snapshot(directory) or security_snapshot
            last_valid_snapshot = stable_snapshot
            stable_audit = audit(directory, deadline=deadline)
            if restore_invalid_state(
                directory, stable_snapshot, notes, "Stable proposal audit", frozen=True
            ):
                stable_audit = (
                    "Audit unavailable: stable proposal audit changed package files."
                )
            if isinstance(stable_audit, dict):
                affected.update(stable_audit.get("vulnerabilities", {}))
            else:
                notes.append(
                    "Stable proposal audit unavailable; follow-up security attribution is unconfirmed."
                )
            # Keep fixes within the proposed manifest constraints; never use --force.
            fixed = fix_security(
                directory,
                deadline,
                notes,
                cache,
                before=stable_audit,
                release_before=release_before,
            )
            if restore_invalid_state(
                directory,
                stable_snapshot,
                notes,
                "Follow-up security fix",
                security_fix=True,
            ):
                proposal_complete = False
            if fixed.returncode:
                proposal_complete = False
                notes.append(
                    f"Automatic audit fix returned exit {fixed.returncode}; remaining findings "
                    "or a tool error require manual review."
                )
            last_valid_snapshot = valid_snapshot(directory) or stable_snapshot

    validation_snapshot = last_valid_snapshot
    install_args = (
        ["install", "--frozen-lockfile"]
        if package_manager == "pnpm"
        else ["ci", "--no-audit"]
    )
    install = (
        subprocess.CompletedProcess([], 1, "", "")
        if prepare_only
        else run(directory, *install_args, deadline=deadline)
    )
    invalid_install_state = restore_invalid_state(
        directory, validation_snapshot, notes, "Frozen install", frozen=True
    )
    last_valid_snapshot = valid_snapshot(directory) or validation_snapshot
    if prepare_only:
        check_status = "Pending: separate prepared-candidate validation."
    elif install.returncode or invalid_install_state:
        check_status = (
            f"Not run: {package_manager} frozen install failed "
            f"(exit {install.returncode}); validation failed."
        )
    else:
        checked = run(directory, "run", validation_script, deadline=deadline)
        invalid_check_state = restore_invalid_state(
            directory,
            last_valid_snapshot,
            notes,
            f"{package_manager} run {validation_script}",
            frozen=True,
        )
        last_valid_snapshot = valid_snapshot(directory) or last_valid_snapshot
        if invalid_check_state:
            check_status = (
                f"Failed: {package_manager} run {validation_script} changed package files or left invalid "
                "package files; restored the "
                "last valid snapshot; validation failed; manual repair required."
            )
        elif checked.returncode == 0:
            check_status = "Passed."
        else:
            check_status = (
                f"Failed (exit {checked.returncode}); manual repair required."
            )
    after = audit(directory, deadline=deadline)
    if restore_invalid_state(
        directory, last_valid_snapshot, notes, "Final audit", frozen=True
    ):
        after = f"Audit unavailable: {package_manager} changed package files; restored the last valid snapshot."
    after_snapshot = valid_snapshot(directory) or last_valid_snapshot
    if package_manager == "npm":
        describe_npm_fixes(
            directory, before, initial_snapshot, after_snapshot, notes, deadline, cache
        )
    if (
        maintenance_mode == "security-only"
        and after_snapshot != initial_snapshot
        and (
            not confirmed_fixes(
                before, after, package_manager, initial_snapshot, after_snapshot
            )
            or security_only_direct_violation(
                initial_snapshot,
                after_snapshot,
                affected,
                confirmed_ids=confirmed_fixes(
                    before, after, package_manager, initial_snapshot, after_snapshot
                ),
                audit_before=before,
                source=package_manager,
            )
        )
    ):
        restore_snapshot(directory, initial_snapshot)
        proposal_complete = False
        after_snapshot = initial_snapshot
        after = audit(directory, deadline=deadline)
        if restore_invalid_state(
            directory, initial_snapshot, notes, "Restored project audit", frozen=True
        ):
            after = "Audit unavailable: restored project audit changed package files."
        check_status = "Proposal discarded: final audit did not confirm a security fix; candidate validation evidence does not apply to the restored files."
        notes.append(
            "Discarded dependency changes because final security evidence was unavailable or no longer confirmed a fix."
        )
    after_lock = after_snapshot[3]
    audit_errors = [
        f"{phase}: {evidence}"
        for phase, evidence in (("Initial audit", before), ("Final audit", after))
        if isinstance(evidence, str)
    ]

    def published_patch_versions(specifier, *, all_versions=False):
        key = ("local-patch", specifier, all_versions)
        if key not in cache:
            snapshot = valid_snapshot(directory)
            result = run(
                directory,
                "view",
                specifier,
                "versions" if all_versions else "version",
                "--json",
                deadline=deadline,
            )
            if snapshot is None or restore_invalid_state(
                directory, snapshot, notes, "Local patch metadata lookup", frozen=True
            ):
                cache[key] = None
            else:
                try:
                    data = json.loads(result.stdout)
                except ValueError:
                    data = None
                error = data.get("error") if isinstance(data, dict) else None
                if (
                    result.returncode == 1
                    and isinstance(error, dict)
                    and error.get("code")
                    in {
                        "ERR_PNPM_NO_MATCHING_VERSION",
                    }
                ):
                    cache[key] = set()
                elif (
                    result.returncode == 1
                    and isinstance(error, dict)
                    and error.get("code") == "E404"
                ):
                    summary = " ".join(
                        str(error.get(field, ""))
                        for field in ("summary", "detail", "message")
                    )
                    cache[key] = (
                        set()
                        if not all_versions
                        and re.search(r"\bNo match found for version\b", summary)
                        else None
                    )
                elif (
                    isinstance(error, dict)
                    and error.get("code") == "ERR_PNPM_PACKAGE_NOT_FOUND"
                ):
                    cache[key] = None
                else:
                    values = [data] if isinstance(data, str) else data
                    cache[key] = (
                        {
                            v
                            for v in values
                            if re.fullmatch(
                                r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)", v
                            )
                        }
                        if result.returncode == 0
                        and isinstance(values, list)
                        and all(isinstance(v, str) for v in values)
                        else None
                    )
        return cache[key]

    patch_report = LOCAL_PATCHES["assess"](
        declared_patches,
        before,
        after,
        published_patch_versions,
        initial_snapshot[3] if isinstance(before, dict) else after_snapshot[3],
    )
    if validation is not None:
        validation["passed"] = check_status == "Passed."
        validation["audit_errors"] = audit_errors
        validation["proposal_complete"] = proposal_complete and not audit_errors
        validation["local_patches"] = patch_report
    routine_rows = routine_upgrade_rows(
        initial_snapshot, security_snapshot, after_snapshot, routine_targets
    )
    release_links = {}
    for _, name, _, proposed in routine_rows:
        if (name, proposed) not in release_links:
            release_links[(name, proposed)] = release_notes_link(
                directory, name, proposed, after_snapshot, notes, deadline
            )
    fingerprints = "\n".join(
        f"- `{name}`: `{hashlib.sha256(content).hexdigest()}`"
        for name, content in {
            "package.json": after_snapshot[0],
            **after_snapshot[1],
        }.items()
    )
    locked_updates = locked_changes(before_lock, after_lock)
    changes = [
        (name, f"- {name}: `{current}` → `{final}`")
        for section in ("dependencies", "devDependencies", "optionalDependencies")
        for name, current in initial_snapshot[2].get(section, {}).items()
        if (final := after_snapshot[2].get(section, {}).get(name)) != current
    ]
    describe_pnpm_fixes(directory, before, initial_snapshot[1], notes, deadline, cache)
    describe_pnpm_fixes(directory, after, after_snapshot[1], notes, deadline, cache)
    native_locks = [
        yaml.safe_load(snapshot[1]["pnpm-lock.yaml"])
        if package_manager == "pnpm"
        else snapshot[3]
        for snapshot in (initial_snapshot, after_snapshot)
    ]
    security_changes = []
    reported_changes = set()
    for name in affected:
        old, new = (
            versions(
                lock,
                {
                    "nodes": [
                        node
                        for node, package in lock.get("packages", {}).items()
                        if node == f"node_modules/{name}"
                        or node.endswith(f"/node_modules/{name}")
                        or package.get("name") == name
                    ]
                },
            )
            for lock in (before_lock, after_lock)
        )
        paths_changed = package_paths(native_locks[0], name, package_manager) != (
            package_paths(native_locks[1], name, package_manager)
        )
        if old != new or paths_changed:
            status = "after audit unavailable; fix unconfirmed"
            if isinstance(after, dict):
                status = (
                    f"still reported by {package_manager}"
                    if name in after.get("vulnerabilities", {})
                    else f"no longer reported by {package_manager}"
                )
            change = (
                f"`{old}` → `{new}`"
                if old != new
                else f"dependency paths changed; installed versions `{new}`"
            )
            security_changes.append(f"- {name}: {change}; {status}.")
            reported_changes.add(name)
    security_changes.extend(
        line
        for name, line in changes
        if name in affected and name not in reported_changes
    )
    if time.monotonic() >= deadline:
        notes.append(
            "The shared 45-minute dependency command time budget was exhausted; remaining commands were skipped."
        )
    count_explanation = (
        "pnpm reports registry advisory counts. Multiple affected dependency "
        "paths do not demonstrate exploitability."
        if package_manager == "pnpm"
        else "npm counts affected package entries, including propagated findings in "
        "parent packages. These are not counts of distinct advisories or "
        "demonstrated exploit paths."
    )
    change_sections = []
    if security_changes:
        change_sections.append(
            "## Security findings and fixes\n\n" + "\n".join(security_changes)
        )
    other_changes = [line for name, line in changes if name not in affected]
    if other_changes:
        change_sections.append(
            "## Other stable dependency upgrades\n\n" + "\n".join(other_changes)
        )
    if isinstance(before, dict) and isinstance(after, dict):
        security_packages = affected | set(after.get("vulnerabilities", {}))
        maintenance_updates = [
            line
            for line in locked_updates
            if line[2:].split(": ", 1)[0] not in security_packages
        ]
        updates = "update" if len(maintenance_updates) == 1 else "updates"
        maintenance = (
            f"**Maintenance:** {len(maintenance_updates)} additional package {updates} "
            f"({len(locked_updates)} total)."
        )
    else:
        maintenance = (
            f"**Dependency updates:** {len(locked_updates)} packages; "
            "security classification unconfirmed."
        )
    if maintenance_mode == "security-only":
        maintenance = "**Routine upgrades disabled.** " + maintenance
    fixed_ids = confirmed_fixes(
        before, after, package_manager, initial_snapshot, after_snapshot
    )
    fixed_count = len(fixed_ids)
    initial_ids = finding_ids(before, package_manager)
    remaining_ids = finding_ids(after, package_manager)
    reported_parents = reported_parent_findings(
        before, after, package_manager, before_lock, after_lock
    )
    new_ids = (
        newly_reported_findings(before, after, package_manager)
        - reported_parents.keys()
    )
    remaining_count = len(remaining_ids or ())
    remaining_unit = (
        ("advisory" if remaining_count == 1 else "advisories")
        if package_manager == "pnpm"
        else (
            "affected package entry"
            if remaining_count == 1
            else "affected package entries"
        )
    )
    remaining_verb = "remains" if remaining_count == 1 else "remain"
    security_counts = (
        f"{fixed_count} security {'fix' if fixed_count == 1 else 'fixes'} · {remaining_count} {remaining_unit} {remaining_verb}"
        if initial_ids is not None and remaining_ids is not None
        else "Security fixes unconfirmed"
    )
    if isinstance(after, dict) and (
        critical := after.get("metadata", {})
        .get("vulnerabilities", {})
        .get("critical", 0)
    ):
        security_counts += f" ({critical} critical)"
    proposed_changes = "\n".join(locked_updates or [line for _, line in changes])
    if not proposed_changes:
        proposed_changes = "No dependency version changes are proposed."
    install_status = (
        "Not run: separate prepared-candidate validation."
        if prepare_only
        else "Passed."
        if not install.returncode and not invalid_install_state
        else "Failed."
    )
    if check_status.startswith("Proposal discarded:"):
        install_status = (
            "Not confirmed for the retained proposal; the candidate was discarded."
        )
    routine_only = (
        bool(locked_updates)
        and initial_ids is not None
        and initial_ids == remaining_ids
        and not new_ids
        and not security_changes
    )
    before_audit = format_audit(before, before_lock)
    after_audit = format_audit(after, after_lock)
    blocked_findings = (
        format_blocked_findings(after, package_manager)
        if initial_ids is not None
        and initial_ids == remaining_ids
        and before_audit == after_audit
        and not security_changes
        else None
    )
    package_metrics = {}
    repair_options = REPAIR_CHOICES["candidates"](after)
    package_report = format_audit_summary(
        before,
        after,
        package_manager,
        fixed_ids=fixed_ids,
        reported_parents=reported_parents,
        locks=(before_lock, after_lock),
        summary=package_metrics,
        repair_options=repair_options,
    )
    background_blockers = bool(routine_only and blocked_findings)
    if background_blockers:
        package_report = f"{remaining_count} {remaining_unit} {'is' if remaining_count == 1 else 'are'} blocked, unchanged by this PR."
    report = (
        format_security_overview(
            platform=platform,
            package_report=package_report,
            package_fixes=fixed_count
            if initial_ids is not None and remaining_ids is not None
            else None,
            package_updates=len(locked_updates),
            review_count=package_metrics.get("review_count", 0),
            passed=check_status == "Passed.",
            routine_only=routine_only,
        )
        + (
            "## Security audit incomplete\n\n"
            "This run fails because complete before/after security evidence is unavailable. "
            "Project validation results are separate.\n\n"
            + "\n".join(f"- {error}" for error in audit_errors)
            + "\n\n"
            if audit_errors
            else ""
        )
        + format_validation(install_status, check_status)
        + (
            f"## Existing security findings\n\n{remaining_count} {remaining_unit} {'is' if remaining_count == 1 else 'are'} blocked, unchanged by this PR.\n\n"
            if blocked_findings
            else f"### Package advisory counts\n\n{security_counts}.\n\n"
        )
    )
    if isinstance(after, str):
        report += f"{after}\n\n"
    report += LOCAL_PATCHES["render"](patch_report)
    if initial_ids is not None and remaining_ids is not None:
        new_count = len(new_ids)
        if new_count:
            unit = (
                ("advisory" if new_count == 1 else "advisories")
                if package_manager == "pnpm"
                else (
                    "affected package entry"
                    if new_count == 1
                    else "affected package entries"
                )
            )
            report += (
                f"🔴 **Newly reported security findings in {new_count} {unit}; review the advisory details before merging.**\n\n"
                if package_manager == "npm"
                else f"🔴 **{new_count} newly reported {unit}; review before merging.**\n\n"
            )
    if not initial_audit_available:
        report += "Initial audit evidence was unavailable; retained security-fix changes are unconfirmed.\n\n"
    report += format_change_report(
        proposed_changes,
        "",
        format_routine_upgrades(routine_rows, release_links),
    )
    if background_blockers:
        report += (
            "<details>\n<summary>Blocked findings and constraints</summary>\n\n"
            + blocked_findings
            + "\n\n</details>\n\n"
        )
    if change_sections:
        report += (
            "<details>\n<summary>Additional dependency change details</summary>\n\n"
            + "\n\n".join(change_sections)
            + "\n\n</details>\n\n"
        )
    # Keep the complete final findings once, including npm propagated packages.
    remaining = (
        (
            "Registry advisory counts: "
            if package_manager == "pnpm"
            else "Affected package entries: "
        )
        + after_audit
        if isinstance(after, dict) and after.get("vulnerabilities")
        else format_remaining_audit(after, after_lock)
    )
    report += (
        f"<details>\n<summary>Full before/after {package_manager} audit</summary>\n\n"
        f"## Remaining advisories\n\n{remaining}\n\n"
        + (
            "Before and after findings are unchanged.\n\n"
            if before_audit == after_audit
            else f"### Before\n\n{before_audit}\n\n"
        )
        + "</details>\n\n"
        "<details>\n<summary>Run configuration and audit evidence</summary>\n\n"
        f"`{directory}` · `{package_manager}`\n\n"
        f"{maintenance}\n\n"
        f"Validation script: `{validation_script}` · Maintenance: `{maintenance_mode}` · Routine direct upgrade scope: `{upgrade_scope}`\n\n"
        f"Run: {datetime.now(timezone.utc).isoformat()}\n\n"
        f"{count_explanation}\n\n"
        + (
            "\n".join(f"- {note}" for note in dict.fromkeys(notes)) + "\n\n"
            if notes
            else ""
        )
        + f"### Candidate dependency files (SHA-256)\n\n{fingerprints}\n\n</details>\n"
    )
    if validate_only:
        status = (
            "Pending"
            if prepare_only
            else "Passed"
            if check_status == "Passed."
            else "Failed"
        )
        report = (
            f"**Committed dependency validation · {status}**\n\n"
            "Checked committed dependencies without attempting repairs or routine upgrades.\n\n"
            + report.partition("\n")[2]
        )
    if prepare_only and not audit_errors:
        record = {
            "version": 1,
            "repository": os.environ["GITHUB_REPOSITORY"],
            "source": subprocess.check_output(
                ["git", "rev-parse", "HEAD"], text=True
            ).strip(),
            "project": directory.as_posix(),
            "manager": package_manager,
            "node": os.environ["NODE_AUDIT_NODE_VERSION"],
            "manager_version": os.environ["NODE_AUDIT_MANAGER_VERSION"],
            "validation_script": validation_script,
            "before_state": dependency_state(initial_snapshot),
            "candidate_state": dependency_state(after_snapshot),
            "before": before,
            "after": after,
            "package_report": package_report,
            "fixed_ids": sorted(fixed_ids),
            "initial_ids": sorted(initial_ids or ()),
            "remaining_ids": sorted(remaining_ids or ()),
        }
        encoded = base64.b64encode(canonical_history(record)).decode("ascii")
        if len(encoded) > 524288:
            raise ValueError("Historical audit evidence exceeds its bound")
        report += f"\n<!-- node-audit-history:v1:{encoded} -->\n"
        heading, separator, tail = report.partition("\n")
        report = (
            heading.replace("Validation failed or unavailable", "Validation pending")
            + separator
            + tail.replace(
                "⚪ Upgrade validation failed or unavailable: **Node.js**",
                "⚪ Upgrade validation pending: **Node.js**",
                1,
            )
        )
        if len(report.encode()) > 1048576:
            raise ValueError("Audit report exceeds its bound")
    return report


HISTORY_TITLE = "Node audit evidence v1"
HISTORY_PATTERN = re.compile(
    r"^<!-- node-audit-history:v1:([A-Za-z0-9+/=]+) -->$", re.M
)


def canonical_history(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def dependency_state(snapshot):
    return {
        name: hashlib.sha256(data).hexdigest()
        for name, data in sorted({"package.json": snapshot[0], **snapshot[1]}.items())
    }


def history_record(report):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate history field")
            result[key] = value
        return result

    if len(report) > 1048576:
        raise ValueError("Audit report exceeds its bound")
    text = report.decode("utf-8")
    matches = HISTORY_PATTERN.findall(text)
    if (
        len(matches) != 1
        or text.count("node-audit-history:") != 1
        or len(matches[0]) > 524288
    ):
        raise ValueError("Missing or ambiguous sealed audit history")
    raw = base64.b64decode(matches[0], validate=True)
    record = json.loads(raw, object_pairs_hook=unique)
    if (
        canonical_history(record) != raw
        or not isinstance(record, dict)
        or type(record.get("version")) is not int
        or record["version"] != 1
    ):
        raise ValueError("Noncanonical or unsupported audit history")
    return record


def check_prepared_history(report, directory):
    record = history_record(report)
    if (
        record["repository"] != os.environ["GITHUB_REPOSITORY"]
        or record["source"]
        != subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
        or record["project"] != directory.as_posix()
        or record["candidate_state"] != dependency_state(valid_snapshot(directory))
    ):
        raise ValueError(
            "Prepared dependencies or project identity differ from sealed evidence"
        )
    return record


def history_api(repository, suffix, *, binary=False):
    result = subprocess.run(
        ["gh", "api", f"repos/{repository}/{suffix}"],
        capture_output=True,
        timeout=60,
        check=True,
    )
    if len(result.stdout) > (8388608 if binary else 1048576):
        raise ValueError("Historical evidence API response exceeds its bound")
    return result.stdout if binary else json.loads(result.stdout)


def verify_history(
    locator,
    *,
    repository,
    source,
    project,
    candidate_state,
    trusted_workflow_sha,
    expected_job_name,
):
    required = {"run", "job", "check", "artifact", "archive_sha256", "content_sha256"}
    if (
        set(locator) != required
        or any(
            type(locator[k]) is not int or locator[k] <= 0
            for k in ("run", "job", "check", "artifact")
        )
        or any(
            not isinstance(locator[k], str)
            or not re.fullmatch(r"[a-f0-9]{64}", locator[k])
            for k in ("archive_sha256", "content_sha256")
        )
    ):
        raise ValueError("Invalid exact historical evidence locator")
    run = history_api(repository, f"actions/runs/{locator['run']}")
    trigger_head = run.get("head_sha")
    job = history_api(repository, f"actions/jobs/{locator['job']}")
    check_url = (
        f"https://api.github.com/repos/{repository}/check-runs/{locator['check']}"
    )
    jobs = history_api(
        repository,
        f"actions/runs/{locator['run']}/attempts/{run['run_attempt']}/jobs?per_page=100",
    )
    workflows = [
        w
        for w in run.get("referenced_workflows", [])
        if w.get("path", "").split("@")[0]
        == "hydra-ecosystem/github-actions/.github/workflows/node-audit.yml"
    ]
    steps = [
        (step.get("name"), step.get("conclusion")) for step in job.get("steps", [])
    ]
    expected_steps = [
        ("Prepare and seal audit evidence", "success"),
        ("Seal uploaded audit evidence", "success"),
    ]
    relevant = [
        step for step in steps if step[0] in {name for name, _ in expected_steps}
    ]
    if (
        run.get("repository", {}).get("full_name") != repository
        or not isinstance(trigger_head, str)
        or re.fullmatch(r"[a-f0-9]{40}", trigger_head) is None
        or run.get("event") not in {"push", "schedule", "workflow_dispatch"}
        or len(workflows) != 1
        or workflows[0].get("sha") != trusted_workflow_sha
        or job.get("id") != locator["job"]
        or job.get("run_id") != locator["run"]
        or job.get("head_sha") != trigger_head
        or job.get("run_attempt") != run["run_attempt"]
        or job.get("name") != expected_job_name
        or job.get("check_run_url") != check_url
        or job.get("status") != "completed"
        or job.get("conclusion") != "success"
        or jobs.get("total_count", 100) >= 100
        or [
            j.get("id")
            for j in jobs.get("jobs", [])
            if j.get("name") == expected_job_name
        ]
        != [locator["job"]]
        or relevant != expected_steps
    ):
        raise ValueError(
            "Historical evidence does not identify the trusted producer job"
        )
    check = history_api(repository, f"check-runs/{locator['check']}")
    annotations = history_api(
        repository, f"check-runs/{locator['check']}/annotations?per_page=100"
    )
    notices = [a for a in annotations if a.get("title") == HISTORY_TITLE]
    message = f"v1:{locator['artifact']}:{locator['archive_sha256']}:{locator['content_sha256']}"
    if (
        check.get("id") != locator["check"]
        or check.get("head_sha") != trigger_head
        or check.get("app", {}).get("id") != 15368
        or check.get("details_url") != job.get("html_url")
        or check.get("output", {}).get("annotations_count", 100) >= 100
        or len(notices) != 1
        or notices[0].get("annotation_level") != "notice"
        or notices[0].get("message") != message
    ):
        raise ValueError("Missing or ambiguous producer seal annotation")
    artifact = history_api(repository, f"actions/artifacts/{locator['artifact']}")
    if (
        artifact.get("id") != locator["artifact"]
        or artifact.get("expired") is not False
        or type(artifact.get("size_in_bytes")) is not int
        or not 0 < artifact["size_in_bytes"] <= 8388608
        or artifact.get("digest") != "sha256:" + locator["archive_sha256"]
        or artifact.get("workflow_run", {}).get("id") != locator["run"]
        or artifact.get("workflow_run", {}).get("head_sha") != trigger_head
    ):
        raise ValueError("Historical artifact metadata differs from its producer seal")
    archive = history_api(
        repository, f"actions/artifacts/{locator['artifact']}/zip", binary=True
    )
    if (
        len(archive) != artifact["size_in_bytes"]
        or hashlib.sha256(archive).hexdigest() != locator["archive_sha256"]
    ):
        raise ValueError("Historical archive digest differs")
    with zipfile.ZipFile(BytesIO(archive)) as bundle:
        entries = bundle.infolist()
        if (
            len(entries) != 1
            or entries[0].filename != "dependency-audit-pr.md"
            or entries[0].file_size > 1048576
        ):
            raise ValueError("Unexpected historical artifact members or size")
        report = bundle.read(entries[0])
    if hashlib.sha256(report).hexdigest() != locator["content_sha256"]:
        raise ValueError("Historical report digest differs")
    record = history_record(report)
    if (
        record["repository"],
        record["source"],
        record["project"],
        record["candidate_state"],
    ) != (repository, source, project, candidate_state):
        raise ValueError(
            "Historical record belongs to different dependencies or project"
        )
    return record


def locate_current_history(report, directory, *, trusted_workflow_sha, prefix):
    repository = os.environ["GITHUB_REPOSITORY"]
    record = check_prepared_history(report, directory)
    run_id = int(os.environ["GITHUB_RUN_ID"])
    jobs = history_api(repository, f"actions/runs/{run_id}/jobs?per_page=100")
    producer_name = f"Node audit evidence ({prefix or 'dependency-audit'})"
    matches = [
        job
        for job in jobs.get("jobs", [])
        if job.get("name") == producer_name
        or job.get("name", "").endswith(" / " + producer_name)
    ]
    if jobs.get("total_count", 100) >= 100 or len(matches) != 1:
        raise ValueError("Missing or ambiguous expected producer job")
    job = matches[0]
    check_id = int(job["check_run_url"].rsplit("/", 1)[-1])
    if (
        job["check_run_url"]
        != f"https://api.github.com/repos/{repository}/check-runs/{check_id}"
    ):
        raise ValueError("Producer Check locator is not server-derived")
    annotations = history_api(
        repository, f"check-runs/{check_id}/annotations?per_page=100"
    )
    notices = [item for item in annotations if item.get("title") == HISTORY_TITLE]
    match = (
        re.fullmatch(
            r"v1:([1-9][0-9]*):([a-f0-9]{64}):([a-f0-9]{64})",
            notices[0].get("message", ""),
        )
        if len(notices) == 1
        else None
    )
    if match is None:
        raise ValueError("Producer has no unique artifact seal")
    locator = {
        "run": run_id,
        "job": job["id"],
        "check": check_id,
        "artifact": int(match[1]),
        "archive_sha256": match[2],
        "content_sha256": match[3],
    }
    verified = verify_history(
        locator,
        repository=repository,
        source=record["source"],
        project=record["project"],
        candidate_state=record["candidate_state"],
        trusted_workflow_sha=trusted_workflow_sha,
        expected_job_name=job["name"],
    )
    if (
        verified != record
        or hashlib.sha256(report).hexdigest() != locator["content_sha256"]
    ):
        raise ValueError("Publisher report differs from immutable producer evidence")
    return locator


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", default=".")
    parser.add_argument("--validation-script", default="build")
    parser.add_argument("--minimum-release-age-days", type=int, default=10)
    parser.add_argument(
        "--maintenance-mode",
        choices=("security-only", "security-and-maintenance"),
        default="security-and-maintenance",
    )
    parser.add_argument(
        "--upgrade-scope", choices=("patch", "minor", "major"), default="major"
    )
    parser.add_argument(
        "--report", type=Path, required=True, help="Temporary output for the PR body"
    )
    parser.add_argument(
        "--github-output",
        type=Path,
        help="Write machine-readable validation status for the publisher",
    )
    parser.add_argument("--resolved-config", type=Path)
    parser.add_argument("--node-update", type=Path)
    parser.add_argument("--local-patches-report", type=Path)
    parser.add_argument("--validate-only", action="store_true")
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--check-prepared", action="store_true")
    parser.add_argument("--github-env", type=Path)
    parser.add_argument("--locate-history", action="store_true")
    parser.add_argument("--trusted-workflow-sha")
    parser.add_argument("--artifact-prefix", default="")
    args = parser.parse_args()
    directory = Path(args.directory)
    if (
        directory.is_absolute()
        or ".." in directory.parts
        or DIRECTORY_PATTERN.fullmatch(args.directory) is None
    ):
        parser.error("directory must be a relative npm project path without '..'")
    if valid_snapshot(directory) is None:
        parser.error(
            "directory must contain valid package files for one npm or pnpm deployment"
        )
    if args.locate_history:
        if not args.trusted_workflow_sha or not re.fullmatch(
            r"[a-f0-9]{40}", args.trusted_workflow_sha
        ):
            parser.error("An immutable trusted producer source is required")
        locator = locate_current_history(
            args.report.read_bytes(),
            directory,
            trusted_workflow_sha=args.trusted_workflow_sha,
            prefix=args.artifact_prefix,
        )
        trailers = "\n".join(
            f"Node-Audit-{key.replace('_', '-')}: {value}"
            for key, value in locator.items()
        )
        trailers += f"\nNode-Audit-Workflow-SHA: {args.trusted_workflow_sha}"
        with args.github_env.open("a") as output:
            output.write(
                f"NODE_AUDIT_HISTORY_TRAILERS<<NODE_HISTORY_END\n{trailers}\nNODE_HISTORY_END\n"
            )
        text = HISTORY_PATTERN.sub("", args.report.read_text(), count=1)
        heading, separator, tail = text.partition("\n")
        passed = os.environ.get("VALIDATION_PASSED") == "true"
        outcome = "Passed." if passed else "Not confirmed: separate validation failed."
        pending = format_validation(
            "Not run: separate prepared-candidate validation.",
            "Pending: separate prepared-candidate validation.",
        )
        args.report.write_text(
            heading.replace(
                "Validation pending",
                "Validation passed" if passed else "Validation failed",
            )
            + separator
            + tail.replace(pending, format_validation(outcome, outcome), 1).replace(
                "⚪ Upgrade validation pending: **Node.js**",
                "✅ Upgrade validated: **Node.js**"
                if passed
                else "⚪ Upgrade validation failed or unavailable: **Node.js**",
                1,
            )
        )
        return
    validation: dict = {}
    if args.check_prepared:
        node_plan = None
        if args.node_update is not None:
            node_proposal = runpy.run_path(
                str(Path(__file__).parents[1] / "node_proposal.py")
            )
            node_plan = node_proposal["read_plan"](args.node_update)
        record = check_prepared_history(args.report.read_bytes(), directory)
        if record.get("manager") != manager(directory) or any(
            not isinstance(record.get(key), str)
            or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", record[key]) is None
            for key in ("node", "manager_version")
        ):
            raise ValueError(
                "Sealed toolchain must identify exact Node and manager versions"
            )
        if node_plan is not None and args.github_env:
            node_proposal["publish"](Path.cwd().resolve(), node_plan)
            node_proposal["verify_candidate"](Path.cwd().resolve(), node_plan)
        if args.github_env:
            with args.github_env.open("a") as output:
                output.write(
                    f"NODE_AUDIT_NODE_VERSION={record['node']}\n"
                    f"NODE_AUDIT_MANAGER={record['manager']}\n"
                    f"NODE_AUDIT_MANAGER_VERSION={record['manager_version']}\n"
                )
            return
        installed_node = subprocess.check_output(
            ["node", "--version"], text=True, timeout=30
        ).strip()
        installed_manager = run(directory, "--version", deadline=time.monotonic() + 30)
        if (
            installed_node != f"v{record['node']}"
            or installed_manager.returncode
            or installed_manager.stdout.strip() != record["manager_version"]
        ):
            raise ValueError("Installed toolchain differs from sealed evidence")
        report = prepare(
            directory,
            validation=validation,
            validate_only=True,
            validation_script=record["validation_script"],
        )
        if node_plan is not None:
            node_proposal["verify_candidate"](Path.cwd().resolve(), node_plan)
        check_prepared_history(args.report.read_bytes(), directory)
        prepared_passed = validation["passed"] and not validation["audit_errors"]
        if not prepared_passed:
            report = report.replace(
                "**Committed dependency validation · Passed**",
                "**Committed dependency validation · Failed**",
                1,
            )
        args.report.write_text(report)
        with args.github_output.open("a") as output:
            output.write(f"validation_passed={str(prepared_passed).lower()}\n")
        if validation["audit_errors"]:
            parser.exit(
                1,
                "Security audit incomplete: "
                + "; ".join(validation["audit_errors"])
                + "\n",
            )
        return
    try:
        patches = []
        node_plan = None
        if args.node_update is not None:
            node_proposal = runpy.run_path(
                str(Path(__file__).parents[1] / "node_proposal.py")
            )
            node_plan = node_proposal["read_plan"](args.node_update)
        if args.resolved_config is not None:
            if not args.resolved_config.is_file():
                raise ValueError("Resolved configuration snapshot is missing")
            project = runpy.run_path(str(Path(__file__).parents[1] / "project.py"))
            selected, _ = project["resolve_for_run"](
                Path.cwd().resolve(), args.resolved_config, []
            )
            if selected != directory.resolve():
                raise ValueError("Selected directory differs from the resolved project")
            resolved = json.loads(args.resolved_config.read_bytes())
            patches = resolved["configuration"].get("localPatches", [])
        report = prepare(
            directory,
            validation=validation,
            validation_script=args.validation_script,
            minimum_release_age_days=args.minimum_release_age_days,
            maintenance_mode=args.maintenance_mode,
            upgrade_scope=args.upgrade_scope,
            local_patches=patches,
            validate_only=args.validate_only,
            prepare_only=args.prepare_only,
            platform=NODE_RELEASES["collect"](node_plan),
        )
        if args.node_update is not None:
            node_proposal = runpy.run_path(
                str(Path(__file__).parents[1] / "node_proposal.py")
            )
            node_proposal["verify_candidate"](Path.cwd().resolve(), node_plan)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    if args.local_patches_report is not None:
        try:
            local_patches_report = LOCAL_PATCHES["serialize_report"](
                validation["local_patches"]
            )
        except ValueError as error:
            parser.error(str(error))
    else:
        local_patches_report = None
    args.report.write_text(report)
    if local_patches_report is not None:
        args.local_patches_report.write_bytes(local_patches_report)
    if args.github_output is not None:
        with args.github_output.open("a") as output:
            output.write(f"validation_passed={str(validation['passed']).lower()}\n")
            if args.prepare_only:
                output.write(
                    f"report_sha256={hashlib.sha256(report.encode()).hexdigest()}\n"
                )
            output.write(
                f"proposal_complete={str(validation['proposal_complete']).lower()}\n"
            )
    print(report)
    if validation["audit_errors"]:
        print(
            "::error title=Node security audit incomplete::Complete before/after "
            "security evidence is unavailable. See the retained report for the cause; "
            "project validation results are separate."
        )
        parser.exit(
            1,
            "Security audit incomplete: "
            + "; ".join(validation["audit_errors"])
            + "\n",
        )


if __name__ == "__main__":
    main()
