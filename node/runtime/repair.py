"""Validate consent, prepare a bounded pnpm pin repair, and publish atomically."""

import argparse
import copy
import json
import os
import re
import runpy
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).parent
CHOICES = runpy.run_path(str(ROOT / "repair_choices.py"))
ENGINE = runpy.run_path(str(ROOT / "templates/dependency_audit.py"))
PROJECT = runpy.run_path(str(ROOT / "project.py"))
CANDIDATE_INSTALL = (
    "install",
    "--lockfile-only",
    "--ignore-scripts",
    "--ignore-pnpmfile",
)


def git(*args):
    return subprocess.check_output(["git", *args], text=True).strip()


def gh(path):
    return json.loads(subprocess.check_output(["gh", "api", path], text=True))


def request():
    number = os.environ["REPAIR_PR"]
    if not re.fullmatch(r"[1-9][0-9]*", number):
        raise ValueError("Invalid PR number")
    for key in ("REPAIR_HEAD", "REPAIR_BASE"):
        if not re.fullmatch(r"[a-f0-9]{40}", os.environ[key]):
            raise ValueError("Invalid expected revision")
    if not re.fullmatch(r"[a-f0-9-]{36}", os.environ["REPAIR_REQUEST"]):
        raise ValueError("Invalid request identifier")
    return CHOICES["validate"](json.loads(os.environ["REPAIR_SELECTIONS"]))


def guard(items):
    repo = os.environ["GITHUB_REPOSITORY"]
    repository = gh(f"repos/{repo}")
    pr = gh(f"repos/{repo}/pulls/{os.environ['REPAIR_PR']}")
    if (
        pr["state"] != "open"
        or pr["head"]["repo"]["full_name"] != repo
        or pr["base"]["repo"]["full_name"] != repo
        or pr["head"]["ref"] != "maintenance/node-security"
        or pr["base"]["ref"] != repository["default_branch"]
        or pr["user"]["type"] != "Bot"
        or pr["head"]["sha"] != os.environ["REPAIR_HEAD"]
        or pr["base"]["sha"] != os.environ["REPAIR_BASE"]
        or CHOICES["parse"](pr["body"] or "") != items
    ):
        raise ValueError("PR state or selections changed; request a fresh repair")
    return pr


def update_policy(text, items):
    """Change scalar values only, retaining the existing comments and formatting."""
    tree = yaml.compose(text)
    if not isinstance(tree, yaml.MappingNode):
        raise ValueError("Invalid pnpm policy")
    overrides = [value for key, value in tree.value if key.value == "overrides"]
    if len(overrides) != 1 or not isinstance(overrides[0], yaml.MappingNode):
        raise ValueError("Exactly one plain overrides mapping is required")
    edits = []
    for item in items:
        values = [v for k, v in overrides[0].value if k.value == item["name"]]
        if (
            len(values) != 1
            or not isinstance(values[0], yaml.ScalarNode)
            or values[0].tag != "tag:yaml.org,2002:str"
            or values[0].value != item["from"]
        ):
            raise ValueError(f"The exact pin for {item['name']} changed")
        value = values[0]
        edits.append(
            (value.start_mark.index, value.end_mark.index, json.dumps(item["to"]))
        )
    for start, end, replacement in sorted(edits, reverse=True):
        text = text[:start] + replacement + text[end:]
    return text


def check_scope(before, after, items):
    if before is None or after is None or before[0] != after[0]:
        raise ValueError("The repair changed package.json or invalidated package files")
    old = yaml.safe_load(before[1]["pnpm-workspace.yaml"])
    new = yaml.safe_load(after[1]["pnpm-workspace.yaml"])
    expected = copy.deepcopy(old)
    for item in items:
        if old.get("overrides", {}).get(item["name"]) != item["from"]:
            raise ValueError("The approved pin changed")
        expected["overrides"][item["name"]] = item["to"]
    if expected != new:
        raise ValueError("The repair changed unapproved pnpm policy")
    old_versions, new_versions = (
        ENGINE["locked_version_sets"](snapshot[3]) for snapshot in (before, after)
    )
    selected = {item["name"] for item in items}
    for name in old_versions.keys() | new_versions.keys():
        if name not in selected and old_versions.get(name) != new_versions.get(name):
            raise ValueError(f"The repair changed an unselected package: {name}")
    for item in items:
        if new_versions.get(item["name"]) != {item["to"]}:
            raise ValueError("The approved target was not installed everywhere")
    selected_versions = {item["name"]: {item["from"], item["to"]} for item in items}

    def selected_version(name, value):
        if name in selected_versions and isinstance(value, str):
            version, separator, peers = value.partition("(")
            if version in selected_versions[name]:
                return "<selected version>" + separator + peers
        return value

    def unrelated(value):
        if isinstance(value, dict):
            return {
                key: unrelated(selected_version(key, child))
                for key, child in value.items()
                if not any(
                    key.split("(", 1)[0] == f"{name}@{version}"
                    for name, versions in selected_versions.items()
                    for version in versions
                )
            }
        if isinstance(value, list):
            return [unrelated(child) for child in value]
        return value

    def lock_scope(snapshot):
        lock = yaml.safe_load(snapshot[1]["pnpm-lock.yaml"])
        for importer in lock.get("importers", {}).values():
            for kind in ("dependencies", "devDependencies", "optionalDependencies"):
                for name, dependency in importer.get(kind, {}).items():
                    if name in selected_versions and isinstance(dependency, dict):
                        for field in ("specifier", "version"):
                            if field in dependency:
                                dependency[field] = selected_version(
                                    name, dependency[field]
                                )
        return unrelated(lock)

    if lock_scope(before) != lock_scope(after):
        raise ValueError(
            "The repair changed unrelated lockfile metadata or dependency edges"
        )


def verified_targets(directory, before, snapshot, items, deadline, age):
    """Ignore only the selected pins when checking the original parent ranges."""
    proof = copy.deepcopy(before)
    if not isinstance(proof, dict) or proof.get("package_manager") != "pnpm":
        raise ValueError("A complete pnpm audit is required")
    files = dict(snapshot[1])
    policy = yaml.safe_load(files["pnpm-workspace.yaml"])
    for item in items:
        if policy.get("overrides", {}).get(item["name"]) != item["from"]:
            raise ValueError("Approved exact pin is missing")
        del policy["overrides"][item["name"]]
    files["pnpm-workspace.yaml"] = yaml.safe_dump(policy).encode()
    notes = []
    ENGINE["describe_pnpm_fixes"](
        directory, proof, files, notes, deadline, {}, collect_proof=True
    )
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=age)
    for item in items:
        finding = proof["vulnerabilities"].get(item["name"], {})
        details = finding.get("via", [])
        if not details or any(
            not isinstance(detail, dict)
            or not detail.get("fixVersion")
            or item["to"] not in detail.get("_verifiedPatchedVersions", [])
            or item["from"] not in detail.get("_verifiedVulnerableVersions", [])
            for detail in details
        ):
            raise ValueError(
                f"Published patch compatibility is unverified for {item['name']}"
            )
        # fixVersion is the lowest common compatible patch for each advisory.
        # Query the requested target explicitly as well; later patches may have
        # narrower parent ranges than the minimum compatible version.
        for detail in details:
            if detail["fixVersion"] != item["to"]:
                raise ValueError(
                    "Target differs from the verified compatible patch; rerun the audit"
                )
        for field in ("dependencies", "devDependencies", "optionalDependencies"):
            constraint = snapshot[2].get(field, {}).get(item["name"])
            if constraint is None:
                continue
            permitted = False
            if isinstance(constraint, str):
                for alternative in constraint.split("||"):
                    check = ENGINE["run"](
                        directory,
                        "view",
                        f"{item['name']}@{alternative.strip()} {item['to']}",
                        "version",
                        "--json",
                        deadline=deadline,
                    )
                    try:
                        values = json.loads(check.stdout)
                    except ValueError:
                        values = None
                    if check.returncode == 0 and (
                        values == item["to"]
                        or isinstance(values, list)
                        and item["to"] in values
                    ):
                        permitted = True
                        break
            if not permitted:
                raise ValueError(
                    "The direct manifest constraint does not permit the selected patch, or compatibility could not be verified"
                )
        result = ENGINE["run"](
            directory, "view", item["name"], "time", "--json", deadline=deadline
        )
        if result.returncode:
            raise ValueError("Release publication time is unavailable")
        published = json.loads(result.stdout).get(item["to"])
        if (
            not isinstance(published, str)
            or datetime.fromisoformat(published.replace("Z", "+00:00")) > cutoff
        ):
            raise ValueError("The selected patch has not passed the release cooldown")
    if ENGINE["valid_snapshot"](directory) != snapshot:
        raise ValueError("Metadata lookup changed dependency files")
    return proof


def export_patch(paths):
    """Export validated files without executing repository-configured diff helpers."""
    return subprocess.check_output(
        [
            "git",
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--binary",
            "HEAD",
            "--",
            *paths,
        ]
    )


def project_context():
    root = Path.cwd().resolve()
    config_path = (
        Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "node-repair-config.json"
    )
    directory, selected = PROJECT["resolve_for_run"](root, config_path, [])
    PROJECT["verify_runtime"](directory, selected)
    if selected["manager"] != "pnpm":
        raise ValueError(
            "Repair attempts currently support exact pnpm override pins only"
        )
    snapshot = ENGINE["valid_snapshot"](directory)
    if snapshot is None or any(
        (directory / name).is_symlink()
        for name in ("package.json", "pnpm-workspace.yaml", "pnpm-lock.yaml")
    ):
        raise ValueError("Invalid project snapshot")
    return directory, selected, snapshot, config_path


def audit_candidate(directory, snapshot, candidate, inputs, items, deadline):
    after = ENGINE["audit"](directory, deadline=deadline)
    if ENGINE["valid_snapshot"](directory) != candidate or not isinstance(after, dict):
        raise ValueError("Final audit is unavailable or changed dependency files")
    fixed = ENGINE["confirmed_fixes"](
        inputs["proof"], after, "pnpm", snapshot, candidate
    )
    required = {
        detail["url"]
        for item in items
        for detail in inputs["proof"]["vulnerabilities"][item["name"]]["via"]
    }
    if not required <= fixed or ENGINE["newly_reported_findings"](
        inputs["before"], after, "pnpm"
    ):
        raise ValueError(
            "The batch did not confirm all selected fixes, or introduced findings"
        )
    return after, fixed


def prepare(items, artifact):
    """Resolve and seal a candidate without running dependency/project scripts."""
    root = Path.cwd().resolve()
    directory, selected, snapshot, _ = project_context()
    deadline = time.monotonic() + 40 * 60
    before = ENGINE["audit"](directory, deadline=deadline)
    proof = verified_targets(
        directory, before, snapshot, items, deadline, selected["minimumReleaseAge"]
    )
    workspace = directory / "pnpm-workspace.yaml"
    workspace.write_text(update_policy(workspace.read_text(), items))
    result = ENGINE["run"](
        directory,
        *CANDIDATE_INSTALL,
        deadline=deadline,
    )
    if result.returncode:
        raise ValueError("Candidate lockfile resolution failed")
    candidate = ENGINE["valid_snapshot"](directory)
    check_scope(snapshot, candidate, items)
    inputs = {"before": before, "proof": proof}
    after, fixed = audit_candidate(
        directory, snapshot, candidate, inputs, items, deadline
    )
    ENGINE["describe_pnpm_fixes"](directory, after, candidate[1], [], deadline, {})
    if ENGINE["valid_snapshot"](directory) != candidate:
        raise ValueError("Audit metadata lookup changed the candidate dependency files")
    paths = [
        (directory / name).relative_to(root).as_posix()
        for name in ("pnpm-workspace.yaml", "pnpm-lock.yaml")
    ]
    patch = export_patch(paths)
    if not patch:
        raise ValueError("No repair changes were produced")
    candidate_artifact = artifact / "candidate"
    candidate_artifact.mkdir(parents=True, exist_ok=True)
    (candidate_artifact / "audit.json").write_text(json.dumps(inputs))
    (candidate_artifact / "candidate.patch").write_bytes(patch)
    package_report = ENGINE["format_audit_summary"](
        proof, after, "pnpm", fixed_ids=fixed, locks=(snapshot[3], candidate[3])
    )
    (candidate_artifact / "result.md").write_text(
        "## Package security\n\n"
        + package_report
        + "\n\n"
        + CHOICES["render"](CHOICES["candidates"](after))
        + "\n<details>\n<summary>Candidate audit evidence</summary>\n\n### Before\n\n"
        + ENGINE["format_remaining_audit"](proof, snapshot[3])
        + "\n\n### Candidate\n\n"
        + ENGINE["format_remaining_audit"](after, candidate[3])
        + "\n\n</details>\n"
    )


def validate(items, artifact):
    """Validate the sealed candidate on a separate runner."""
    directory, selected, snapshot, config_path = project_context()
    source = artifact / "candidate"
    evidence = artifact / "evidence"
    inputs = json.loads((source / "audit.json").read_text())
    subprocess.run(["git", "apply", str(source / "candidate.patch")], check=True)
    candidate = ENGINE["valid_snapshot"](directory)
    check_scope(snapshot, candidate, items)
    deadline = time.monotonic() + 40 * 60
    validation = {}
    config = json.loads(config_path.read_text())["configuration"]
    details = ENGINE["prepare"](
        directory,
        validation=validation,
        validation_script=selected["validationScript"],
        minimum_release_age_days=selected["minimumReleaseAge"] // 1440,
        maintenance_mode="security-only",
        local_patches=config.get("localPatches", []),
        validate_only=True,
    )
    evidence.mkdir(parents=True, exist_ok=True)
    (evidence / "validation.md").write_text(details)
    if not validation.get("passed") or validation.get("audit_errors"):
        raise ValueError("Frozen install or configured project validation failed")
    if ENGINE["valid_snapshot"](directory) != candidate:
        raise ValueError("Validation changed the candidate dependency files")
    audit_candidate(directory, snapshot, candidate, inputs, items, deadline)


def publish(items, artifact):
    pr = guard(items)
    if git("rev-parse", "HEAD") != os.environ["REPAIR_HEAD"]:
        raise ValueError("Publisher checkout differs from the approved head")
    directory, _ = PROJECT["project_directory"](
        Path.cwd().resolve(),
        PROJECT["CONFIGURATION"]["local_configuration"](Path.cwd()),
    )
    before = ENGINE["valid_snapshot"](directory)
    paths = {
        (directory / name).relative_to(Path.cwd()).as_posix()
        for name in ("pnpm-workspace.yaml", "pnpm-lock.yaml")
    }
    patch = artifact / "candidate" / "candidate.patch"
    subprocess.run(["git", "apply", "--check", str(patch)], check=True)
    subprocess.run(["git", "apply", str(patch)], check=True)
    changed = set(
        subprocess.check_output(["git", "diff", "--name-only", "-z"], text=True)
        .strip("\0")
        .split("\0")
    )
    if changed != paths:
        raise ValueError("Candidate contains unapproved paths")
    check_scope(before, ENGINE["valid_snapshot"](directory), items)
    if any(
        (directory / name).is_symlink()
        for name in ("package.json", "pnpm-workspace.yaml", "pnpm-lock.yaml")
    ):
        raise ValueError("Symlinked dependency files are not supported for repair")
    subprocess.run(["git", "add", "--", *sorted(paths)], check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=github-actions[bot]",
            "-c",
            "user.email=41898282+github-actions[bot]@users.noreply.github.com",
            "commit",
            "-m",
            "Node: apply selected security pin repairs\n\nNode-Repair: validated-selected-pins-v1",
        ],
        check=True,
    )
    guard(items)
    branch = pr["head"]["ref"]
    subprocess.run(
        [
            "git",
            "push",
            f"--force-with-lease=refs/heads/{branch}:{os.environ['REPAIR_HEAD']}",
            "origin",
            f"HEAD:refs/heads/{branch}",
        ],
        check=True,
    )
    body = artifact / "published.md"
    previous = pr["body"] or ""
    platform = ""
    if "## Platform security\n" in previous and "## Package security\n" in previous:
        platform = (
            "## Platform security\n"
            + previous.split("## Platform security\n", 1)[1].split(
                "## Package security\n", 1
            )[0]
        )
    body.write_text(
        "**Selected pin repairs · Validation job passed · Review before merging**\n\n"
        + platform
        + (artifact / "candidate" / "result.md").read_text()
        + f"\n[Validation and audit logs](https://github.com/{os.environ['GITHUB_REPOSITORY']}/actions/runs/{os.environ['GITHUB_RUN_ID']})\n"
    )
    subprocess.run(
        ["gh", "pr", "edit", os.environ["REPAIR_PR"], "--body-file", str(body)],
        check=True,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "operation", choices=("guard", "prepare", "validate", "publish")
    )
    parser.add_argument(
        "--artifact",
        type=Path,
        default=Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "node-repair",
    )
    args = parser.parse_args()
    try:
        items = request()
        if args.operation == "guard":
            guard(items)
        elif args.operation == "prepare":
            os.environ["npm_config_ignore_pnpmfile"] = "true"
            os.environ["pnpm_config_ignore_pnpmfile"] = "true"
            prepare(items, args.artifact)
        elif args.operation == "validate":
            validate(items, args.artifact)
        else:
            publish(items, args.artifact)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        evidence = args.artifact / "evidence"
        evidence.mkdir(parents=True, exist_ok=True)
        (evidence / "failure.md").write_text(
            "## Repair attempt failed\n\nThe batch did not complete. "
            "No automatic retry was requested. Inspect this run's logs before trying again.\n\n"
            + str(error)[:2000]
            + "\n"
        )
        parser.exit(1, str(error) + "\n")


if __name__ == "__main__":
    main()
