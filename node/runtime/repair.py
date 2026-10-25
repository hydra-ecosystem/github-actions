"""Prepare a sealed pnpm candidate and validate it without publication."""

import argparse
import copy
import json
import os
import re
import runpy
import subprocess
import tempfile
import time
from collections import Counter
from contextlib import contextmanager
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
HOOK_ENV = {
    f"{namespace}_config_{setting}": "true"
    for namespace in ("npm", "pnpm")
    for setting in ("ignore_scripts", "ignore_pnpmfile")
}


def json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field")
        result[key] = value
    return result


def request():
    number = os.environ["REPAIR_PR"]
    if not re.fullmatch(r"[1-9][0-9]*", number):
        raise ValueError("Invalid PR number")
    items = CHOICES["validate"](
        json.loads(os.environ["REPAIR_SELECTIONS"], object_pairs_hook=json_object)
    )
    CHOICES["fingerprint"](
        int(number), os.environ["REPAIR_HEAD"], os.environ["REPAIR_BASE"], items
    )
    identifier = os.environ["REPAIR_REQUEST"]
    repository = os.environ["GITHUB_REPOSITORY"]
    if not re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", identifier):
        raise ValueError("Invalid request identifier")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) or not items:
        raise ValueError("A repository and a nonempty selected batch are required")
    return dict(
        id=identifier,
        repository=repository,
        head=os.environ["REPAIR_HEAD"],
        base=os.environ["REPAIR_BASE"],
        pr=int(number),
        selections=items,
    )


def gh(path):
    return json.loads(subprocess.check_output(["gh", "api", path], text=True))


def git(*args):
    return subprocess.check_output(["git", *args], text=True)


def guard(expected):
    repo = expected["repository"]
    repository = gh(f"repos/{repo}")
    pr = gh(f"repos/{repo}/pulls/{expected['pr']}")
    body = pr.get("body") or ""
    markers = [
        line
        for line in re.split(r"\r?\n", body)
        if "<!-- node-repair:revision:" in line
    ]
    if (
        repository.get("full_name") != repo
        or type(repository.get("id")) is not int
        or not repository.get("default_branch")
        or pr.get("number") != expected["pr"]
        or pr.get("state") != "open"
        or pr.get("user", {}).get("type") != "Bot"
        or any(
            pr.get(side, {}).get("repo", {}).get("id") != repository["id"]
            for side in ("head", "base")
        )
        or pr.get("head", {}).get("ref") != "maintenance/node-security"
        or pr.get("base", {}).get("ref") != repository["default_branch"]
        or pr["head"].get("sha") != expected["head"]
        or pr["base"].get("sha") != expected["base"]
        or markers != [CHOICES["revision_marker"](expected["head"], expected["base"])]
        or CHOICES["parse"](body) != expected["selections"]
    ):
        raise ValueError("PR state or selections changed; request a fresh repair")
    return pr


@contextmanager
def suppress_hooks():
    previous = {key: os.environ.get(key) for key in HOOK_ENV}
    os.environ.update(HOOK_ENV)
    try:
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def project_path(root, name):
    if not isinstance(name, str) or not name or "\\" in name:
        raise ValueError("Invalid project directory")
    relative = Path(name)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("Project directory must stay inside the repository")
    path = root
    for part in relative.parts:
        path /= part
        if path.is_symlink():
            raise ValueError("Symlinked project parents are unsupported")
    return relative.as_posix()


def project_context():
    root = Path.cwd().resolve()
    config_path = (
        Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "node-repair-config.json"
    )
    directory, selected = PROJECT["resolve_for_run"](root, config_path, [])
    configuration = json.loads(config_path.read_text())["configuration"]
    name = project_path(root, configuration["directory"])
    if root / name != directory or selected["manager"] != "pnpm":
        raise ValueError("Repair attempts require a standalone pnpm project")
    PROJECT["verify_runtime"](directory, selected)
    snapshot = ENGINE["valid_snapshot"](directory)
    if snapshot is None:
        raise ValueError("Invalid project snapshot")
    return directory, selected, snapshot


def update_policy(text, items):
    """Replace only the selected scalar values, preserving comments and layout."""
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
    old, new = (yaml.safe_load(s[1]["pnpm-workspace.yaml"]) for s in (before, after))
    expected = copy.deepcopy(old)
    for item in items:
        if old.get("overrides", {}).get(item["name"]) != item["from"]:
            raise ValueError("The approved pin changed")
        expected["overrides"][item["name"]] = item["to"]
    if expected != new:
        raise ValueError("The repair changed unapproved pnpm policy")
    versions = [ENGINE["locked_version_sets"](s[3]) for s in (before, after)]
    selected = {item["name"]: item for item in items}
    for name in versions[0].keys() | versions[1].keys():
        if name not in selected and versions[0].get(name) != versions[1].get(name):
            raise ValueError(f"The repair changed an unselected package: {name}")
    for item in items:
        if any(
            v.get(item["name"]) != {item[key]}
            for v, key in zip(versions, ("from", "to"))
        ):
            raise ValueError("The approved version must cover every installed instance")

    def version(name, value):
        if name in selected and isinstance(value, str):
            base, separator, peers = value.partition("(")
            if base in (selected[name]["from"], selected[name]["to"]):
                return "<selected>" + separator + peers
        return value

    def normalize(snapshot):
        lock = yaml.safe_load(snapshot[1]["pnpm-lock.yaml"])
        for name, value in lock.get("overrides", {}).items():
            lock["overrides"][name] = version(name, value)
        for importer in lock.get("importers", {}).values():
            for section in ("dependencies", "devDependencies", "optionalDependencies"):
                for name, edge in importer.get(section, {}).items():
                    if name in selected and isinstance(edge, dict):
                        for field in ("specifier", "version"):
                            if field in edge:
                                edge[field] = version(name, edge[field])
        for section in ("packages", "snapshots"):
            entries = lock.get(section, {})
            for key in list(entries):
                name, separator, base = key.split("(", 1)[0].rpartition("@")
                if (
                    separator
                    and name in selected
                    and base in (selected[name]["from"], selected[name]["to"])
                ):
                    suffix = key[len(f"{name}@{base}") :]
                    del entries[key]
                    entries[f"{name}@<selected>{suffix}"] = None
                    continue
                if section == "snapshots":
                    for kind in ("dependencies", "optionalDependencies"):
                        for name, value in entries[key].get(kind, {}).items():
                            entries[key][kind][name] = version(name, value)
        return lock

    if normalize(before) != normalize(after):
        raise ValueError("The repair changed unrelated lockfile metadata or edges")


def verified_targets(directory, before, snapshot, items, deadline, age):
    proof = copy.deepcopy(before)
    validate_audit(proof)
    ENGINE["describe_pnpm_fixes"](
        directory, proof, snapshot[1], [], deadline, {}, collect_proof=True
    )
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=age)
    for item in items:
        if (
            yaml.safe_load(snapshot[1]["pnpm-workspace.yaml"])
            .get("overrides", {})
            .get(item["name"])
            != item["from"]
        ):
            raise ValueError("Approved exact pin is missing")
        details = proof["vulnerabilities"].get(item["name"], {}).get("via", [])
        if not details or any(
            detail.get("_repairFrom") != item["from"]
            or item["to"] not in detail.get("_verifiedRepairVersions", [])
            or item["from"] not in detail.get("_verifiedVulnerableVersions", [])
            for detail in details
        ):
            raise ValueError("Published patch and parent compatibility are unverified")
        for field in ("dependencies", "devDependencies", "optionalDependencies"):
            constraint = snapshot[2].get(field, {}).get(item["name"])
            if constraint is None:
                continue
            allowed = False
            for alternative in (
                constraint.split("||") if isinstance(constraint, str) else []
            ):
                result = ENGINE["run"](
                    directory,
                    "view",
                    f"{item['name']}@{alternative.strip()} {item['to']}",
                    "version",
                    "--json",
                    deadline=deadline,
                )
                try:
                    values = json.loads(result.stdout)
                except ValueError:
                    values = None
                if result.returncode == 0 and (
                    values == item["to"]
                    or isinstance(values, list)
                    and item["to"] in values
                ):
                    allowed = True
            if not allowed:
                raise ValueError("Direct manifest compatibility is unverified")
        result = ENGINE["run"](
            directory, "view", item["name"], "time", "--json", deadline=deadline
        )
        if result.returncode:
            raise ValueError("Release publication time is unavailable")
        published = json.loads(result.stdout).get(item["to"])
        if not isinstance(published, str):
            raise ValueError("Release publication time is unavailable")
        stamp = datetime.fromisoformat(published.replace("Z", "+00:00"))
        if stamp.tzinfo is None or stamp > cutoff:
            raise ValueError("The selected patch has not passed the release cooldown")
    if ENGINE["valid_snapshot"](directory) != snapshot:
        raise ValueError("Metadata lookup changed dependency files")
    return proof


def validate_audit(data):
    if (
        not isinstance(data, dict)
        or data.get("package_manager") != "pnpm"
        or not isinstance(data.get("metadata"), dict)
        or not isinstance(data.get("advisories"), dict)
        or not isinstance(data.get("vulnerabilities"), dict)
        or data.get("error")
    ):
        raise ValueError("A complete structured pnpm audit is required")
    raw = []
    for advisory in data["advisories"].values():
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
            or advisory["severity"] not in ENGINE["SEVERITY_ORDER"]
            or not isinstance(advisory.get("findings"), list)
            or any(
                not isinstance(finding, dict)
                or not isinstance(finding.get("version"), str)
                or not finding["version"]
                for finding in advisory["findings"]
            )
            or "patched_versions" not in advisory
            or advisory["patched_versions"] is not None
            and not isinstance(advisory["patched_versions"], str)
        ):
            raise ValueError("Malformed raw audit advisory")
        raw.append(
            (
                advisory["module_name"],
                advisory["title"],
                advisory["url"],
                advisory["vulnerable_versions"],
                advisory["severity"],
                tuple(
                    sorted(
                        f"{advisory['module_name']}@{finding['version']}"
                        for finding in advisory["findings"]
                    )
                ),
                advisory["patched_versions"],
            )
        )
    observed = []
    for name, finding in data["vulnerabilities"].items():
        if (
            not isinstance(name, str)
            or not name
            or not isinstance(finding, dict)
            or not isinstance(finding.get("via"), list)
            or not finding["via"]
        ):
            raise ValueError("Malformed audit finding")
        for detail in finding["via"]:
            if (
                not isinstance(detail, dict)
                or any(
                    not isinstance(detail.get(key), str) or not detail[key]
                    for key in ("title", "url", "range", "severity")
                )
                or detail["severity"] not in ENGINE["SEVERITY_ORDER"]
                or not isinstance(detail.get("nodes"), list)
                or any(not isinstance(node, str) for node in detail["nodes"])
                or "patchedRange" not in detail
                or detail["patchedRange"] is not None
                and not isinstance(detail["patchedRange"], str)
            ):
                raise ValueError("Malformed audit advisory")
            observed.append(
                (
                    name,
                    detail["title"],
                    detail["url"],
                    detail["range"],
                    detail["severity"],
                    tuple(sorted(detail["nodes"])),
                    detail.get("patchedRange"),
                )
            )
    if Counter(raw) != Counter(observed):
        raise ValueError("Raw and normalized audit advisories do not match")
    normalized = {
        str(index): detail
        for index, (_, _, detail) in enumerate(ENGINE["audit_entries"](data, "pnpm"))
    }
    if (
        not ENGINE["counts_match_details"](
            data["metadata"].get("vulnerabilities"),
            data["vulnerabilities"],
            "pnpm",
            data["advisories"],
        )
        or not ENGINE["counts_match_details"](
            data["metadata"].get("vulnerabilities"),
            data["vulnerabilities"],
            "pnpm",
            normalized,
        )
        or ENGINE["finding_ids"](data, "pnpm") is None
    ):
        raise ValueError("Audit counts do not match findings")


def validate_envelope(data, expected, directory):
    if (
        not isinstance(data, dict)
        or set(data)
        != {"schema_version", "request", "project_directory", "before", "candidate"}
        or type(data["schema_version"]) is not int
        or data["schema_version"] != 1
        or not isinstance(data["request"], dict)
        or set(data["request"])
        != {"id", "repository", "head", "base", "pr", "selections"}
        or data["request"] != expected
        or type(data["request"].get("pr")) is not int
        or data["project_directory"] != directory
        or project_path(Path.cwd().resolve(), directory) != directory
    ):
        raise ValueError("Candidate audit does not match the request and project")
    CHOICES["fingerprint"](
        expected["pr"], expected["head"], expected["base"], expected["selections"]
    )
    for key in ("before", "candidate"):
        validate_audit(data[key])
    remaining = ENGINE["finding_ids"](data["candidate"], "pnpm")
    for item in expected["selections"]:
        details = data["before"]["vulnerabilities"].get(item["name"], {}).get("via", [])
        if not details or any(
            detail["url"] in remaining
            or item["to"] not in detail.get("_verifiedRepairVersions", [])
            or item["from"] not in detail.get("_verifiedVulnerableVersions", [])
            for detail in details
        ):
            raise ValueError("Selected fixes are not confirmed by the audit evidence")
    if ENGINE["newly_reported_findings"](data["before"], data["candidate"], "pnpm"):
        raise ValueError("The candidate introduced findings")
    return data


def read_envelope(path, expected, directory):
    if path.is_symlink() or not path.is_file():
        raise ValueError("Candidate audit must be a regular file")
    return validate_envelope(
        json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=json_object),
        expected,
        directory,
    )


def export_patch(paths):
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


def apply_candidate(expected, artifact, directory, snapshot):
    """Consume the preparation copy; never produce a new candidate artifact."""
    root = Path.cwd().resolve()
    if (
        artifact.is_symlink()
        or set(p.name for p in artifact.iterdir())
        != {"candidate.patch", "audit.json", "result.md"}
        or any(p.is_symlink() or not p.is_file() for p in artifact.iterdir())
    ):
        raise ValueError("Invalid sealed artifact members")
    envelope = read_envelope(
        artifact / "audit.json", expected, directory.relative_to(root).as_posix()
    )
    paths = {
        (directory / name).relative_to(root).as_posix()
        for name in ("pnpm-workspace.yaml", "pnpm-lock.yaml")
    }
    # Let Git parse quoted names, binary diffs and path safety. A temporary index
    # proves the complete patch's paths and modes before it touches the worktree.
    with tempfile.TemporaryDirectory(prefix="node-repair-index-") as temporary:
        environment = dict(os.environ, GIT_INDEX_FILE=str(Path(temporary) / "index"))

        def indexed(*args):
            return subprocess.check_output(["git", *args], env=environment, text=True)

        indexed("read-tree", "HEAD")
        indexed(
            "apply",
            "--cached",
            "--whitespace=nowarn",
            str(artifact / "candidate.patch"),
        )
        records = indexed(
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--cached",
            "--raw",
            "--no-abbrev",
            "-z",
            "HEAD",
        ).split("\0")
        if not records[0] or indexed(
            "diff", "--no-ext-diff", "--no-textconv", "--cached", "--summary", "HEAD"
        ):
            raise ValueError("Candidate must modify existing dependency files only")
        for index in range(0, len(records) - 1, 2):
            fields = records[index].split()
            if (
                len(fields) != 5
                or fields[:2] != [":100644", "100644"]
                or fields[4] != "M"
                or records[index + 1] not in paths
            ):
                raise ValueError("Candidate patch changed an unapproved path or mode")
    git("apply", "--whitespace=nowarn", str(artifact / "candidate.patch"))
    candidate = ENGINE["valid_snapshot"](directory)
    check_scope(snapshot, candidate, expected["selections"])
    return envelope, candidate


def validation_state(root, directory):
    """Capture declaration bytes and modes before running project code."""
    inputs = PROJECT["configuration_inputs"](root, directory)
    paths = set(inputs) | {(directory / "pnpm-lock.yaml").relative_to(root).as_posix()}
    for parent in (directory, *directory.parents):
        if parent.is_relative_to(root):
            paths.update(
                (parent / name).relative_to(root).as_posix()
                for name in (".npmrc", ".pnpmfile.cjs")
            )
    state = {}
    for name in paths:
        path = root / project_path(root, name)
        if path.exists():
            if path.is_symlink() or not path.is_file():
                raise ValueError("Validation declarations must remain regular files")
            state[name] = (path.stat().st_mode, path.read_bytes())
        else:
            state[name] = None
    return state


def validate(expected, artifact, evidence):
    root = Path.cwd().resolve()
    if (
        git("rev-parse", "HEAD").strip() != expected["head"]
        or git("status", "--porcelain", "--untracked-files=all").strip()
    ):
        raise ValueError("Validation requires a clean checkout of the expected head")
    if artifact.resolve() != artifact or artifact.is_relative_to(root):
        raise ValueError("Candidate artifacts must be outside the project checkout")
    if (
        evidence.resolve() != evidence
        or evidence.is_relative_to(root)
        or evidence.is_relative_to(artifact)
        or artifact.is_relative_to(evidence)
    ):
        raise ValueError(
            "Validation evidence must be separate from the checkout and candidate"
        )
    evidence.mkdir(parents=True, exist_ok=False)
    try:
        with suppress_hooks():
            directory, selected, snapshot = project_context()
            envelope, candidate = apply_candidate(
                expected, artifact, directory, snapshot
            )
        state = validation_state(root, directory)
        deadline = time.monotonic() + 40 * 60

        def unchanged():
            if (
                validation_state(root, directory) != state
                or ENGINE["valid_snapshot"](directory) != candidate
            ):
                raise ValueError("Validation changed dependency files or configuration")

        for label, arguments in (
            ("Frozen install", ("install", "--frozen-lockfile")),
            (
                "Configured project/local-patch checks",
                ("run", selected["validationScript"]),
            ),
        ):
            result = ENGINE["run"](directory, *arguments, deadline=deadline)
            (
                evidence
                / ("install.log" if label == "Frozen install" else "checks.log")
            ).write_text(result.stdout + "\n" + result.stderr)
            unchanged()
            if result.returncode:
                raise ValueError(f"{label} failed (exit {result.returncode})")
        with suppress_hooks():
            after = ENGINE["audit"](directory, deadline=deadline)
        unchanged()
        # Reuse the strict selected-fix and no-new-findings checks against a fresh
        # audit. The in-memory preparation envelope stays the comparison source.
        validate_envelope(
            dict(envelope, candidate=after), expected, envelope["project_directory"]
        )
        (evidence / "audit.json").write_text(
            json.dumps(after, ensure_ascii=False) + "\n"
        )
        message = "Validation passed: frozen install, configured project/local-patch checks and fresh advisory checks. No dependency change has been published."
    except Exception as error:
        (evidence / "result.md").write_text(
            "Validation failed. No dependency change has been published.\n\n"
            + str(error)
            + "\n"
        )
        raise
    (evidence / "result.md").write_text(message + "\n")
    return after


def prepare(expected, artifact):
    with suppress_hooks():
        return prepare_candidate(expected, artifact)


def prepare_candidate(expected, artifact):
    root = Path.cwd().resolve()
    if (
        git("rev-parse", "HEAD").strip() != expected["head"]
        or git("status", "--porcelain", "--untracked-files=all").strip()
    ):
        raise ValueError("Preparation requires a clean checkout of the expected head")
    directory, selected, snapshot = project_context()
    deadline = time.monotonic() + 40 * 60
    before = ENGINE["audit"](directory, deadline=deadline)
    items = expected["selections"]
    proof = verified_targets(
        directory, before, snapshot, items, deadline, selected["minimumReleaseAge"]
    )
    workspace = directory / "pnpm-workspace.yaml"
    workspace.write_text(update_policy(workspace.read_text(), items))
    if ENGINE["run"](directory, *CANDIDATE_INSTALL, deadline=deadline).returncode:
        raise ValueError("Candidate lockfile resolution failed")
    candidate = ENGINE["valid_snapshot"](directory)
    check_scope(snapshot, candidate, items)
    after = ENGINE["audit"](directory, deadline=deadline)
    validate_audit(after)
    fixed = ENGINE["confirmed_fixes"](proof, after, "pnpm", snapshot, candidate)
    required = {
        detail["url"]
        for item in items
        for detail in proof["vulnerabilities"][item["name"]]["via"]
    }
    if not required <= fixed:
        raise ValueError("The candidate did not confirm every selected advisory fix")
    ENGINE["describe_pnpm_fixes"](directory, after, candidate[1], [], deadline, {})
    if ENGINE["valid_snapshot"](directory) != candidate:
        raise ValueError("Audit lookup changed the candidate")
    paths = [
        (directory / name).relative_to(root).as_posix()
        for name in ("pnpm-workspace.yaml", "pnpm-lock.yaml")
    ]
    status = git("status", "--porcelain=v1", "-z", "--untracked-files=all")
    if any(
        not entry.startswith(" M ") or entry[3:] not in paths
        for entry in status.split("\0")
        if entry
    ):
        raise ValueError(
            "Preparation changed files outside the selected dependency scope"
        )
    patch = export_patch(paths)
    if not patch:
        raise ValueError("No candidate changes were produced")
    envelope = dict(
        schema_version=1,
        request=expected,
        project_directory=directory.relative_to(root).as_posix(),
        before=proof,
        candidate=after,
    )
    validate_envelope(envelope, expected, envelope["project_directory"])
    report = (
        "## Package security candidate\n\n"
        "Candidate preparation succeeded. Project validation has not run. No dependency change has been published.\n\n"
        + ENGINE["format_audit_summary"](
            proof, after, "pnpm", fixed_ids=fixed, locks=(snapshot[3], candidate[3])
        )
    )
    if artifact.resolve() != artifact or artifact.is_relative_to(root):
        raise ValueError("Candidate artifacts must be outside the project checkout")
    artifact.mkdir(parents=True, exist_ok=False)
    (artifact / "candidate.patch").write_bytes(patch)
    (artifact / "audit.json").write_text(
        json.dumps(envelope, ensure_ascii=False) + "\n"
    )
    (artifact / "result.md").write_text(report + "\n")
    if set(p.name for p in artifact.iterdir()) != {
        "candidate.patch",
        "audit.json",
        "result.md",
    } or any(p.is_symlink() or not p.is_file() for p in artifact.iterdir()):
        raise ValueError("Invalid sealed artifact members")
    return envelope


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("guard", "prepare", "validate"))
    parser.add_argument("--artifact", type=Path)
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    expected = request()
    if args.operation == "guard":
        guard(expected)
    elif args.artifact is None:
        parser.error("prepare and validate require --artifact")
    elif args.operation == "validate":
        if args.evidence is None:
            parser.error("validate requires --evidence")
        validate(expected, args.artifact, args.evidence)
    else:
        prepare(expected, args.artifact)


if __name__ == "__main__":
    main()
