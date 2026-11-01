"""Prepare, validate and publish exactly one sealed selected pnpm candidate."""

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
import tempfile
import time
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path
from zipfile import ZipFile

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


def gh(path, *, body=None):
    arguments = ["gh", "api", path]
    options = {}
    if body is not None:
        arguments += ["--method", "PATCH", "--input", "-"]
        options["input"] = json.dumps(body)
    return json.loads(subprocess.check_output(arguments, text=True, **options))


def git(*args, **kwargs):
    return subprocess.check_output(["git", *args], text=True, **kwargs)


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


def project_context(*, verify_runtime=True):
    root = Path.cwd().resolve()
    config_path = (
        Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "node-repair-config.json"
    )
    directory, selected = PROJECT["resolve_for_run"](root, config_path, [])
    configuration = json.loads(config_path.read_text())["configuration"]
    name = project_path(root, configuration["directory"])
    if root / name != directory or selected["manager"] != "pnpm":
        raise ValueError("Repair attempts require a standalone pnpm project")
    if verify_runtime:
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


REPAIR_HISTORY_TITLE = "Node repair evidence v1"
LOCATOR_KEYS = ("run", "job", "check", "artifact", "archive_sha256", "content_sha256")


def producer_names(run, repository, target, workflow_sha, leaf):
    """Resolve job display paths from immutable caller/reusable workflow bytes."""
    expected, ordinary = [], []
    references = run.get("referenced_workflows", [])

    def visit(repo, path, revision, prefix, ancestors):
        identity = (repo, path, revision)
        if (
            identity in ancestors
            or len(ancestors) >= 8
            or not re.fullmatch(r"\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml", path)
        ):
            raise ValueError("Unverifiable reusable workflow ancestry")
        data = ENGINE["history_api"](repo, f"contents/{path}?ref={revision}")
        if data.get("type") != "file" or data.get("encoding") != "base64":
            raise ValueError("Missing immutable workflow source")
        raw = base64.b64decode(data["content"].replace("\n", ""), validate=True)
        if len(raw) > 1048576:
            raise ValueError("Workflow source exceeds its bound")
        jobs = yaml.safe_load(raw)["jobs"]
        if f"{repo}/{path}" == target and revision == workflow_sha:
            expected.append(prefix + leaf)
            return
        for key, job in jobs.items():
            name = job.get("name", key)
            if not isinstance(name, str) or "${{" in name:
                raise ValueError("Dynamic producer ancestry is unverifiable")
            name = prefix + name
            uses = job.get("uses")
            if not uses:
                ordinary.append(name)
                continue
            source, _, ref = uses.partition("@")
            if source.startswith("./"):
                source = repo + "/" + source[2:]
                matches = [
                    r
                    for r in references
                    if r.get("path", "").split("@")[0] == source
                    and r.get("sha") == revision
                ]
            else:
                matches = [
                    r
                    for r in references
                    if r.get("path", "").split("@")[0] == source
                    and ref
                    in {
                        r.get("sha"),
                        r.get("ref"),
                        (r.get("ref") or "")
                        .removeprefix("refs/heads/")
                        .removeprefix("refs/tags/"),
                        r.get("path", "").partition("@")[2],
                    }
                ]
            if not matches:
                continue
            if len(matches) != 1:
                raise ValueError("Ambiguous reusable workflow source")
            owner, project, nested = source.split("/", 2)
            visit(
                owner + "/" + project,
                nested,
                matches[0]["sha"],
                name + " / ",
                (*ancestors, identity),
            )

    visit(repository, run.get("path", "").split("@")[0], run["head_sha"], "", ())
    if (
        not expected
        or len(set(expected)) != len(expected)
        or set(expected) & set(ordinary)
    ):
        raise ValueError("Missing or colliding immutable producer identity")
    return expected


def native_history(expected, directory, snapshot):
    """Read the nearest first-parent producer receipt, never editable PR prose."""
    root = Path.cwd().resolve()
    for commit in git("rev-list", "--first-parent", expected["head"]).splitlines():
        body = git("show", "-s", "--format=%B", commit)
        trailers = git("interpret-trailers", "--parse", input=body)
        repair = "Node-Repair: validated-selected-pins-v1" in trailers.splitlines()
        prefix = "Node-Repair-" if repair else "Node-Audit-"
        if not repair and "Node-Audit-" not in trailers:
            continue
        fields = {}
        for line in trailers.splitlines():
            if line.startswith(prefix):
                key, _, value = line[len(prefix) :].partition(": ")
                key = key.lower().replace("-", "_")
                if key in fields:
                    raise ValueError("Duplicate native evidence trailer")
                fields[key] = value
        workflow = fields.pop("workflow_sha", "")
        if set(fields) != set(LOCATOR_KEYS) or not re.fullmatch(
            r"[a-f0-9]{40}", workflow
        ):
            raise ValueError("Missing exact native evidence locator")
        locator = dict(fields)
        for key in LOCATOR_KEYS[:4]:
            if not re.fullmatch(r"[1-9][0-9]*", fields[key]):
                raise ValueError("Invalid native evidence identifier")
            locator[key] = int(fields[key])
        source = git("rev-parse", commit + "^").strip()
        project = directory.relative_to(root).as_posix()
        state = ENGINE["dependency_state"](snapshot)
        if repair:
            return verify_repair_history(
                locator, expected["repository"], source, project, state, workflow
            )
        job = ENGINE["history_api"](
            expected["repository"], f"actions/jobs/{locator['job']}"
        )
        name = job.get("name", "")
        suffix = name.rsplit(" / ", 1)[-1]
        if suffix not in {
            f"Node audit evidence ({p})"
            for p in ("dependency-audit", "node-main", "node-security", "node-upgrades")
        }:
            raise ValueError("Unexpected normal audit producer")
        run = ENGINE["history_api"](
            expected["repository"], f"actions/runs/{locator['run']}"
        )
        if name not in producer_names(
            run,
            expected["repository"],
            "hydra-ecosystem/github-actions/.github/workflows/node-audit.yml",
            workflow,
            suffix,
        ):
            raise ValueError("Normal history belongs to a sibling job")
        record = ENGINE["verify_history"](
            locator,
            repository=expected["repository"],
            source=source,
            project=project,
            candidate_state=state,
            trusted_workflow_sha=workflow,
            expected_job_name=name,
        )
        validate_history(record)
        return record
    raise ValueError(
        "No sealed historical evidence; review or replace the old proposal"
    )


def history_attempts(record):
    return record.get("attempts", [record])


def validate_history(record):
    attempts = history_attempts(record)
    if not isinstance(attempts, list) or not attempts:
        raise ValueError("Invalid cumulative attempt inventory")
    prior = None
    for attempt in attempts:
        if (
            not isinstance(attempt, dict)
            or "attempts" in attempt
            or type(attempt.get("version")) is not int
            or attempt["version"] != 1
            or attempt.get("manager") != "pnpm"
            or any(attempt.get(k) != record.get(k) for k in ("repository", "project"))
            or not isinstance(attempt.get("package_report"), str)
            or not isinstance(attempt.get("fixed_ids"), list)
            or not re.fullmatch(r"[a-f0-9]{40}", attempt.get("source", ""))
        ):
            raise ValueError("Malformed historical attempt")
        for key in ("before", "after"):
            validate_audit(attempt[key])
        for key in ("before_state", "candidate_state"):
            if set(attempt[key]) != {
                "package.json",
                "pnpm-workspace.yaml",
                "pnpm-lock.yaml",
            } or any(
                not re.fullmatch(r"[a-f0-9]{64}", value)
                for value in attempt[key].values()
            ):
                raise ValueError("Invalid historical dependency state")
        if prior is not None and attempt["before_state"] != prior:
            raise ValueError("Broken historical dependency chain")
        prior = attempt["candidate_state"]
    if prior != record["candidate_state"] or attempts[-1]["source"] != record["source"]:
        raise ValueError("Cumulative history does not describe its final attempt")


def verify_repair_history(locator, repository, source, project, state, workflow):
    if (
        set(locator) != set(LOCATOR_KEYS)
        or any(type(locator[k]) is not int or locator[k] <= 0 for k in LOCATOR_KEYS[:4])
        or any(not re.fullmatch(r"[a-f0-9]{64}", locator[k]) for k in LOCATOR_KEYS[4:])
    ):
        raise ValueError("Invalid repair evidence locator")

    def api(suffix, **kw):
        return ENGINE["history_api"](repository, suffix, **kw)

    run = api(f"actions/runs/{locator['run']}")
    job = api(f"actions/jobs/{locator['job']}")
    jobs = api(
        f"actions/runs/{locator['run']}/attempts/{run['run_attempt']}/jobs?per_page=100"
    )
    name = job.get("name", "")
    expected_steps = [
        ("Prepare the selected candidate using trusted workflow code", "success"),
        ("Seal uploaded repair evidence", "success"),
    ]
    refs = [
        r
        for r in run.get("referenced_workflows", [])
        if r.get("path", "").split("@")[0]
        == "hydra-ecosystem/github-actions/.github/workflows/node-repair.yml"
    ]
    if (
        run.get("repository", {}).get("full_name") != repository
        or run.get("event") != "workflow_dispatch"
        or not re.fullmatch(r"[a-f0-9]{40}", run.get("head_sha", ""))
        or len(refs) != 1
        or refs[0].get("sha") != workflow
        or job.get("id") != locator["job"]
        or job.get("run_id") != locator["run"]
        or job.get("head_sha") != run["head_sha"]
        or job.get("run_attempt") != run["run_attempt"]
        or job.get("check_run_url")
        != f"https://api.github.com/repos/{repository}/check-runs/{locator['check']}"
        or job.get("status") != "completed"
        or job.get("conclusion") != "success"
        or jobs.get("total_count", 100) >= 100
        or [j.get("id") for j in jobs.get("jobs", []) if j.get("name") == name]
        != [locator["job"]]
        or [
            (s.get("name"), s.get("conclusion"))
            for s in job.get("steps", [])
            if s.get("name") in {n for n, _ in expected_steps}
        ]
        != expected_steps
    ):
        raise ValueError("Repair evidence does not identify the trusted producer")
    if name not in producer_names(
        run,
        repository,
        "hydra-ecosystem/github-actions/.github/workflows/node-repair.yml",
        workflow,
        "Node repair preparation",
    ):
        raise ValueError("Repair history belongs to a sibling job")
    check = api(f"check-runs/{locator['check']}")
    notices = [
        a
        for a in api(f"check-runs/{locator['check']}/annotations?per_page=100")
        if a.get("title") == REPAIR_HISTORY_TITLE
    ]
    message = f"v1:{locator['artifact']}:{locator['archive_sha256']}:{locator['content_sha256']}"
    if (
        check.get("id") != locator["check"]
        or check.get("head_sha") != run["head_sha"]
        or check.get("app", {}).get("id") != 15368
        or check.get("details_url") != job.get("html_url")
        or check.get("output", {}).get("annotations_count", 100) >= 100
        or len(notices) != 1
        or notices[0].get("annotation_level") != "notice"
        or notices[0].get("message") != message
    ):
        raise ValueError("Missing or ambiguous repair producer seal")
    artifact = api(f"actions/artifacts/{locator['artifact']}")
    if (
        artifact.get("id") != locator["artifact"]
        or artifact.get("expired") is not False
        or type(artifact.get("size_in_bytes")) is not int
        or not 0 < artifact["size_in_bytes"] <= 8388608
        or artifact.get("digest") != "sha256:" + locator["archive_sha256"]
        or artifact.get("workflow_run", {}).get("id") != locator["run"]
        or artifact.get("workflow_run", {}).get("head_sha") != run["head_sha"]
    ):
        raise ValueError("Repair artifact metadata differs from its producer seal")
    archive = api(f"actions/artifacts/{locator['artifact']}/zip", binary=True)
    if (
        len(archive) != artifact["size_in_bytes"]
        or hashlib.sha256(archive).hexdigest() != locator["archive_sha256"]
    ):
        raise ValueError("Repair archive digest differs")
    with ZipFile(BytesIO(archive)) as bundle:
        entries = bundle.infolist()
        if (
            len(entries) != 3
            or {e.filename for e in entries}
            != {"candidate.patch", "audit.json", "result.md"}
            or any(e.file_size > 1048576 for e in entries)
        ):
            raise ValueError("Unexpected repair artifact members or size")
        patch, audit, report = (
            bundle.read(n) for n in ("candidate.patch", "audit.json", "result.md")
        )
    if not patch or hashlib.sha256(report).hexdigest() != locator["content_sha256"]:
        raise ValueError("Repair report digest or patch differs")
    record = ENGINE["history_record"](report)
    envelope = json.loads(audit, object_pairs_hook=json_object)
    validate_envelope(envelope, envelope["request"], project)
    validate_history(record)
    if (
        (
            record["repository"],
            record["source"],
            record["project"],
            record["candidate_state"],
        )
        != (repository, source, project, state)
        or envelope["request"]["repository"] != repository
        or envelope["request"]["head"] != source
        or record["attempts"][-1]["before"] != envelope["before"]
        or record["attempts"][-1]["after"] != envelope["candidate"]
    ):
        raise ValueError("Repair history belongs to different source or dependencies")
    return record


def report_rows(report):
    """Consume the two existing shared-renderer table formats."""
    rows = []
    if "<table>" in report:
        for row in re.findall(r"<tr>(.*?)</tr>", report, re.S):
            cells = re.findall(r"<td>(.*?)</td>", row, re.S)
            if len(cells) != 6:
                continue
            cells = [
                re.sub(r'<a href="([^"]+)">(.*?)</a>', r"[\2](\1)", c) for c in cells
            ]
            cells = [
                html.unescape(re.sub(r"<code>(.*?)</code>", r"`\1`", c)) for c in cells
            ]
            rows.append(cells)
    else:
        rows = [
            line[2:-2].split(" | ")
            for line in report.splitlines()
            if line.startswith("| `") and line.endswith(" |")
        ]
    if any(len(row) != 6 or not re.fullmatch(r"`[^`\n|]+`", row[0]) for row in rows):
        raise ValueError("Unrecognized historical report row")
    return rows


def cumulative_report(
    history, expected, directory, selected, snapshot, candidate, before, after, fixed
):
    project = directory.relative_to(Path.cwd().resolve()).as_posix()
    state = ENGINE["dependency_state"](snapshot)
    validate_history(history)
    if (history["repository"], history["project"], history["candidate_state"]) != (
        expected["repository"],
        project,
        state,
    ):
        raise ValueError("Historical dependency state differs from the selected head")
    current = dict(
        version=1,
        repository=expected["repository"],
        source=expected["head"],
        project=project,
        manager="pnpm",
        before_state=state,
        candidate_state=ENGINE["dependency_state"](candidate),
        before=before,
        after=after,
        fixed_ids=sorted(fixed),
        package_report=ENGINE["format_audit_summary"](
            before, after, "pnpm", fixed_ids=fixed, locks=(snapshot[3], candidate[3])
        ),
    )
    attempts = history_attempts(history) + [current]
    record = dict(
        version=1,
        repository=expected["repository"],
        source=expected["head"],
        project=project,
        candidate_state=current["candidate_state"],
        attempts=attempts,
    )
    validate_history(record)
    unresolved = {
        (identity, name) for identity, name, _ in ENGINE["audit_entries"](after, "pnpm")
    }
    observed = unresolved | {
        (identity, name)
        for identity, name, _ in ENGINE["audit_entries"](before, "pnpm")
    }
    inventory, rows = set(), []
    for index, attempt in enumerate(attempts):
        previous = index < len(attempts) - 1
        entries = ENGINE["audit_entries"](attempt["before"], "pnpm") + ENGINE[
            "audit_entries"
        ](attempt["after"], "pnpm")
        inventory.update((identity, name) for identity, name, _ in entries)
        attempt_rows = report_rows(attempt["package_report"])
        if {name for _, name, _ in entries} - {row[0][1:-1] for row in attempt_rows}:
            raise ValueError("Historical report omits advisory rows")
        for row in attempt_rows:
            name = row[0][1:-1]
            if previous:
                pairs = {
                    (identity, package)
                    for identity, package, _ in entries
                    if package == name
                }
                missing, pending = pairs - observed, pairs & unresolved
                qualifier = "Current unresolved. " if pending else ""
                if pending:
                    qualifier += (
                        "Advisories: "
                        + ", ".join(
                            f"`{identity.rsplit('/', 1)[-1]}`"
                            for identity, _ in sorted(pending)
                        )
                        + ". "
                    )
                if missing or not pairs:
                    qualifier += "Not observed in the current audit. "
                    if missing:
                        qualifier += (
                            "Advisories: "
                            + ", ".join(
                                f"`{identity.rsplit('/', 1)[-1]}`"
                                for identity, _ in sorted(missing)
                            )
                            + ". "
                        )
                if pairs & observed - unresolved:
                    qualifier += "See current attempt for current evidence. "
                row[4] = (
                    f"Historical evidence (attempt {index + 1}). " + qualifier + row[4]
                )
            else:
                row[4] = "Current attempt. " + row[4]
            links = dict(
                (detail["url"], detail.get("title", identity))
                for identity, package, detail in entries
                if package == name
            )
            if any(not re.fullmatch(r"https://[^\s<>()\[\]|`]+", url) for url in links):
                raise ValueError("Unsafe historical advisory link")
            row[5] += " " + " ".join(
                f"[{url.rsplit('/', 1)[-1]}]({url})"
                for url in links
                if f"]({url})" not in row[5]
            )
            rows.append(
                "| "
                + " | ".join(
                    c.replace("\n", " ").replace("\r", " ").replace("|", "&#124;")
                    for c in row
                )
                + " |"
            )
    report = "## Package security candidate\n\nCandidate preparation succeeded. Project validation has not run. No dependency change has been published.\n\n"
    report += (
        "Selected repair attempt: "
        + ", ".join(
            f"`{i['name']} {i['from']} → {i['to']}`" for i in expected["selections"]
        )
        + ".\n\n"
    )
    report += f"Cumulative evidence: {len(inventory)} advisory/package pairs across {len(attempts)} attempts. Historical outcomes are not fresh fix claims.\n\n"
    report += (
        "| Package | Update | Severity | Advisories | Action / blocker | Security evidence |\n| --- | --- | --- | --- | --- | --- |\n"
        + "\n".join(rows)
    )
    encoded = base64.b64encode(ENGINE["canonical_history"](record)).decode("ascii")
    report += f"\n\n<!-- node-audit-history:v1:{encoded} -->\n"
    if len(encoded) > 524288 or len(report.encode()) > 1048576:
        raise ValueError("Cumulative history exceeds its bound; no artifact sealed")
    return report


def publication_locator(expected):
    """Resolve the exact original preparation notice in this workflow attempt."""
    run, attempt, artifact = (
        os.environ[key]
        for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "REPAIR_ARTIFACT_ID")
    )
    if any(
        not re.fullmatch(r"[1-9][0-9]*", value) for value in (run, attempt, artifact)
    ):
        raise ValueError("Invalid preparation run, attempt or artifact ID")
    repo = expected["repository"]
    data = ENGINE["history_api"](repo, f"actions/runs/{run}")
    if str(data.get("run_attempt")) != attempt:
        raise ValueError("Preparation workflow attempt changed")
    names = producer_names(
        data,
        repo,
        "hydra-ecosystem/github-actions/.github/workflows/node-repair.yml",
        os.environ["TRUSTED_WORKFLOW_SHA"],
        "Node repair preparation",
    )
    jobs = ENGINE["history_api"](
        repo, f"actions/runs/{run}/attempts/{attempt}/jobs?per_page=100"
    )
    matches = [j for j in jobs.get("jobs", []) if j.get("name") in names]
    if jobs.get("total_count", 100) >= 100 or len(matches) != 1:
        raise ValueError("Missing or ambiguous preparation producer")
    job = matches[0]
    check = job.get("check_run_url", "").removeprefix(
        f"https://api.github.com/repos/{repo}/check-runs/"
    )
    if not re.fullmatch(r"[1-9][0-9]*", check):
        raise ValueError("Invalid preparation Check URL")
    notices = [
        a
        for a in ENGINE["history_api"](
            repo, f"check-runs/{check}/annotations?per_page=100"
        )
        if a.get("title") == REPAIR_HISTORY_TITLE
    ]
    seal = (
        re.fullmatch(
            r"v1:([1-9][0-9]*):([a-f0-9]{64}):([a-f0-9]{64})",
            notices[0].get("message", ""),
        )
        if len(notices) == 1
        else None
    )
    if seal is None or seal[1] != artifact:
        raise ValueError("Preparation notice does not bind the original artifact ID")
    return dict(
        run=int(run),
        job=job["id"],
        check=int(check),
        artifact=int(artifact),
        archive_sha256=seal[2],
        content_sha256=seal[3],
    )


def publication_body(previous, report, expected, commit, envelope):
    """Use sealed package evidence and retain the existing platform section."""
    spans = list(
        re.finditer(r"(?ms)^## Platform security\r?\n.*?(?=^## |\Z)", previous)
    )
    if (
        len(spans) != 1
        or len(re.findall(r"(?im)^##[^\r\n]*platform[^\r\n]*", previous)) != 1
        or not re.match(r"## Package security\r?\n", previous[spans[0].end() :])
        or "<!-- node-repair:" in spans[0].group()
    ):
        raise ValueError("Missing or ambiguous platform report; refusing publication")
    platform = spans[0].group()
    history = ENGINE["history_record"](report.encode("utf-8"))
    validate_history(history)
    if not isinstance(history.get("attempts"), list) or len(history["attempts"]) < 2:
        raise ValueError("Preparation lacks complete cumulative history")
    preparation = (
        "Candidate preparation succeeded. Project validation has not run. "
        "No dependency change has been published."
    )
    if not report.startswith("## Package security candidate\n\n" + preparation):
        raise ValueError("Invalid sealed preparation report")
    report = ENGINE["HISTORY_PATTERN"].sub("", report, count=1)
    report = report.replace("## Package security candidate", "## Package security", 1)
    report = report.replace(
        preparation,
        "Selected repairs passed frozen installation, configured project/local-patch "
        "checks and a fresh audit, and were published to this PR. Human review is "
        "still required; nothing merges automatically.",
        1,
    ).replace("Current attempt. ✅ Fix proposed.", "Current attempt. ✅ Upgraded.")
    run = os.environ["GITHUB_RUN_ID"]
    if not re.fullmatch(r"[1-9][0-9]*", run):
        raise ValueError("Invalid workflow run ID")
    choices = CHOICES["render"](
        CHOICES["candidates"](envelope["candidate"]),
        head=commit,
        base=expected["base"],
    )
    marker = "" if choices else CHOICES["revision_marker"](commit, expected["base"])
    body = (
        platform + report.rstrip() + "\n\n"
        f"[Validated repair run](https://github.com/{expected['repository']}/actions/runs/{run})"
        f" · Repair commit `{commit}`\n\n" + choices + marker + "\n"
    )

    if len(body) > 65536:
        raise ValueError("Cumulative PR report exceeds GitHub's body limit")
    return body


def publish(expected, artifact):
    """Publish only the original preparation copy, without project execution."""
    root = Path.cwd().resolve()
    message = "No repair push was attempted."
    try:
        if (
            git("rev-parse", "HEAD").strip() != expected["head"]
            or git("status", "--porcelain", "--untracked-files=all").strip()
        ):
            raise ValueError("Publication requires a clean expected-head checkout")
        if artifact.resolve() != artifact or artifact.is_relative_to(root):
            raise ValueError("Candidate artifacts must be outside the checkout")
        guard(expected)
        directory, _, snapshot = project_context(verify_runtime=False)
        envelope, candidate = apply_candidate(expected, artifact, directory, snapshot)
        locator = publication_locator(expected)
        workflow = os.environ["TRUSTED_WORKFLOW_SHA"]
        record = verify_repair_history(
            locator,
            expected["repository"],
            expected["head"],
            directory.relative_to(root).as_posix(),
            ENGINE["dependency_state"](candidate),
            workflow,
        )
        if not isinstance(record.get("attempts"), list) or len(record["attempts"]) < 2:
            raise ValueError("Preparation lacks complete cumulative history")
        report = (artifact / "result.md").read_bytes()
        if (
            hashlib.sha256(report).hexdigest() != locator["content_sha256"]
            or record["attempts"][-1]["before"] != envelope["before"]
            or record["attempts"][-1]["after"] != envelope["candidate"]
        ):
            raise ValueError(
                "Local preparation copy differs from the original sealed candidate"
            )
        trailers = (
            "\n".join(
                f"Node-Repair-{key.replace('_', '-')}: {value}"
                for key, value in locator.items()
            )
            + f"\nNode-Repair-Workflow-SHA: {workflow}"
        )
        # Stage exact bytes without invoking Git clean filters from attributes.
        for name in ("pnpm-workspace.yaml", "pnpm-lock.yaml"):
            path = (directory / name).relative_to(root).as_posix()
            blob = git("hash-object", "-w", "--no-filters", "--", path).strip()
            git("update-index", "--cacheinfo", "100644", blob, path)
        commit = git(
            "-c",
            "commit.gpgsign=false",
            "-c",
            "user.name=github-actions[bot]",
            "-c",
            "user.email=41898282+github-actions[bot]@users.noreply.github.com",
            "commit-tree",
            git("write-tree").strip(),
            "-p",
            expected["head"],
            "-m",
            "Repair selected dependency pins\n\nNode-Repair: validated-selected-pins-v1\n"
            + trailers,
        ).strip()
        git(
            "-c",
            "core.hooksPath=/dev/null",
            "update-ref",
            "HEAD",
            commit,
            expected["head"],
        )
        current = guard(expected)
        body = publication_body(
            current["body"],
            report.decode("utf-8"),
            expected,
            commit,
            envelope,
        )
        token = base64.b64encode(
            ("x-access-token:" + os.environ["GH_TOKEN"]).encode()
        ).decode()
        environment = dict(
            os.environ,
            GIT_CONFIG_COUNT="1",
            GIT_CONFIG_KEY_0="http.https://github.com/.extraheader",
            GIT_CONFIG_VALUE_0="AUTHORIZATION: basic " + token,
            GIT_TERMINAL_PROMPT="0",
        )
        message = f"Repair push of commit {commit} attempted; inspect the branch before another attempt."
        subprocess.run(
            [
                "git",
                "-c",
                "core.hooksPath=/dev/null",
                "push",
                f"--force-with-lease=refs/heads/maintenance/node-security:{expected['head']}",
                "origin",
                "HEAD:refs/heads/maintenance/node-security",
            ],
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
        message = (
            f"Repair commit {commit} was published. The PR report update is incomplete; "
            "inspect the branch before another attempt."
        )
        latest = gh(f"repos/{expected['repository']}/pulls/{expected['pr']}")
        if (
            latest.get("head", {}).get("sha") != commit
            or latest.get("base", {}).get("sha") != expected["base"]
            or latest.get("body") != current["body"]
        ):
            raise ValueError(
                "PR changed after repair push; retain the commit and inspect the report"
            )
        gh(
            f"repos/{expected['repository']}/pulls/{expected['pr']}",
            body={"body": body},
        )
        message = f"Repair commit {commit} and its validated report were published. No merge occurred."
        return commit
    finally:
        print(message)
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as summary:
                summary.write(message + "\n")


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
    history = native_history(expected, directory, snapshot)
    deadline = time.monotonic() + 40 * 60
    before = ENGINE["audit"](directory, deadline=deadline)
    items = expected["selections"]
    proof = verified_targets(
        directory, before, snapshot, items, deadline, selected["minimumReleaseAge"]
    )
    workspace = directory / "pnpm-workspace.yaml"
    workspace.write_bytes(
        update_policy(workspace.read_bytes().decode("utf-8"), items).encode("utf-8")
    )
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
    ENGINE["describe_pnpm_fixes"](
        directory, after, candidate[1], [], deadline, {}, collect_proof=True
    )
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
    report = cumulative_report(
        history, expected, directory, selected, snapshot, candidate, proof, after, fixed
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
    parser.add_argument(
        "operation", choices=("guard", "prepare", "validate", "publish")
    )
    parser.add_argument("--artifact", type=Path)
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    expected = request()
    if args.operation == "guard":
        guard(expected)
    elif args.artifact is None:
        parser.error("prepare, validate and publish require --artifact")
    elif args.operation == "validate":
        if args.evidence is None:
            parser.error("validate requires --evidence")
        validate(expected, args.artifact, args.evidence)
    elif args.operation == "publish":
        publish(expected, args.artifact)
    else:
        prepare(expected, args.artifact)


if __name__ == "__main__":
    main()
