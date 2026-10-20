"""Check Node maintenance installations from immutable repository data only."""

import argparse
import base64
import functools
import hashlib
import html
import json
import os
import re
import runpy
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from threading import Lock

import yaml

PROJECT = runpy.run_path(str(Path(__file__).with_name("project.py")))
CONFIGURATION = PROJECT["CONFIGURATION"]
MAX_REPOSITORIES = 25
MAX_CONCURRENT_REPOSITORIES = 5
MAX_FILE_BYTES = 2_000_000
CONFIG_PATH = ".github/node-maintenance.json"
CALLER_PATH = ".github/workflows/dependency-audit.yml"
SHA = r"[0-9a-f]{40}"
MAJOR_RELEASE = r"v[1-9][0-9]*"
WORKFLOW_REF = rf"(?:{SHA}|{MAJOR_RELEASE})"
CRON_FIELDS = (
    (0, 59, {}),
    (0, 23, {}),
    (1, 31, {}),
    (
        1,
        12,
        {
            "JAN": 1,
            "FEB": 2,
            "MAR": 3,
            "APR": 4,
            "MAY": 5,
            "JUN": 6,
            "JUL": 7,
            "AUG": 8,
            "SEP": 9,
            "OCT": 10,
            "NOV": 11,
            "DEC": 12,
        },
    ),
    (0, 6, {"SUN": 0, "MON": 1, "TUE": 2, "WED": 3, "THU": 4, "FRI": 5, "SAT": 6}),
)


class Unverified(ValueError):
    """A required observation could not be obtained; this is not a pass."""


def workflow_snapshot_ref(ref):
    return "tags/" + ref if re.fullmatch(MAJOR_RELEASE, ref) else ref


class GitHub:
    def __init__(self, token=""):
        self.token = token
        self.snapshots = {}
        self.snapshot_locks = {}
        self.snapshot_locks_guard = Lock()
        self.defaults_lock = Lock()
        # Defaults remain public and unauthenticated, as in the individual audit.
        self.cached_defaults = functools.cache(CONFIGURATION["public_read"])
        # Public workflow metadata must not inherit private repository credentials.
        self.public_github = GitHub() if token else self

    def read_defaults(self, url, accept="application/json"):
        # Resolve each shared ref once, even when several repositories need it.
        with self.defaults_lock:
            return self.cached_defaults(url, accept)

    @functools.cache
    def get(self, path):
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "node-fleet-setup",
        }
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        request = urllib.request.Request(
            "https://api.github.com/" + path, headers=headers
        )
        try:
            # A redirect must never carry the token to another origin.
            with urllib.request.build_opener(CONFIGURATION["NoRedirect"]).open(
                request, timeout=20
            ) as response:
                data = response.read(8_000_001)
        except urllib.error.HTTPError as error:
            raise Unverified(
                f"GitHub read failed (HTTP {error.code}); check access and API limits"
            ) from error
        except (OSError, urllib.error.URLError) as error:
            raise Unverified(
                "GitHub read unavailable; rerun when access is restored"
            ) from error
        if len(data) > 8_000_000:
            raise Unverified("GitHub response exceeds the checker size limit")
        try:
            value = json.loads(data)
        except (ValueError, RecursionError) as error:
            raise Unverified("GitHub returned invalid JSON") from error
        if not isinstance(value, dict):
            raise Unverified("GitHub did not return a response object")
        return value

    def snapshot(self, repository, ref=""):
        repository = repository.lower()
        key = (repository, ref)
        with self.snapshot_locks_guard:
            lock = self.snapshot_locks.setdefault(key, Lock())
        with lock:
            if key not in self.snapshots:
                self.snapshots[key] = Repository(self, repository, ref)
            return self.snapshots[key]


class Repository:
    def __init__(self, github, repository, ref):
        self.github = github
        self.name = repository
        metadata = github.get(f"repos/{repository}")
        if not isinstance(metadata.get("default_branch"), str):
            raise Unverified("GitHub did not identify the default branch")
        self.ref = ref or metadata["default_branch"]
        commit = github.get(
            f"repos/{repository}/commits/{urllib.parse.quote(self.ref, safe='')}"
        )
        try:
            self.commit = commit["sha"]
            tree_sha = commit["commit"]["tree"]["sha"]
        except (KeyError, TypeError) as error:
            raise Unverified(
                "GitHub did not identify the pinned commit tree"
            ) from error
        if not all(
            isinstance(value, str) and re.fullmatch(SHA, value)
            for value in (self.commit, tree_sha)
        ):
            raise Unverified(
                "GitHub did not return immutable commit and tree identities"
            )
        tree = github.get(f"repos/{repository}/git/trees/{tree_sha}?recursive=1")
        if tree.get("truncated") is not False or not isinstance(tree.get("tree"), list):
            raise Unverified(
                "Repository tree is incomplete; no setup verdict is possible"
            )
        if any(
            not isinstance(entry, dict) or not isinstance(entry.get("path"), str)
            for entry in tree["tree"]
        ):
            raise Unverified("GitHub returned an invalid repository tree")
        self.files = {entry["path"]: entry for entry in tree["tree"]}
        if len(self.files) != len(tree["tree"]):
            raise Unverified("GitHub returned duplicate repository paths")

    def read(self, path, *, required=True, limit=65536):
        entry = self.files.get(path)
        if entry is None:
            if required:
                raise ValueError(f"Missing {path}")
            return None
        if entry.get("type") != "blob" or entry.get("mode") not in ("100644", "100755"):
            raise ValueError(
                f"{path} must be a regular file; symlinks and submodules are unsupported"
            )
        if type(entry.get("size")) is not int or not 0 <= entry["size"] <= limit:
            raise ValueError(f"{path} exceeds the supported file size ({limit} bytes)")
        blob_sha = entry.get("sha", "")
        if not re.fullmatch(SHA, blob_sha):
            raise Unverified(f"Invalid Git blob identity for {path}")
        blob = self.github.get(f"repos/{self.name}/git/blobs/{blob_sha}")
        try:
            if blob.get("encoding") != "base64" or not isinstance(
                blob.get("content"), str
            ):
                raise ValueError("unsupported encoding")
            data = base64.b64decode("".join(blob["content"].split()), validate=True)
        except (KeyError, TypeError, ValueError) as error:
            raise Unverified(f"Cannot decode {path}") from error
        if len(data) > limit or len(data) != entry["size"]:
            raise Unverified(f"File size differs from the pinned tree: {path}")
        actual = hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest()
        if actual != blob_sha:
            raise Unverified(f"File content differs from the pinned tree: {path}")
        return data


def inventory(value):
    if not isinstance(value, dict) or set(value) != {"defaults", "repositories"}:
        raise ValueError("Inventory requires exactly defaults and repositories")
    CONFIGURATION["validate_source"](value["defaults"])
    repos = value["repositories"]
    if not isinstance(repos, list) or not 1 <= len(repos) <= MAX_REPOSITORIES:
        raise ValueError(
            f"repositories must contain 1 to {MAX_REPOSITORIES} owner/repository names"
        )
    names = []
    for name in repos:
        repository, _, _ = CONFIGURATION["validate_source"](
            {"repository": name, "path": "inventory.json", "ref": "main"}
        )
        if repository in names:
            raise ValueError(f"Duplicate repository: {repository}")
        names.append(repository)
    return {"defaults": value["defaults"], "repositories": names}


def materialize(repository, root):
    """Copy only required data into a private temporary directory. Execute nothing."""

    def copy(path, *, required=False, limit=65536):
        data = repository.read(path, required=required, limit=limit)
        if data is not None:
            destination = root / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
        return data

    raw = copy(CONFIG_PATH, required=True)
    config = CONFIGURATION["json_object"](raw, CONFIG_PATH)
    CONFIGURATION["validate_settings"](config, CONFIG_PATH)
    name = config.get("directory")
    if (
        not isinstance(name, str)
        or not name
        or PROJECT["DIRECTORY_PATTERN"].fullmatch(name) is None
        or PurePosixPath(name).is_absolute()
        or ".." in PurePosixPath(name).parts
    ):
        raise ValueError("directory must select a project inside the repository")
    directory = PurePosixPath(name)
    found_node = False
    for parent in (directory, *directory.parents):
        prefix = "" if parent == PurePosixPath(".") else str(parent) + "/"
        copy(prefix + "package.json", required=parent == directory)
        copy(prefix + "pnpm-workspace.yaml")
        declarations = [prefix + filename for filename in (".nvmrc", ".node-version")]
        if not found_node and any(path in repository.files for path in declarations):
            for path in declarations:
                copy(path)
            found_node = True
    prefix = "" if directory == PurePosixPath(".") else str(directory) + "/"
    for filename in ("package-lock.json", "pnpm-lock.yaml", "npm-shrinkwrap.json"):
        copy(prefix + filename, limit=MAX_FILE_BYTES)
    copy(CALLER_PATH, required=True)


def check_engines(directory, selected):
    """Find a compatible stable version in a declared major using range boundaries."""
    expression = (
        json.loads((directory / "package.json").read_bytes())
        .get("engines", {})
        .get("node")
    )
    if expression is None or "." in selected["node"]:
        return  # Exact versions are checked by project().
    major = int(selected["node"])
    candidates = {(major, 13 if major == 22 else 0, 0)}
    for match in re.finditer(r"v?(\d+(?:\.\d+){0,2})", expression):
        parts = tuple(map(int, match[1].split(".")))
        version = parts + (0,) * (3 - len(parts))
        candidates.update(
            (version, (*version[:2], version[2] + 1), (version[0], version[1] + 1, 0))
        )
    if not any(
        version[0] == major
        and version >= (22, 13, 0)
        and PROJECT["node_satisfies"](version, expression)
        for version in candidates
    ):
        raise ValueError(
            f"Node {major} has no supported stable version matching engines.node={expression!r}"
        )


def _cron_number(value, minimum, maximum, names):
    upper = value.upper()
    if upper in names:
        number = names[upper]
    elif value.isascii() and value.isdecimal():
        number = int(value)
    else:
        raise ValueError(f"Unsupported cron value {value!r}")
    if not minimum <= number <= maximum:
        raise ValueError(f"Cron value {value!r} is outside {minimum}-{maximum}")
    return number


def _cron_part(value, minimum, maximum, names):
    if not value:
        raise ValueError("Cron fields cannot be empty")
    if "/" in value:
        if value.count("/") != 1:
            raise ValueError(f"Unsupported cron step {value!r}")
        base, step = value.split("/")
        if not step.isascii() or not step.isdecimal() or int(step) <= 0:
            raise ValueError(f"Invalid cron step {value!r}")
        if base != "*":
            _cron_part(base, minimum, maximum, names)
        return
    if value == "*":
        return
    if "," in value:
        parts = value.split(",")
        if any(not part for part in parts):
            raise ValueError(f"Invalid cron list {value!r}")
        for part in parts:
            _cron_part(part, minimum, maximum, names)
        return
    if "-" in value:
        if value.count("-") != 1:
            raise ValueError(f"Unsupported cron range {value!r}")
        start, end = value.split("-")
        if _cron_number(start, minimum, maximum, names) > _cron_number(
            end, minimum, maximum, names
        ):
            raise ValueError(f"Cron range is reversed {value!r}")
        return
    _cron_number(value, minimum, maximum, names)


def validate_cron(value, location="schedule"):
    """Validate the bounded cron forms used by fleet setup comparisons."""
    if not isinstance(value, str) or len(value.split()) != 5:
        raise ValueError(f"{location} requires a five-field cron expression")
    for field, (minimum, maximum, names) in zip(value.split(), CRON_FIELDS):
        _cron_part(field, minimum, maximum, names)


def validate_crons(values, location="schedule"):
    if not isinstance(values, list):
        raise ValueError(f"{location} must be a list of cron expressions")
    for value in values:
        validate_cron(value, location)


def _validate_call_interface(job, call, path):
    supplied_inputs = job.get("with", {})
    supplied_secrets = job.get("secrets", {})
    declared_inputs = call.get("inputs", {})
    declared_secrets = call.get("secrets", {})
    if not isinstance(supplied_inputs, dict) or not isinstance(supplied_secrets, dict):
        raise ValueError(
            f"Caller must use explicit input and secret mappings for {path}"
        )
    if not isinstance(declared_inputs, dict) or not isinstance(declared_secrets, dict):
        raise ValueError(f"Pinned {path} has invalid workflow_call mappings")
    if not set(supplied_inputs) <= set(declared_inputs):
        raise ValueError(f"Caller supplies undeclared inputs to pinned {path}")
    if not set(supplied_secrets) <= set(declared_secrets):
        raise ValueError(f"Caller supplies undeclared secrets to pinned {path}")
    for name, declaration in declared_inputs.items():
        if not isinstance(declaration, dict):
            raise ValueError(f"Pinned {path} has an invalid input declaration")
        if declaration.get("required") is True and name not in supplied_inputs:
            raise ValueError(f"Caller omits required input {name!r} for pinned {path}")
    for name, declaration in declared_secrets.items():
        if not isinstance(declaration, dict):
            raise ValueError(f"Pinned {path} has an invalid secret declaration")
        if declaration.get("required") is True and name not in supplied_secrets:
            raise ValueError(
                f"Caller omits required secret mapping {name!r} for pinned {path}"
            )


def check_caller(root, config, selected, github, default_branch="main"):
    workflow = yaml.safe_load((root / CALLER_PATH).read_bytes())
    if not isinstance(workflow, dict):
        raise ValueError("Caller must be a workflow mapping")
    events = workflow.get("on", workflow.get(True, {}))
    if not isinstance(events, dict):
        raise ValueError("Caller requires schedules and workflow_dispatch")
    dispatch = events.get("workflow_dispatch")
    choice = (
        dispatch.get("inputs", {}).get("audit-kind", {})
        if isinstance(dispatch, dict)
        else {}
    )
    if (
        choice.get("type") != "choice"
        or set(choice.get("options", [])) != {"security", "upgrades"}
        or choice.get("default") != "security"
    ):
        raise ValueError(
            "Caller requires the security/upgrades manual choice with default security"
        )
    jobs = workflow.get("jobs", {})
    if not isinstance(jobs, dict) or not jobs:
        raise ValueError("Caller requires a nonempty jobs mapping")
    coordinated = "maintenance" in jobs
    if coordinated:
        job = jobs["maintenance"]
        pattern = rf"([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/\.github/workflows/node-maintenance\.yml@({WORKFLOW_REF})"
        match = re.fullmatch(pattern, job.get("uses", ""))
        if set(jobs) != {"maintenance"} or not match or "if" in job or "needs" in job:
            raise ValueError(
                "Coordinated caller requires one unconditional maintenance job"
            )
        if job.get("permissions") != {
            "contents": "write",
            "pull-requests": "write",
            "issues": "write",
        }:
            raise ValueError(
                "Coordinated caller permissions differ from the supported contract"
            )
        if (
            job.get("with", {}).get("audit-kind")
            != "${{ inputs.audit-kind || 'auto' }}"
        ):
            raise ValueError("Coordinated caller must forward audit-kind")
        expected_push = {
            "branches": [default_branch],
            "paths": [
                "**/pnpm-lock.yaml",
                "**/package-lock.json",
                ".github/node-maintenance.json",
            ],
        }
        if events.get("push") != expected_push:
            raise ValueError(
                "Coordinated caller requires the default-branch dependency path filters"
            )
        calls = [(job, ".github/workflows/node-maintenance.yml")]
        if workflow.get("concurrency") != {
            "group": "dependency-audit",
            "cancel-in-progress": False,
            "queue": "max",
        }:
            raise ValueError(
                "Coordinated caller must retain pending runs with queue: max"
            )
    else:
        audit, publisher = jobs.get("audit", {}), jobs.get("pull-request", {})
        if not isinstance(audit, dict) or not isinstance(publisher, dict):
            raise ValueError("Caller requires audit and pull-request job mappings")
        if "if" in audit or "if" in publisher:
            raise ValueError(
                "Caller audit and publisher jobs must be unconditionally enabled"
            )
        pattern = rf"([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/\.github/workflows/node-audit\.yml@({WORKFLOW_REF})"
        match = re.fullmatch(pattern, audit.get("uses", ""))
        if (
            not match
            or publisher.get("uses")
            != f"{match[1]}/.github/workflows/node-publish.yml@{match[2]}"
        ):
            raise ValueError(
                "Audit and publisher must use matching Node workflows at the same major release tag (such as v1) or full commit SHA"
            )
        needs = publisher.get("needs", [])
        if "needs" in audit or needs not in ("audit", ["audit"]):
            raise ValueError(
                "Audit must have no prerequisites; publisher must depend only on audit"
            )
        if audit.get("permissions") != {
            "contents": "read",
            "issues": "write",
        } or publisher.get("permissions") != {
            "contents": "write",
            "pull-requests": "write",
        }:
            raise ValueError(
                "Caller audit/publisher permissions differ from the supported caller contract"
            )
        if (
            audit.get("with", {}).get("audit-kind")
            != "${{ inputs.audit-kind || 'auto' }}"
            or publisher.get("with", {}).get("validation-passed")
            != "${{ needs.audit.outputs.validation_passed }}"
        ):
            raise ValueError(
                "Caller must forward audit-kind and the audit validation result"
            )
        calls = [
            (audit, ".github/workflows/node-audit.yml"),
            (publisher, ".github/workflows/node-publish.yml"),
        ]
    concurrency = workflow.get("concurrency", {})
    if (
        not isinstance(concurrency, dict)
        or concurrency.get("cancel-in-progress") is not False
        or not concurrency.get("group")
    ):
        raise ValueError(
            "Caller must serialize runs with concurrency and cancel-in-progress: false"
        )
    source = github.public_github.snapshot(match[1], workflow_snapshot_ref(match[2]))
    contract = CONFIGURATION["json_object"](
        source.read("node/contract.json"), "pinned Node contract"
    )
    if contract.get("component") != "node" or contract.get("integration_version") != 6:
        raise ValueError(
            "Pinned workflows must declare the supported Node integration version 6"
        )
    if (
        "localPatches" in config
        and contract.get("local_patches", {}).get("config_key") != "localPatches"
    ):
        raise ValueError(
            "Pinned workflows do not support localPatches; update both workflow pins"
        )
    toolchain = CONFIGURATION["json_object"](
        source.read("node/runtime/toolchain.json"), "pinned toolchain support"
    ).get("supported", {})
    manager = selected["manager"]
    if selected["node"].split(".")[0] not in toolchain.get("node", []) or selected[
        manager
    ] not in toolchain.get(manager, []):
        raise ValueError(
            "Pinned workflows do not support the resolved toolchain; update both workflow pins or align project policy"
        )
    if (
        coordinated
        and contract.get("coordinated_maintenance", {}).get("workflow")
        != ".github/workflows/node-maintenance.yml"
    ):
        raise ValueError("Pinned workflows do not support coordinated maintenance")
    for job, path in calls:
        reusable = yaml.safe_load(source.read(path))
        triggers = (
            reusable.get("on", reusable.get(True, {}))
            if isinstance(reusable, dict)
            else {}
        )
        call = triggers.get("workflow_call") if isinstance(triggers, dict) else None
        if (
            not isinstance(call, dict)
            or not isinstance(reusable.get("jobs"), dict)
            or not reusable["jobs"]
        ):
            raise ValueError(f"Pinned {path} is not a reusable workflow")
        _validate_call_interface(job, call, path)
        if path.endswith("node-audit.yml") and "validation_passed" not in call.get(
            "outputs", {}
        ):
            raise ValueError("Pinned audit workflow does not expose validation_passed")
    configured = config.get("schedule", ["0 2 30 1 *"])
    validate_crons(
        PROJECT["SCHEDULING"]["cron_entries"](configured), "resolved schedule"
    )
    if isinstance(config.get("schedule"), dict):
        PROJECT["SCHEDULING"]["select_mode"](
            root,
            config,
            selected["maintenance"]["mode"],
            "auto",
            "workflow_dispatch",
            {},
        )
    else:
        actual = events.get("schedule", [])
        actual_crons = (
            [item.get("cron") for item in actual] if isinstance(actual, list) else []
        )
        validate_crons(actual_crons, "caller schedule")
        if (
            not isinstance(actual, list)
            or any(not isinstance(item, dict) for item in actual)
            or sorted(actual_crons) != sorted(configured)
        ):
            raise ValueError("Caller cron entries differ from the resolved schedule")


def check_repository(github, name, expected):
    result = {
        "repository": name,
        "commit": None,
        "status": "unverified",
        "diagnostic": "",
    }
    try:
        repository = github.snapshot(name)
        result["commit"] = repository.commit
        with TemporaryDirectory(prefix="node-fleet-") as temporary:
            root = Path(temporary)
            materialize(repository, root)
            sources = []
            config = CONFIGURATION["load_configuration"](
                root, sources, read=github.read_defaults
            )
            wanted = CONFIGURATION["validate_source"](expected)
            if not any(
                (source["repository"], source["path"], source["ref"]) == wanted
                for source in sources
            ):
                raise ValueError(
                    "Installation no longer follows the inventory's expected defaults repository/path/ref"
                )
            directory, selected = PROJECT["project"](root, config=config)
            PROJECT["verify_package_files"](directory, selected)
            check_engines(directory, selected)
            check_caller(root, config, selected, github, repository.ref)
        state = github.get(
            f"repos/{name}/actions/workflows/{PurePosixPath(CALLER_PATH).name}"
        )
        if state.get("state") != "active":
            raise ValueError(
                "Node dependency audit workflow is disabled; enable it in Actions"
            )
        result.update(status="ok", diagnostic="Static setup checks passed")
    except Unverified as error:
        result["diagnostic"] = str(error)
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        RecursionError,
        yaml.YAMLError,
    ) as error:
        result.update(status="failed", diagnostic=str(error)[:4000])
    return result


def check_fleet(github, source):
    CONFIGURATION["validate_source"]({**source, "ref": source["ref"] or "HEAD"})
    report = {
        "schema_version": 1,
        "inventory": {**source, "commit": None},
        "results": [],
        "status": "unverified",
        "diagnostic": "",
    }
    try:
        repository = github.snapshot(source["repository"], source["ref"])
        report["inventory"].update(ref=repository.ref, commit=repository.commit)
        settings = inventory(
            CONFIGURATION["json_object"](
                repository.read(source["path"]), "fleet inventory"
            )
        )
        with ThreadPoolExecutor(
            max_workers=min(MAX_CONCURRENT_REPOSITORIES, len(settings["repositories"]))
        ) as executor:
            report["results"] = list(
                executor.map(
                    lambda name: check_repository(github, name, settings["defaults"]),
                    settings["repositories"],
                )
            )
        report["status"] = (
            "ok"
            if all(item["status"] == "ok" for item in report["results"])
            else "failed"
        )
    except Unverified as error:
        report["diagnostic"] = str(error)
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as error:
        report.update(status="failed", diagnostic=str(error)[:4000])
    return report


def summary(report):
    def escape(value):
        return html.escape(str(value)).replace("|", "&#124;").replace("\n", " ")

    lines = [
        "## Node maintenance setup check",
        "",
        "| Repository | Static setup | Detail |",
        "| --- | --- | --- |",
    ]
    for item in report["results"]:
        lines.append(
            f"| {escape(item['repository'])} | {escape(item['status'])} | {escape(item['diagnostic'])} |"
        )
    if report["diagnostic"]:
        lines.extend(["", escape(report["diagnostic"])])
    lines.extend(
        [
            "",
            "Installed tool versions, credential contents, publication access, dependency health, and project builds were not tested.",
        ]
    )
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--inventory-repository", default=os.environ.get("GITHUB_REPOSITORY", "")
    )
    parser.add_argument("--inventory-path", default="defaults/node-repositories.json")
    parser.add_argument("--inventory-ref", default="")
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    source = {
        "repository": args.inventory_repository,
        "path": args.inventory_path,
        "ref": args.inventory_ref,
    }
    report = check_fleet(GitHub(os.environ.get("GH_TOKEN", "")), source)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    text = summary(report)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as output:
            output.write(text)
    print(text)
    if report["status"] != "ok":
        parser.exit(1, "Node maintenance setup needs attention; inspect the report.\n")


if __name__ == "__main__":
    main()
