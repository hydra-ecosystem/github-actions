"""Resolve public GitHub defaults as bounded JSON data, without credentials."""

import json
import re
import runpy
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

SCHEDULING = runpy.run_path(str(Path(__file__).with_name("scheduling.py")))
LOCAL_PATCHES = runpy.run_path(str(Path(__file__).with_name("local_patches.py")))

MAX_BYTES = 65536
MAX_SOURCES = 8
SHARED_KEYS = {"toolchain", "maintenance", "minimumReleaseAgeDays", "schedule"}
LOCAL_KEYS = {"directory", "validationScript", "localPatches"}


def json_object(data, location, max_bytes=MAX_BYTES):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError(f"{location}: duplicate JSON key {key!r}")
            result[key] = value
        return result

    def constant(value):
        raise ValueError(f"{location}: non-finite JSON number {value}")

    if len(data) > max_bytes:
        raise ValueError(f"{location}: configuration exceeds {max_bytes} bytes")
    try:
        result = json.loads(data, object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise ValueError(f"{location}: invalid JSON: {error}") from error
    if not isinstance(result, dict):
        raise ValueError(f"{location}: configuration must be a JSON object")
    return result


def validate_source(source):
    if not isinstance(source, dict) or set(source) != {"repository", "path", "ref"}:
        raise ValueError("defaults must contain repository, path and ref")
    if any(
        not isinstance(value, str)
        or not value
        or len(value) > 2048
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
        for value in source.values()
    ):
        raise ValueError(
            "defaults repository, path and ref must be nonempty strings of at most 2048 characters"
        )
    repository, path, ref = (source[key] for key in ("repository", "path", "ref"))
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) or any(
        part in {".", ".."} for part in repository.split("/")
    ):
        raise ValueError("defaults.repository must be a GitHub owner/repository")
    if (
        path.startswith("/")
        or "\\" in path
        or any(part in {"", ".", ".."} for part in path.split("/"))
    ):
        raise ValueError("defaults.path must be a repository-relative file path")
    if any(part in {"", ".", ".."} for part in ref.split("/")):
        raise ValueError("defaults.ref must name a branch, tag or commit")
    return repository.lower(), path, ref


def validate_settings(config, location):
    if not isinstance(config, dict):
        raise ValueError(f"{location}: configuration must be an object")
    unknown = set(config) - SHARED_KEYS - LOCAL_KEYS - {"defaults"}
    if unknown:
        raise ValueError(f"{location}: unknown configuration fields: {sorted(unknown)}")
    if "localPatches" in config:
        LOCAL_PATCHES["validate_declarations"](config["localPatches"])
    if "schedule" in config:
        SCHEDULING["validate_schedule"](config["schedule"])
    if "defaults" in config:
        validate_source(config["defaults"])
    if "toolchain" in config:
        values = config["toolchain"]
        if not isinstance(values, dict) or not set(values) <= {"node", "npm", "pnpm"}:
            raise ValueError(f"{location}: toolchain accepts only node, npm and pnpm")
        for key, value in values.items():
            pattern = r"v?\d+(?:\.\d+\.\d+)?" if key == "node" else r"\d+\.\d+\.\d+"
            if value != "project" and (
                not isinstance(value, str) or not re.fullmatch(pattern, value)
            ):
                raise ValueError(f"{location}: invalid toolchain.{key}")
    if "minimumReleaseAgeDays" in config:
        days = config["minimumReleaseAgeDays"]
        if type(days) is not int or days < 0:
            raise ValueError(
                f"{location}: minimumReleaseAgeDays must be a nonnegative integer"
            )
    if "maintenance" in config:
        values = config["maintenance"]
        if not isinstance(values, dict) or not set(values) <= {"mode", "upgradeScope"}:
            raise ValueError(
                f"{location}: maintenance accepts only mode and upgradeScope"
            )
        if "mode" in values and values["mode"] not in (
            "security-only",
            "security-and-maintenance",
        ):
            raise ValueError(f"{location}: invalid maintenance.mode")
        if "upgradeScope" in values and values["upgradeScope"] not in (
            "patch",
            "minor",
            "major",
        ):
            raise ValueError(f"{location}: invalid maintenance.upgradeScope")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def public_read(url, accept="application/json"):
    # Never attach GITHUB_TOKEN: only public sources are supported. Redirects
    # fail rather than sending a request to a different origin or repository.
    request = urllib.request.Request(
        url, headers={"Accept": accept, "User-Agent": "node-audit-shared-defaults"}
    )
    try:
        with urllib.request.build_opener(NoRedirect()).open(
            request, timeout=15
        ) as response:
            data = response.read(MAX_BYTES + 1)
    except urllib.error.HTTPError as error:
        raise ValueError(
            f"Cannot read public defaults source {url}: HTTP {error.code}; "
            "check public access, repository, path and ref"
        ) from error
    except (OSError, urllib.error.URLError) as error:
        raise ValueError(
            f"Cannot read public defaults source {url}: {error}"
        ) from error
    if len(data) > MAX_BYTES:
        raise ValueError(f"{url}: defaults response exceeds {MAX_BYTES} bytes")
    return data


def merge_shared(inherited, explicit, *, inherit_schedule=True):
    result = dict(inherited)
    for key in SHARED_KEYS & explicit.keys():
        if key == "schedule" and not inherit_schedule:
            continue
        value = explicit[key]
        result[key] = (
            {**result.get(key, {}), **value}
            if key in {"toolchain", "maintenance", "schedule"}
            and isinstance(value, dict)
            and isinstance(result.get(key, {}), dict)
            else value
        )
    return result


def local_configuration(root):
    root = root.resolve()
    path = root / ".github/node-maintenance.json"
    if not path.resolve().is_relative_to(root):
        raise ValueError(
            ".github/node-maintenance.json resolves outside the repository"
        )
    with path.open("rb") as stream:
        config = json_object(
            stream.read(MAX_BYTES + 1), ".github/node-maintenance.json"
        )
    validate_settings(config, ".github/node-maintenance.json")
    return config


def load_configuration(root, sources=None, *, inherit_schedule=True, read=None):
    read = public_read if read is None else read
    local = local_configuration(root)
    sources = sources if sources is not None else []
    commits = {}

    def inherit(source, stack):
        repository, path, ref = validate_source(source)
        if len(stack) >= MAX_SOURCES:
            raise ValueError(f"defaults inheritance exceeds {MAX_SOURCES} sources")
        cache_key = (repository, ref)
        if cache_key not in commits:
            commit = ref.lower()
            if not re.fullmatch(r"[0-9a-f]{40}", commit):
                url = (
                    f"https://api.github.com/repos/{repository}/commits/"
                    + urllib.parse.quote(ref, safe="")
                )
                commit = read(url, "application/vnd.github.sha").decode().strip()
            if not re.fullmatch(r"[0-9a-f]{40}", commit):
                raise ValueError(
                    f"{repository}@{ref}: GitHub did not return a full commit"
                )
            commits[cache_key] = commit
        commit = commits[cache_key]
        identity = (repository, path, commit)
        if identity in stack:
            raise ValueError(
                f"defaults inheritance cycle at {repository}/{path}@{commit}"
            )
        url = (
            f"https://raw.githubusercontent.com/{repository}/{commit}/"
            + urllib.parse.quote(path, safe="/")
        )
        source_info = {
            "repository": repository,
            "path": path,
            "ref": ref,
            "commit": commit,
        }
        sources.append(source_info)
        config = json_object(read(url), f"{repository}/{path}@{commit}")
        validate_settings(config, f"{repository}/{path}@{commit}")
        inherited = (
            inherit(config["defaults"], (*stack, identity))
            if "defaults" in config
            else {}
        )
        return merge_shared(inherited, config, inherit_schedule=inherit_schedule)

    inherited = inherit(local["defaults"], ()) if "defaults" in local else {}
    result = merge_shared(inherited, local, inherit_schedule=inherit_schedule)
    result.update({key: value for key, value in local.items() if key in LOCAL_KEYS})
    if not inherit_schedule and "schedule" in local:
        result["schedule"] = local["schedule"]
    return result
