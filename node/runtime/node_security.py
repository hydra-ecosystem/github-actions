"""Require the latest published security release in the installed Node major."""

import json
import re
import urllib.error
import urllib.request

RELEASE_INDEX = "https://nodejs.org/dist/index.json"
MAX_BYTES = 2_000_000


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def read_public(url, *, max_bytes=MAX_BYTES, timeout=15):
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "node-audit-security"},
    )
    try:
        with urllib.request.build_opener(NoRedirect()).open(
            request, timeout=timeout
        ) as response:
            data = response.read(max_bytes + 1)
    except (OSError, urllib.error.URLError) as error:
        raise ValueError(
            f"Cannot verify Node runtime security: {url}: {error}"
        ) from error
    if len(data) > max_bytes:
        raise ValueError("Node security evidence exceeds the security check size limit")
    return data


def read_release_index():
    return read_public(RELEASE_INDEX)


def version_tuple(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)", value
    ):
        raise ValueError("Node runtime security requires exact stable release versions")
    return tuple(map(int, value.removeprefix("v").split(".")))


def security_releases(major, *, read=None):
    data = (read_release_index if read is None else read)()
    try:
        releases = json.loads(data)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise ValueError(
            "Cannot verify Node runtime security: invalid release index"
        ) from error
    if not isinstance(releases, list) or not releases:
        raise ValueError(
            "Cannot verify Node runtime security: empty or invalid release index"
        )
    security_releases = []
    for release in releases:
        if not isinstance(release, dict):
            raise ValueError(
                "Cannot verify Node runtime security: invalid release record"
            )
        version = version_tuple(release.get("version"))
        if version[0] != int(major):
            continue
        if type(release.get("security")) is not bool:
            raise ValueError(
                "Cannot verify Node runtime security: invalid security flag"
            )
        if release["security"]:
            security_releases.append(version)
    if not security_releases:
        raise ValueError(
            f"Cannot verify Node runtime security: no security release for Node {major}"
        )
    return [".".join(map(str, version)) for version in sorted(set(security_releases))]


def latest_security_release(major, *, read=None):
    return security_releases(major, read=read)[-1]


def verify_node_security(installed, *, read=None):
    actual = version_tuple(installed)
    minimum_text = latest_security_release(actual[0], read=read)
    minimum = version_tuple(minimum_text)
    if actual < minimum:
        raise ValueError(
            f"Installed Node {installed} is older than the latest Node {actual[0]} "
            f"security release {minimum_text}. Update the Node declaration or runner "
            f"to at least {minimum_text}; security releases do not wait for the "
            f"package release cooldown. Source: {RELEASE_INDEX}"
        )
    print(
        f"Node runtime security passed: installed {installed}; "
        f"latest security release {minimum_text}; source {RELEASE_INDEX}"
    )
    return minimum_text
