"""Self-contained lossless history sharing with bounded logical expansion."""

import base64
import json
import re
from collections import Counter

MAX_REPORT = 1048576
MAX_LOGICAL = 8 * MAX_REPORT
MAX_VALUES = 200000
MAX_DEPTH = 64
PATTERN = re.compile(r"^<!-- node-audit-history:v([12]):([A-Za-z0-9+/=]+) -->$", re.M)


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def bounded(size, values, depth):
    if size > MAX_LOGICAL or values > MAX_VALUES or depth > MAX_DEPTH:
        raise ValueError("Historical evidence exceeds its logical expansion bound")
    return size, values, depth


def pack(record):
    strings = Counter()
    visited = 0

    def count(value, paths=False, depth=0):
        nonlocal visited
        visited += 1
        bounded(0, visited, depth + int(isinstance(value, (dict, list))))
        if isinstance(value, dict):
            for key, child in value.items():
                if not isinstance(key, str):
                    raise ValueError("History keys must be strings")
                count(child, key == "paths", depth + 1)
        elif isinstance(value, list):
            for child in value:
                count(child, paths, depth + 1)
        elif isinstance(value, str) and not paths:
            strings[value] += 1

    count(record)
    bounded(len(canonical(record)), visited, 0)
    objects, paths, segments, shared = [], [], [], []
    object_ids, path_ids, segment_ids, string_ids = {}, {}, {}, {}

    def encode(value, in_paths=False):
        if isinstance(value, str) and in_paths:
            parent = -1
            for part in value.split(">"):
                if part not in segment_ids:
                    segment_ids[part] = len(segments)
                    segments.append(part)
                edge = (parent, segment_ids[part])
                if edge not in path_ids:
                    path_ids[edge] = len(paths)
                    paths.append(list(edge))
                parent = path_ids[edge]
            return {"p": parent}
        if (
            isinstance(value, str)
            and (strings[value] - 1) * len(canonical(value)) > 12 * strings[value] + 3
        ):
            if value not in string_ids:
                string_ids[value] = len(shared)
                shared.append(value)
            return {"s": string_ids[value]}
        if isinstance(value, dict):
            node = {k: encode(value[k], k == "paths") for k in sorted(value)}
        elif isinstance(value, list):
            node = [encode(v, in_paths) for v in value]
        else:
            return value
        key = canonical(node)
        if key not in object_ids:
            object_ids[key] = len(objects)
            objects.append(node)
        return {"r": object_ids[key]}

    root = encode(record)
    if sum(map(len, (objects, paths, segments, shared))) > MAX_VALUES:
        raise ValueError("History tables exceed their entry bound")
    return dict(
        version=2,
        root=root,
        objects=objects,
        paths=paths,
        segments=segments,
        strings=shared,
    )


def unpack(data):
    if (
        not isinstance(data, dict)
        or set(data) != {"version", "root", "objects", "paths", "segments", "strings"}
        or type(data["version"]) is not int
        or data["version"] != 2
    ):
        raise ValueError("Unsupported history storage envelope")
    objects, paths, segments, strings = (
        data[k] for k in ("objects", "paths", "segments", "strings")
    )
    if (
        any(not isinstance(v, list) for v in (objects, paths, segments, strings))
        or not objects
    ):
        raise ValueError("Invalid history tables")
    if sum(map(len, (objects, paths, segments, strings))) > MAX_VALUES:
        raise ValueError("History tables exceed their entry bound")
    if any(not isinstance(s, str) for s in segments + strings):
        raise ValueError("Invalid history string table")

    def index(value, limit):
        if type(value) is not int or not 0 <= value < limit:
            raise ValueError("Invalid or forward history reference")
        return value

    path_sizes = []
    for i, edge in enumerate(paths):
        if not isinstance(edge, list) or len(edge) != 2 or type(edge[0]) is not int:
            raise ValueError("Invalid history path")
        parent, segment = edge
        size = len(canonical(segments[index(segment, len(segments))])) - 2
        if parent != -1:
            size += path_sizes[index(parent, i)] + 1
        bounded(size + 2, 1, 0)
        path_sizes.append(size)
    string_sizes = [len(canonical(s)) for s in strings]
    sizes = []

    def stats(token, limit):
        if isinstance(token, dict):
            if len(token) != 1:
                raise ValueError("Invalid history token")
            kind, value = next(iter(token.items()))
            if kind == "r":
                return sizes[index(value, limit)]
            if kind == "p":
                return path_sizes[index(value, len(paths))] + 2, 1, 0
            if kind == "s":
                return string_sizes[index(value, len(strings))], 1, 0
            raise ValueError("Unknown history token")
        if isinstance(token, list):
            raise ValueError("Inline history container")
        return len(canonical(token)), 1, 0

    # Compute complete expansion costs before building any expanded container.
    for i, node in enumerate(objects):
        if not isinstance(node, (dict, list)):
            raise ValueError("Invalid history object")
        children = [
            stats(v, i) for v in (node.values() if isinstance(node, dict) else node)
        ]
        keys = sum(len(canonical(k)) + 1 for k in node) if isinstance(node, dict) else 0
        sizes.append(
            bounded(
                2 + max(0, len(node) - 1) + keys + sum(c[0] for c in children),
                1 + sum(c[1] for c in children),
                1 + max((c[2] for c in children), default=0),
            )
        )
    if data["root"] != {"r": len(objects) - 1}:
        raise ValueError("Invalid history root")
    stats(data["root"], len(objects))

    def expand(token):
        if not isinstance(token, dict):
            return token
        kind, value = next(iter(token.items()))
        if kind == "s":
            return strings[value]
        if kind == "p":
            parts = []
            while value != -1:
                value, segment = paths[value]
                parts.append(segments[segment])
            return ">".join(reversed(parts))
        node = objects[value]
        # Build each occurrence independently; mutable historical views cannot alias.
        return (
            {k: expand(v) for k, v in node.items()}
            if isinstance(node, dict)
            else [expand(v) for v in node]
        )

    return expand(data["root"])


def marker(record, max_encoded=MAX_REPORT):
    if (
        not isinstance(record, dict)
        or type(record.get("version")) is not int
        or record["version"] != 1
    ):
        raise ValueError("Unsupported logical history")
    raw = canonical(pack(record))
    encoded = base64.b64encode(raw).decode("ascii")
    if len(encoded) > max_encoded:
        raise ValueError("Historical evidence exceeds its stored bound")
    return f"<!-- node-audit-history:v2:{encoded} -->"


def read(report):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate history field")
            result[key] = value
        return result

    try:
        if len(report) > MAX_REPORT:
            raise ValueError("Audit report exceeds its bound")
        text = report.decode("utf-8")
        matches = PATTERN.findall(text)
        if len(matches) != 1 or text.count("node-audit-history:") != 1:
            raise ValueError("Missing or ambiguous sealed audit history")
        version, encoded = matches[0]
        raw = base64.b64decode(encoded, validate=True)
        stored = json.loads(raw, object_pairs_hook=unique)
        if canonical(stored) != raw:
            raise ValueError("Noncanonical history")
        record = unpack(stored) if version == "2" else stored
        if (
            not isinstance(record, dict)
            or type(record.get("version")) is not int
            or record["version"] != 1
        ):
            raise ValueError("Unsupported logical history")
        return record
    except (RecursionError, UnicodeError, TypeError, OverflowError) as error:
        raise ValueError("Malformed historical evidence") from error
