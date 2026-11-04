"""Lossless history storage and adversarial expansion boundaries."""

import base64
import copy
import runpy
from pathlib import Path

import pytest

CODEC = runpy.run_path(str(Path(__file__).parents[1] / "runtime/history.py"))


def framed(data, version=2):
    return (
        f"<!-- node-audit-history:v{version}:".encode()
        + base64.b64encode(CODEC["canonical"](data))
        + b" -->"
    )


def sample():
    advisory = {
        "title": "A repeated advisory title that belongs to each historical snapshot",
        "url": "https://github.com/advisories/GHSA-test-test-test",
        "paths": ["root>α@1>leaf@2", "root>α@1>leaf@3", "root>α@1>leaf@2", "", ">x>"],
    }
    return {
        "version": 1,
        "attempts": [
            {"before": copy.deepcopy(advisory), "after": copy.deepcopy(advisory)}
            for _ in range(3)
        ],
        "tokens": [{"r": 0}, {"p": -1}, {"s": True}],
    }


@pytest.mark.parametrize("version", [1, 2])
def test_exact_logical_history_and_independent_mutable_snapshots(version):
    record = sample()
    body = framed(record, 1) if version == 1 else CODEC["marker"](record).encode()
    restored = CODEC["read"](body)
    assert CODEC["canonical"](restored) == CODEC["canonical"](record)
    restored["attempts"][0]["before"]["paths"].reverse()
    assert restored["attempts"][0]["after"] == record["attempts"][0]["after"]
    assert restored["attempts"][1] == record["attempts"][1]
    assert CODEC["PATTERN"].sub("", body.decode()) == ""


def test_changed_historical_fields_stay_distinct_and_encoding_is_deterministic():
    record = sample()
    record["attempts"][1]["after"]["title"] += " changed"
    packed = CODEC["pack"](record)
    assert CODEC["unpack"](packed) == record
    reordered = dict(reversed(list(record.items())))
    assert CODEC["marker"](reordered) == CODEC["marker"](record)


def test_repeated_advisories_and_dependency_routes_have_order_of_magnitude_saving():
    advisory = {
        "title": "Repeated long security advisory title",
        "paths": [f"project@1>parent@2>branch{i}@3>leaf@4" for i in range(150)],
    }
    record = {
        "version": 1,
        "attempts": [{"before": advisory, "after": advisory} for _ in range(8)],
    }
    old = framed(record, 1)
    new = CODEC["marker"](record).encode()
    assert len(old) > 10 * len(new)
    assert CODEC["read"](new) == record


@pytest.mark.parametrize(
    "problem",
    [
        "envelope-key",
        "version",
        "bool-version",
        "table-type",
        "empty-objects",
        "object-type",
        "inline-list",
        "unknown-token",
        "multi-token",
        "bool-index",
        "float-index",
        "negative-index",
        "forward-object",
        "root-type",
        "root-bool",
        "path-type",
        "path-parent",
        "path-cycle",
        "path-segment",
        "string-type",
        "segment-type",
        "missing-string",
    ],
)
def test_rejects_invalid_tables_and_references(problem):
    data = CODEC["pack"]({"version": 1, "child": [1]})
    if problem == "envelope-key":
        data["extra"] = 0
    elif problem == "version":
        data["version"] = 3
    elif problem == "bool-version":
        data["version"] = True
    elif problem == "table-type":
        data["objects"] = {}
    elif problem == "empty-objects":
        data["objects"] = []
    elif problem == "object-type":
        data["objects"][0] = "bad"
    elif problem == "inline-list":
        data["objects"][0] = [[0]]
    elif problem == "unknown-token":
        data["objects"][0] = [{"x": 0}]
    elif problem == "multi-token":
        data["objects"][0] = [{"r": 0, "s": 0}]
    elif problem == "bool-index":
        data["objects"][0] = [{"r": False}]
    elif problem == "float-index":
        data["objects"][0] = [{"r": 0.0}]
    elif problem == "negative-index":
        data["objects"][0] = [{"r": -1}]
    elif problem == "forward-object":
        data["objects"][0] = [{"r": 1}]
    elif problem == "root-type":
        data["root"] = []
    elif problem == "root-bool":
        data["root"] = {"r": True}
    elif problem == "path-type":
        data["paths"] = [{}]
    elif problem == "path-parent":
        data["segments"], data["paths"] = ["x"], [[-2, 0]]
    elif problem == "path-cycle":
        data["segments"], data["paths"] = ["x"], [[0, 0]]
    elif problem == "path-segment":
        data["segments"], data["paths"] = ["x"], [[-1, True]]
    elif problem == "string-type":
        data["strings"] = [0]
    elif problem == "segment-type":
        data["segments"] = [None]
    elif problem == "missing-string":
        data["objects"][0] = [{"s": 0}]
    with pytest.raises(ValueError):
        CODEC["read"](framed(data))


@pytest.mark.parametrize(
    "problem", ["cycle", "amplification", "depth", "values", "path-size"]
)
def test_preflight_rejects_expansion_without_building_it(monkeypatch, problem):
    data = CODEC["pack"]({"version": 1})
    if problem in {"cycle", "amplification"}:
        data["objects"] = [[None]]
        for _ in range(25):
            data["objects"].append([{"r": len(data["objects"]) - 1}] * 2)
        data["root"] = {"r": len(data["objects"]) - 1}
        if problem == "cycle":
            data["objects"][0] = [{"r": 0}]
    elif problem == "path-size":
        data["segments"], data["paths"] = ["abcdef"], [[i - 1, 0] for i in range(20)]
        monkeypatch.setitem(CODEC["bounded"].__globals__, "MAX_LOGICAL", 100)
    else:
        value = {"version": 1, "child": [None] * 12}
        if problem == "depth":
            for _ in range(10):
                value["child"] = [value["child"]]
        data = CODEC["pack"](value)
        monkeypatch.setitem(
            CODEC["bounded"].__globals__,
            "MAX_DEPTH" if problem == "depth" else "MAX_VALUES",
            5,
        )
    with pytest.raises(ValueError):
        CODEC["read"](framed(data))


@pytest.mark.parametrize(
    "raw",
    [
        b'{"version":1,"version":1}',
        b'{"version": 1}',
        b'{"version":1,"n":NaN}',
        b'{"version":1,"n":1e9999}',
    ],
)
def test_rejects_duplicate_noncanonical_and_nonfinite_legacy_json(raw):
    with pytest.raises(ValueError):
        CODEC["read"](b"<!-- node-audit-history:v1:" + base64.b64encode(raw) + b" -->")


def test_stored_limits_ambiguous_markers_and_unknown_versions():
    body = CODEC["marker"](sample()).encode()
    for invalid in [
        body * 2,
        body + b"\n<!-- node-audit-history:v3:e30= -->",
        body.replace(b":v2:", b":v3:"),
        b"x" * 1048577,
    ]:
        with pytest.raises(ValueError):
            CODEC["read"](invalid)
    with pytest.raises(ValueError):
        CODEC["marker"](sample(), max_encoded=12)


def test_many_small_json_shapes_round_trip():
    for i in range(105):
        value = {
            "version": 1,
            "value": [
                None,
                True,
                False,
                i,
                i / 7,
                "雪",
                {"r": i},
                {"paths": [">" * i, "x>" * i]},
            ],
        }
        assert CODEC["read"](CODEC["marker"](value).encode()) == value


def test_exact_logical_byte_limit_counts_unicode_and_path_separators(monkeypatch):
    record = sample()
    data = CODEC["pack"](record)
    size = len(CODEC["canonical"](record))
    monkeypatch.setitem(CODEC["bounded"].__globals__, "MAX_LOGICAL", size)
    assert CODEC["read"](framed(data)) == record
    monkeypatch.setitem(CODEC["bounded"].__globals__, "MAX_LOGICAL", size - 1)
    with pytest.raises(ValueError):
        CODEC["read"](framed(data))


def test_writer_and_reader_share_exact_container_depth_limit(monkeypatch):
    record = {"version": 1, "value": [[[]]]}
    monkeypatch.setitem(CODEC["bounded"].__globals__, "MAX_DEPTH", 4)
    body = CODEC["marker"](record).encode()
    assert CODEC["read"](body) == record
    monkeypatch.setitem(CODEC["bounded"].__globals__, "MAX_DEPTH", 3)
    with pytest.raises(ValueError):
        CODEC["marker"](record)
    with pytest.raises(ValueError):
        CODEC["read"](body)


def test_repeated_large_strings_hit_byte_limit_before_value_limit():
    data = CODEC["pack"]({"version": 1})
    data["strings"] = ["x" * 100000]
    data["objects"][-1]["large"] = {"r": 0}
    data["objects"].insert(0, [{"s": 0}] * 90)
    data["root"] = {"r": 1}
    with pytest.raises(ValueError, match="logical expansion"):
        CODEC["read"](framed(data))


@pytest.mark.parametrize("value", [None, [], {}, {"version": True}, {"version": 2}])
def test_writer_rejects_unsupported_logical_record(value):
    with pytest.raises(ValueError, match="logical history"):
        CODEC["marker"](value)
