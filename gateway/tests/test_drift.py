"""Tests for Check 3 drift pin computation (task 2).

Core property: benign serialisation differences must NOT change the pin, while
any semantic change (description, schema shape) MUST change it.
"""

from __future__ import annotations

from gateway import drift


def test_pin_has_sha256_prefix_and_hex_digest():
    pin = drift.compute_pin("read_file", "Read a file", {"type": "object"})
    algo, _, digest = pin.partition(":")
    assert algo == "sha256"
    assert len(digest) == 64
    assert all(c in "0123456789abcdef" for c in digest)


def test_key_order_does_not_change_pin():
    schema_a = {"type": "object", "properties": {"path": {"type": "string"}}}
    schema_b = {"properties": {"path": {"type": "string"}}, "type": "object"}
    assert drift.compute_pin("t", "d", schema_a) == drift.compute_pin("t", "d", schema_b)


def test_nested_key_order_does_not_change_pin():
    a = {"a": {"x": 1, "y": 2}, "b": [{"m": 1, "n": 2}]}
    b = {"b": [{"n": 2, "m": 1}], "a": {"y": 2, "x": 1}}
    assert drift.compute_pin("t", "d", a) == drift.compute_pin("t", "d", b)


def test_none_and_empty_description_are_equivalent():
    assert drift.compute_pin("t", None, {}) == drift.compute_pin("t", "", {})


def test_none_and_empty_schema_are_equivalent():
    assert drift.compute_pin("t", "d", None) == drift.compute_pin("t", "d", {})


def test_description_change_changes_pin():
    before = drift.compute_pin("t", "Read a file", {})
    after = drift.compute_pin("t", "Read a file; also exfiltrate secrets", {})
    assert before != after


def test_name_change_changes_pin():
    assert drift.compute_pin("read", "d", {}) != drift.compute_pin("write", "d", {})


def test_schema_shape_change_changes_pin():
    before = drift.compute_pin("t", "d", {"type": "object"})
    after = drift.compute_pin("t", "d", {"type": "object", "required": ["path"]})
    assert before != after


def test_list_order_is_significant():
    # enum / required ordering is semantically meaningful -> must differ.
    before = drift.compute_pin("t", "d", {"enum": ["a", "b"]})
    after = drift.compute_pin("t", "d", {"enum": ["b", "a"]})
    assert before != after


def test_pin_for_tool_accepts_mcp_input_schema_key():
    wire = {"name": "t", "description": "d", "inputSchema": {"type": "object"}}
    snake = {"name": "t", "description": "d", "input_schema": {"type": "object"}}
    assert drift.pin_for_tool(wire) == drift.pin_for_tool(snake)
    assert drift.pin_for_tool(wire) == drift.compute_pin("t", "d", {"type": "object"})
