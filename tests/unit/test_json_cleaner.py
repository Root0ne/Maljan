"""Unit tests for JSON cleanup utilities."""

from __future__ import annotations

from maljan.utils.json_cleaner import extract_json, repair_json, safe_parse_json


class TestExtractJson:
    """Tests for markdown and JSON extraction."""

    def test_extracts_from_json_code_block(self):
        text = 'Some text\n```json\n{"a": 1}\n```\nMore text'
        assert extract_json(text) == '{"a": 1}'

    def test_extracts_from_plain_code_block(self):
        text = '```\n{"b": 2}\n```'
        assert extract_json(text) == '{"b": 2}'

    def test_falls_back_to_first_json_object(self):
        text = 'Here is the result: {"c": 3} and more'
        assert extract_json(text) == '{"c": 3}'

    def test_falls_back_to_first_json_array(self):
        text = "Results: [1, 2, 3] end"
        assert extract_json(text) == "[1, 2, 3]"

    def test_returns_original_when_no_json(self):
        text = "No json here"
        assert extract_json(text) == "No json here"


class TestRepairJson:
    """Tests for JSON repair heuristics."""

    def test_removes_trailing_comma_before_brace(self):
        raw = '{"a": 1,}'
        assert repair_json(raw) == '{"a": 1}'

    def test_removes_trailing_comma_before_bracket(self):
        raw = "[1, 2, 3,]"
        assert repair_json(raw) == "[1, 2, 3]"

    def test_replaces_single_quotes(self):
        raw = "{'key': 'value'}"
        assert repair_json(raw) == '{"key": "value"}'

    def test_removes_single_line_comments(self):
        raw = '{\n  "a": 1, // comment\n  "b": 2\n}'
        repaired = repair_json(raw)
        assert "//" not in repaired
        assert '"a": 1' in repaired
        assert '"b": 2' in repaired

    def test_removes_multi_line_comments(self):
        raw = '{\n  /* comment */\n  "a": 1\n}'
        repaired = repair_json(raw)
        assert "/*" not in repaired
        assert '"a": 1' in repaired

    def test_escapes_inner_double_quotes(self):
        raw = "{'say': 'hello \"world\"'}"
        repaired = repair_json(raw)
        assert '\\"world\\"' in repaired


class TestSafeParseJson:
    """Tests for the full safe_parse_json pipeline."""

    def test_parses_clean_json(self):
        result = safe_parse_json('{"key": "value", "num": 42}')
        assert result == {"key": "value", "num": 42}

    def test_parses_markdown_wrapped_json(self):
        text = '```json\n{"wrapped": true}\n```'
        result = safe_parse_json(text)
        assert result == {"wrapped": True}

    def test_repairs_trailing_commas(self):
        text = '{"items": [1, 2, 3,],}'
        result = safe_parse_json(text)
        assert result == {"items": [1, 2, 3]}

    def test_repairs_single_quotes(self):
        text = "{'status': 'ok'}"
        result = safe_parse_json(text)
        assert result == {"status": "ok"}

    def test_returns_none_for_garbage(self):
        assert safe_parse_json("not json at all") is None

    def test_returns_none_for_incomplete_json(self):
        assert safe_parse_json('{"incomplete": ') is None

    def test_parses_nested_object(self):
        text = '{\n  "data": {\n    "count": 5,\n  },\n}'
        result = safe_parse_json(text)
        assert result == {"data": {"count": 5}}

    def test_parses_array_of_objects(self):
        text = '[{"a": 1,}, {"b": 2,},]'
        result = safe_parse_json(text)
        assert result == [{"a": 1}, {"b": 2}]

    def test_handles_realistic_llm_output(self):
        text = (
            "Here is the STIX bundle:\n\n"
            "```json\n"
            '{\n  "type": "bundle",\n  "id": "bundle--1",\n  "objects": [\n'
            '    {"type": "malware", "name": "evil.exe"},\n'
            "  ],\n}"
            "\n```"
        )
        result = safe_parse_json(text)
        assert result is not None
        assert result["type"] == "bundle"
        assert len(result["objects"]) == 1
