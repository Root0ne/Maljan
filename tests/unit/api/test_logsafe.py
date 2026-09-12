"""A request-derived value must not be able to forge a second log line."""

from __future__ import annotations

import uuid

from app.logsafe import TRUNCATION_MARKER, log_safe


def test_newlines_become_their_escaped_spelling() -> None:
    forged = "job-1\nWARNING:root:the queue is on fire"
    assert log_safe(forged) == "job-1\\nWARNING:root:the queue is on fire"
    assert "\n" not in log_safe(forged)


def test_carriage_returns_cannot_rewrite_the_line() -> None:
    assert log_safe("a\r\nb") == "a\\r\\nb"


def test_other_control_characters_get_the_hex_form() -> None:
    assert log_safe("a\x00b\x1bc\x7fd") == "a\\x00b\\x1bc\\x7fd"
    assert log_safe("tab\there") == "tab\\there"


def test_a_long_value_is_truncated_and_marked() -> None:
    out = log_safe("x" * 500)
    assert out == "x" * 256 + TRUNCATION_MARKER
    assert log_safe("y" * 20, limit=8) == "y" * 8 + TRUNCATION_MARKER


def test_a_value_at_the_limit_is_not_marked() -> None:
    assert log_safe("z" * 8, limit=8) == "z" * 8


def test_non_string_input_is_rendered_as_text() -> None:
    ident = uuid.UUID("11111111-2222-3333-4444-555555555555")
    assert log_safe(ident) == str(ident)
    assert log_safe(7) == "7"
    assert log_safe(None) == "None"
    assert log_safe(ValueError("bad\nvalue")) == "bad\\nvalue"


def test_clean_input_survives_untouched_and_a_second_pass_changes_nothing() -> None:
    clean = "550e8400-e29b-41d4-a716-446655440000"
    assert log_safe(clean) == clean
    assert log_safe(log_safe(clean)) == clean
    escaped = log_safe("a\nb")
    assert log_safe(escaped) == escaped
