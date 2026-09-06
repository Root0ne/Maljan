"""What an admin may write into core.mcp.servers."""

from __future__ import annotations

import pytest
from app.services.server_map import ServerMapError, split_server_secrets, validate_server_map


def _entry(**over):
    base = {"enabled": True, "transport": "stdio", "command": "mcp", "agents": ["static"]}
    base.update(over)
    return base


def test_a_valid_map_comes_back_normalised():
    out = validate_server_map({"r2custom": _entry()})
    assert out["r2custom"]["command"] == "mcp"
    assert out["r2custom"]["tools"] is None


def test_a_key_that_is_not_a_slug_is_refused():
    with pytest.raises(ServerMapError) as exc:
        validate_server_map({"R2 Custom": _entry()})
    assert "R2 Custom" in exc.value.errors


def test_a_reserved_key_cannot_be_claimed_by_a_new_server():
    with pytest.raises(ServerMapError) as exc:
        validate_server_map({"ghidra": _entry()})
    assert "ghidra" in exc.value.errors
    assert "reserved" in exc.value.errors["ghidra"]


def test_a_built_in_may_be_disabled_but_not_deleted():
    out = validate_server_map({"network": _entry(enabled=False, agents=["network"])})
    assert out["network"]["enabled"] is False
    assert "threatintel" in out, "a built-in left out of the body is re-seeded, not removed"


def test_a_custom_key_left_out_of_the_body_is_removed():
    stored = {"gone": _entry(), "kept": _entry()}
    out = validate_server_map({"kept": _entry()}, stored=stored)
    assert "gone" not in out and "kept" in out


def test_an_unknown_agent_role_is_refused():
    with pytest.raises(ServerMapError) as exc:
        validate_server_map({"x": _entry(agents=["auditor"])})
    assert "x.agents" in exc.value.errors


def test_a_token_is_split_out_of_the_map_rather_than_stored_in_it():
    """The registry leaf is one plain JSON row; a token in it would be in clear."""
    cleaned, tokens = split_server_secrets(
        {"x": _entry(transport="http", url="https://h", command="", auth_token="s3cr3t")}
    )
    assert "auth_token" not in cleaned["x"]
    assert tokens == {"x": "s3cr3t"}


def test_the_mask_means_unchanged_and_never_becomes_the_token():
    from app.services.server_map import TOKEN_MASK

    cleaned, tokens = split_server_secrets(
        {"x": _entry(transport="http", url="https://h", command="", auth_token=TOKEN_MASK)}
    )
    assert "auth_token" not in cleaned["x"]
    assert tokens == {}, "a round-tripped mask leaves the stored row alone"


def test_an_empty_or_null_token_asks_for_the_row_to_be_deleted():
    _, empty = split_server_secrets({"x": _entry(auth_token="")})
    _, nulled = split_server_secrets({"x": _entry(auth_token=None)})
    assert empty == {"x": None} and nulled == {"x": None}


def test_an_entry_that_never_mentions_a_token_leaves_the_row_untouched():
    _, tokens = split_server_secrets({"x": _entry()})
    assert tokens == {}


def test_the_token_key_is_derived_from_the_server_name():
    from app.services.server_map import server_token_key

    assert server_token_key("r2custom") == "core.mcp.servers.r2custom.auth_token"


def test_merge_puts_the_rows_back_into_the_map_and_drops_the_synthetic_keys():
    from app.services.server_map import merge_server_secrets

    merged = merge_server_secrets(
        {
            "core.mcp.servers": {"x": {"command": "mcp"}},
            "core.mcp.servers.x.auth_token": "s3cr3t",
            "core.llm.provider": "openai",
        }
    )
    assert merged["core.mcp.servers"]["x"]["auth_token"] == "s3cr3t"
    assert "core.mcp.servers.x.auth_token" not in merged
    assert merged["core.llm.provider"] == "openai"


def test_merge_ignores_a_row_whose_server_is_gone():
    from app.services.server_map import merge_server_secrets

    merged = merge_server_secrets(
        {"core.mcp.servers": {}, "core.mcp.servers.gone.auth_token": "s3cr3t"}
    )
    assert merged["core.mcp.servers"] == {}
    assert "core.mcp.servers.gone.auth_token" not in merged


def test_a_stdio_server_without_a_command_is_refused():
    with pytest.raises(ServerMapError) as exc:
        validate_server_map({"x": _entry(command="")})
    assert "x.command" in exc.value.errors


def test_an_http_server_without_a_url_is_refused():
    with pytest.raises(ServerMapError) as exc:
        validate_server_map({"x": _entry(transport="http", command="", url="")})
    assert "x.url" in exc.value.errors
