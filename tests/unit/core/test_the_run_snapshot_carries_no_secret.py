"""The run settings snapshot carries no secret (AUD-18).

``run_summary.settings_snapshot`` reaches everyone who may read the report,
and the disclosure record is built from the same snapshot. A value typed as a
secret was masked before; a tool server's ``env`` map, the credential inside a
configured URL (its userinfo, any query value, its fragment), a credential a
server's arguments carry after a flag that names one, and a form field that
names a credential were not. Every one of them is set here to a distinct
marker and none may survive, in the snapshot or in the efficiency
fingerprint's masked settings and server digests.
"""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from maljan.core import settings_overrides as ov
from maljan.core.config import MCPServerConfig, Settings
from maljan.core.settings_catalog import core_catalog, snapshot_hidden_paths

_PREFIX = "f10mark"


def _marker(index: int) -> str:
    return f"{_PREFIX}{index:03d}zq"


def _secret_catalogue_paths() -> list[str]:
    return [entry.path for entry in core_catalog() if entry.secret]


def _every_secret_set() -> tuple[Settings, list[str]]:
    """Settings with a marker in every place a credential can live, and the markers."""
    markers: list[str] = []

    def mark() -> str:
        markers.append(_marker(len(markers)))
        return markers[-1]

    overrides: dict[str, object] = {path: mark() for path in _secret_catalogue_paths()}
    url_paths = [
        e.path
        for e in core_catalog()
        if e.type == "str" and e.path.rsplit(".", 1)[-1] in ("url", "base_url")
    ]
    for path in url_paths:
        url = f"https://user:{_marker(999)}@svc.example/x?api_key={_marker(998)}"
        try:
            ov.build_settings({path: url})
        except ValidationError:
            continue  # the model refuses a credential in this address: none can reach a run
        overrides[path] = f"https://user:{mark()}@svc.example/x?api_key={mark()}"
    env_paths = [e.path for e in core_catalog() if e.path.rsplit(".", 1)[-1] == "env"]
    for path in env_paths:
        overrides[path] = {"UPSTREAM_API_TOKEN": mark(), "PLAIN_NAME": mark()}
    overrides["llm.agents"] = {
        "static": {
            "provider": "openai",
            "model": "m",
            "base_url": f"https://u:{mark()}@agent.example/v1",
        }
    }
    overrides["sandbox.cape2.submit_options"] = {"api_key": mark(), "route": "tor"}
    overrides["sandbox.rest.submit.extra_fields"] = {"secret": mark()}
    overrides["sandbox.rest.submit.submit_fields"] = {"auth_token": mark()}
    settings = ov.build_settings(overrides)
    settings.mcp.servers["probe_srv"] = MCPServerConfig(
        enabled=True,
        transport="http",
        url=f"https://{mark()}@tools.example/mcp?sig={mark()}&mode=fast#t={mark()}",
        auth_token=mark(),
        env={"LOG_LEVEL": mark(), "A_FIRST": mark()},
    )
    settings.mcp.servers["probe_stdio"] = MCPServerConfig(
        enabled=True,
        transport="stdio",
        command="tool",
        args=["--api-key", mark(), f"--token={mark()}", "--verbose", "--name", "plain"],
    )
    return settings, markers


def test_every_catalogue_secret_is_among_the_hidden_paths():
    settings, _ = _every_secret_set()
    secrets, servers = snapshot_hidden_paths(settings)
    assert set(_secret_catalogue_paths()) <= set(secrets)
    assert "mcp.servers.probe_srv.auth_token" in secrets
    assert {"static.ghidra", "static.r2", "sandbox.cape2.mcp", "mcp.servers.probe_srv"} <= set(
        servers
    )


@pytest.mark.parametrize("snapshot", ["public", "disclosure", "worker", "efficiency"])
def test_no_marker_survives_in_the_snapshot(snapshot):
    settings, markers = _every_secret_set()
    if snapshot == "public":
        snap = ov.public_snapshot(settings, _secret_catalogue_paths())
    elif snapshot == "disclosure":
        snap = ov.public_snapshot(settings, ())
    elif snapshot == "efficiency":
        from maljan.analysis.efficiency import masked_settings

        snap = masked_settings(settings)
    else:
        from app.worker.analysis_worker import settings_snapshot

        snap = settings_snapshot(settings)
    dumped = json.dumps(snap)
    assert len(markers) > len(_secret_catalogue_paths())
    leaked = [m for m in markers if m in dumped]
    assert leaked == []
    assert _PREFIX not in dumped


def test_an_env_map_keeps_its_names_sorted_and_masks_every_value():
    settings, _ = _every_secret_set()
    snap = ov.public_snapshot(settings, ())
    for path in ("static.ghidra.env", "static.r2.env", "sandbox.cape2.mcp.env"):
        held = [key for key in snap if key.startswith(f"{path}.")]
        assert held == [f"{path}.PLAIN_NAME", f"{path}.UPSTREAM_API_TOKEN"]
        assert {snap[key] for key in held} == {"***"}
    server = [key for key in snap if key.startswith("mcp.servers.probe_srv.env.")]
    assert server == ["mcp.servers.probe_srv.env.A_FIRST", "mcp.servers.probe_srv.env.LOG_LEVEL"]


def test_a_credential_an_argument_carries_is_masked_and_the_rest_kept():
    settings, _ = _every_secret_set()
    snap = ov.public_snapshot(settings, ())
    assert snap["mcp.servers.probe_stdio.args"] == [
        "--api-key",
        "***",
        "--token=***",
        "--verbose",
        "--name",
        "plain",
    ]


def test_an_address_keeps_its_host_and_loses_its_credential():
    settings, _ = _every_secret_set()
    snap = ov.public_snapshot(settings, ())
    # Every query value goes, whatever its key, and the fragment is masked.
    assert snap["mcp.servers.probe_srv.url"] == "https://***@tools.example/mcp?sig=***&mode=***#***"
    assert snap["llm.openai.base_url"] == "https://***@svc.example/x?api_key=***"
    assert snap["sandbox.cape2.submit_options.route"] == "tor"


def test_a_setting_without_a_secret_is_unchanged():
    settings = Settings(_env_file=None)
    snap = ov.public_snapshot(settings, ())
    plain = ov.flatten(settings.model_dump(mode="json"))
    assert snap["llm.provider"] == plain["llm.provider"]
    assert snap["sandbox.cape2.base_url"] == plain["sandbox.cape2.base_url"]


def test_an_old_stored_snapshot_still_reads():
    """A snapshot stored before the fix (env names, ten-asterisk tokens) is read as it is."""
    from pathlib import Path
    from types import SimpleNamespace

    from scripts.replay.stored import StoredRun

    from app.api.v1.jobs import _profile_the_job_ran

    old = {
        "mcp.servers.x.env.LOG_LEVEL": "***",
        "mcp.servers.x.auth_token": "**********",
        "agents.profile": "default",
    }
    summary = {"settings_snapshot": old}
    job = SimpleNamespace(config={}, report=SimpleNamespace(run_summary=summary))
    assert _profile_the_job_ran(job) == "default"
    assert StoredRun(name="old", root=Path("."), run_summary=summary).settings == old


def test_the_fingerprint_hashes_a_servers_masked_identity():
    """``declared_server`` hashes each field masked, so a token never feeds a digest."""
    from maljan.analysis.efficiency import declared_server

    def server(token: str, name: str = "plain") -> MCPServerConfig:
        return MCPServerConfig(
            transport="stdio",
            command="tool",
            args=["--api-key", token, "--name", name],
            url=f"https://u:{token}@h.example/?sig={token}#{token}",
        )

    one, two = declared_server(server(_marker(1))), declared_server(server(_marker(2)))
    assert one == two
    assert declared_server(server(_marker(1), name="other"))["identity"] != one["identity"]


def test_masking_replaces_each_hidden_part_and_removes_no_text():
    from maljan.core.settings_masking import masked_text

    assert masked_text("see https://h.example/x#sec-2 here") == "see https://h.example/x#*** here"
    assert masked_text("https://h.example/?a=&b=1&flag") == "https://h.example/?a=&b=***&flag"
    assert masked_text("https://h.example/?") == "https://h.example/?"
    assert masked_text("https://h.example/#") == "https://h.example/#"
    assert masked_text("1abc://h") == "1abc://h"


class _CountedText(str):
    """A string that counts the characters read from it one at a time."""

    reads = 0

    def __getitem__(self, index):  # type: ignore[override]
        _CountedText.reads += 1
        return str.__getitem__(self, index)


@pytest.mark.parametrize(
    "text",
    [
        "a" * 40_000 + " x://h",
        "a" * 40_000 + "://h",
        "a://" * 10_000,
        ("ab" * 50 + "://") * 400,
    ],
    ids=["letters-then-url", "one-long-scheme", "many-schemes", "repeated-runs"],
)
def test_finding_urls_reads_each_character_a_bounded_number_of_times(text):
    from maljan.core.settings_masking import url_spans

    _CountedText.reads = 0
    url_spans(_CountedText(text))
    assert _CountedText.reads <= 3 * len(text) + 3


def test_a_credential_that_begins_with_a_dash_is_masked():
    from maljan.core.settings_masking import masked_args

    assert masked_args(["--api-key", "-ZZDASH", "--name", "n"]) == [
        "--api-key",
        "***",
        "--name",
        "n",
    ]
    # Another long flag right after is a flag, not the value.
    assert masked_args(["--api-key", "--verbose"]) == ["--api-key", "--verbose"]


# An address written with no scheme, and what is left of it once its userinfo is masked.
_SCHEMELESS = [
    ("user:{pw}@llm.internal:8080/v1", "***@llm.internal:8080/v1"),
    ("user:{pw}@x@llm.internal:8080/v1", "***@llm.internal:8080/v1"),
    ("user:{pw}%40x@llm.internal:8080", "***@llm.internal:8080"),
    ("{pw}@llm.internal:8080", "***@llm.internal:8080"),
    ("user:{pw}@[::1]:8080/v1", "***@[::1]:8080/v1"),
]


@pytest.mark.parametrize(("written", "masked"), _SCHEMELESS)
def test_a_schemeless_address_loses_its_userinfo_in_the_snapshot(written, masked):
    secret = _marker(500)
    settings = ov.build_settings({"llm.openai.base_url": written.format(pw=secret)})

    snap = ov.public_snapshot(settings, ())

    assert snap["llm.openai.base_url"] == masked
    assert secret not in json.dumps(snap)


@pytest.mark.parametrize(("written", "masked"), _SCHEMELESS)
def test_every_url_masking_masks_a_schemeless_userinfo(written, masked):
    from maljan.core.settings_catalog import configured_secret_values
    from maljan.core.settings_masking import masked_text, masked_value

    secret = _marker(501)
    value = written.format(pw=secret)

    assert masked_text(f"cannot reach ({value}).") == f"cannot reach ({masked})."
    assert masked_value({"base_url": value}) == {"base_url": masked}
    assert secret not in ov.redact_url(f"driver said: {value}")
    if written.startswith("user:"):
        # A password is a secret the event scrub registers, as in a URL with a
        # scheme; a user name alone only where it has a token's shape.
        held = configured_secret_values(ov.build_settings({"llm.openai.base_url": value}))
        assert any(secret in found for found in held)


@pytest.mark.parametrize(
    "text",
    [
        "ops@example.com",
        "pkg@1.2.3",
        "npx -y @scope/server@latest",
        "git@github.com:org/repo.git",
        "image@sha256:0123abcd",
        "https://***@svc.example/x",
        "mailto:ops@example.com",
        "From:alice@evil.com",
        "C:\\Users\\bob@corp",
    ],
)
def test_a_value_that_is_no_schemeless_address_is_kept(text):
    from maljan.core.settings_masking import masked_text

    assert masked_text(text) == text


def test_an_address_inside_compact_json_is_masked():
    from maljan.core.settings_masking import masked_text

    secret = _marker(502)

    # The member's key is masked with it: a colon before the last quote may
    # be the password's own.
    assert masked_text(f'{{"u":"user:{secret}@llm.internal"}}') == '{"***@llm.internal"}'
    # A quoted value with no colon before its quote keeps what stands before it.
    assert masked_text(f'url="user:{secret}@llm.internal"') == 'url="***@llm.internal"'


def _registered(value: str) -> set[str]:
    from maljan.core.settings_catalog import configured_secret_values

    return configured_secret_values(_with_fragment(f"Error: cannot connect to {value}"))


@pytest.mark.parametrize("word", ["from", "to"])
@pytest.mark.parametrize("tail", ["h:5432", "h:8080/v1"])
def test_a_mailbox_word_before_a_password_and_a_port_is_no_mailbox(word, tail):
    from maljan.core.settings_masking import masked_text

    secret = _marker(503)
    for value in (f"{word}:user:{secret}@{tail}", f"{word}:{secret}@{tail}"):
        assert masked_text(value) == f"***@{tail}"
        assert secret in _registered(value)


@pytest.mark.parametrize("opener", list("\"'([{<"))
@pytest.mark.parametrize("tail", ["llm.internal", "llm.internal:8080/v1"])
def test_a_password_holding_an_opener_leaves_nothing_of_itself(opener, tail):
    from maljan.core.settings_masking import masked_text

    password = f"{_marker(504)}{opener}{_marker(505)}"
    value = f"user:{password}@{tail}"

    masked = masked_text(f"Error: cannot connect to {value}")

    assert masked == f"Error: cannot connect to ***@{tail}"
    assert _marker(504) not in masked and _marker(505) not in masked
    assert password in _registered(value)


def _with_fragment(fragment: str) -> Settings:
    return ov.build_settings(
        {
            "mcp.servers": {
                "notes": {"transport": "stdio", "command": "notes-mcp", "prompt_fragment": fragment}
            }
        }
    )


@pytest.mark.parametrize("fragment", ["Label: x@example.com", "Contact: ops@example.com"])
def test_a_mail_address_in_free_text_is_no_secret_and_is_kept(fragment):
    from maljan.core.settings_catalog import configured_secret_values

    settings = _with_fragment(fragment)

    assert configured_secret_values(settings) & {fragment, *fragment.split()} == set()
    assert ov.public_snapshot(settings, ())["mcp.servers.notes.prompt_fragment"] == fragment


def test_an_address_in_free_text_registers_only_its_password():
    from maljan.core.settings_catalog import configured_secret_values

    fragment = "Error: cannot connect to admin:s3cr3t@10.0.0.5"
    settings = _with_fragment(fragment)

    held = configured_secret_values(settings)

    assert "s3cr3t" in held
    assert not any("cannot" in value or "Error" in value for value in held)
    snap = ov.public_snapshot(settings, ())
    assert snap["mcp.servers.notes.prompt_fragment"] == "Error: cannot connect to ***@10.0.0.5"
