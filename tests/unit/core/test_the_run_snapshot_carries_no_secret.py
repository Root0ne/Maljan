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
import random
import re
import string
import time

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


@pytest.mark.parametrize("opener", list("\"'([{<"))
@pytest.mark.parametrize("tail", ["llm.internal:8080", "llm.internal:8080/v1", "llm.internal/v1"])
def test_a_token_alone_holding_an_opener_leaves_nothing_of_itself(opener, tail):
    from maljan.core.settings_masking import masked_text
    from maljan.pipeline import events

    token = f"{_marker(506)}{opener}{_marker(507)}"
    value = f"{token}@{tail}"

    masked = masked_text(f"Error: cannot connect to {value}")

    assert masked == f"Error: cannot connect to ***@{tail}"
    held = _registered(value)
    assert token in held
    # A later event that repeats the token, in its address or alone, is masked too.
    events.remember_secret_values(held)
    later = events.scrub(f"retrying {value}; {token} refused")
    assert _marker(506) not in later and _marker(507) not in later


@pytest.mark.parametrize("opener", list("\"'([{<"))
@pytest.mark.parametrize("tail", ["h:8080", "h/v1"])
def test_a_token_alone_ending_in_an_opener_is_masked(opener, tail):
    from maljan.core.settings_masking import masked_text

    token = f"{_marker(508)}{opener}"

    assert masked_text(f"cannot connect to {token}@{tail}") == f"cannot connect to ***@{tail}"
    assert token in _registered(f"{token}@{tail}")


@pytest.mark.parametrize(
    "text",
    [
        'require("@scope/pkg")',
        "import('@scope/pkg/sub')",
        'print("ops@example.com")',
        "(see ops@example.com)",
        "[@decorator]",
        "f(@name)",
        "user@host",
        '"user@host"',
        "<ops@example.com>",
        'x("@h:8080")',
        '{"from":"\\"Evil\\"<x@evil.com>"}',
        '{"to":"\\"bob\\"@corp.com"}',
        '{"email":"a\\"b@corp.com"}',
        '{"k":"v","to":"\\"b\\"@c.com"}',
    ],
)
def test_ordinary_text_with_an_opener_and_an_at_is_kept(text):
    from maljan.core.settings_masking import masked_text

    assert masked_text(text) == text
    assert configured_secret_values_of(text) == set()


@pytest.mark.parametrize(
    ("text", "masked", "before"),
    [
        ('func("user@host:22")', 'func("***@host:22")', 'func("'),
        ('C2="admin@1.2.3.4:4444/gate.php"', 'C2="***@1.2.3.4:4444/gate.php"', 'C2="'),
        ('log: connect("bob@srv:3306")', 'log: connect("***@srv:3306")', 'connect("'),
        ('url="tok@h:8080"', 'url="***@h:8080"', 'url="'),
    ],
)
def test_a_quoted_token_alone_keeps_what_stands_before_its_quote(text, masked, before):
    from maljan.core.settings_masking import masked_text

    assert masked_text(text) == masked
    assert not any(before in value for value in configured_secret_values_of(text))


# A JSON-escaped quote or backslash before the "@" marks no path.
@pytest.mark.parametrize("password", ['p\\"{pw}', 'p\\\\\\"{pw}', 'user:p\\"{pw}'])
def test_a_password_escaped_in_json_text_is_masked(password):
    from maljan.core.settings_masking import masked_text

    secret = _marker(510)
    text = '{"password":"' + password.format(pw=secret) + '@h:8080"}'

    assert masked_text(text) == '{"***@h:8080"}'
    assert secret not in masked_text(f"Error: {text}")


@pytest.mark.parametrize("path", ["C:\\Users\\bob@corp", "C:\\\\Users\\\\bob@h:8080"])
def test_a_windows_path_is_kept(path):
    from maljan.core.settings_masking import masked_text

    assert masked_text(path) == path


# A backslash before a letter inside a password, as JSON text escapes one
# (``p\\\\ss``) or as written (``p\\ss``), a separator or an escaped quote
# before such a backslash, and JSON text inside a JSON string, each with what
# is left once it is masked.
_BACKSLASHED_PASSWORDS = [
    ('{"password":"p\\\\{pw}@h:8080"}', '{"***@h:8080"}'),
    ('{"password":"p\\\\ss{pw}@h:8080"}', '{"***@h:8080"}'),
    ("user:p\\\\{pw}@h:8080", "***@h:8080"),
    ('{"u":"user:{pw}\\nx@h:8080/v1"}', '{"***@h:8080/v1"}'),
    ('{"u":"user:{pw}\\\\nx@h:8080/v1"}', '{"***@h:8080/v1"}'),
    ("p\\{pw}@h:8080", "***@h:8080"),
    ("user:{pw}\\\\@h:8080", "***@h:8080"),
    ('{"a":"C:\\\\x","b":"p\\\\{pw}@h:8080"}', '{"***@h:8080"}'),
    ('{"password":"u:Xy;\\\\{pw}@h:8080"}', '{"***@h:8080"}'),
    ('{"password":"Xy,\\\\{pw}@h:8080"}', '{"***@h:8080"}'),
    ('{"password":"Xy=\\\\{pw}@h:8080"}', '{"***@h:8080"}'),
    ('{"password":"Xy|\\\\{pw}@h:8080"}', '{"***@h:8080"}'),
    ('{"password":"Xy<\\\\{pw}@h:8080"}', '{"***@h:8080"}'),
    ('{"password":"Xy(\\\\{pw}@h:8080"}', '{"***@h:8080"}'),
    ('{"password":"Xy\\"\\\\{pw}@h:8080"}', '{"***@h:8080"}'),
    ("u:Xy;\\\\{pw}@h:8080", "***@h:8080"),
    ("u:Xy,.\\{pw}@h:8080", "***@h:8080"),
    ('{"password":"u:a=.\\\\{pw}@h:8080"}', '{"***@h:8080"}'),
    ('{"password":"Xy\\"C:\\\\{pw}@h:8080"}', '{"***@h:8080"}'),
    ('"\\\\{pw}@h:8080"', '"***@h:8080"'),
    ('{"a":"{\\"password\\":\\"{pw}@h:8080\\"}"}', '{"***@h:8080\\"}"}'),
    ('{"a":"{\\"u\\":\\"user:{pw}@h:8080/v1\\"}"}', '{"***@h:8080/v1\\"}"}'),
    # A path that ends before an opener, and a drive written with a slash
    # anywhere but at the start or with no name after it, shield nothing.
    (".\\x('t\\{pw}@h:8080')", ".\\x('***@h:8080')"),
    ("Xy=c:/k\\{pw}@h:8080", "***@h:8080"),
    ("a:/\\{pw}@h:8080", "***@h:8080"),
]


def _credential_shaped_token() -> str:
    from tests.credential_shapes import lowercase_body

    return "Kq" + lowercase_body(30)


@pytest.mark.parametrize(("written", "masked"), _BACKSLASHED_PASSWORDS)
def test_a_backslash_before_a_letter_in_a_password_does_not_shield_it(written, masked):
    from maljan.core.settings_masking import masked_text

    secret = _credential_shaped_token()
    text = written.replace("{pw}", secret)

    assert masked_text(text) == masked
    # At the end of a line of text, the password still goes.
    assert masked_text(f"Error: cannot connect to {text}") == f"Error: cannot connect to {masked}"
    # The event scrub registers the token as it is written unescaped too.
    assert any(
        secret in found and "\\" not in found and '"' not in found
        for found in configured_secret_values_of(text)
    )


@pytest.mark.parametrize(
    "written",
    [
        "https://user:p\\\\{pw}@h:8080/v1",
        '{"a":"{\\"url\\":\\"https://user:{pw}@h:8080\\"}"}',
        '{"a":"{\\"url\\":\\"https://user:{pw}@h:8080/v1\\"}"}',
    ],
)
def test_a_backslashed_password_in_a_url_with_a_scheme_is_masked(written):
    from maljan.core.settings_masking import masked_text

    secret = _marker(512)
    text = written.replace("{pw}", secret)

    assert masked_text(text) == written.replace("p\\\\", "").replace("user:{pw}", "***")
    assert secret not in masked_text(text)


@pytest.mark.parametrize(
    "path",
    [
        "C:\\Users\\bob@h:8080",
        "C:\\\\Users\\\\bob@h:8080/x",
        "C:/Users/bob\\x@h:8080",
        "\\\\srv\\share\\bob@h:8080",
        "\\\\\\\\srv\\\\share\\\\bob@h:8080",
        '{"path":"C:\\\\Users\\\\bob@h:8080"}',
        '{"path":"C:\\\\Users\\\\bob@corp"}',
        '{"unc":"\\\\\\\\srv\\\\share\\\\bob@h/x"}',
        '{"p":"a=C:\\\\x@h:8080"}',
        ".\\\\dir\\\\bob@h:8080",
        "..\\dir\\bob@h:8080",
        "%APPDATA%\\dir\\bob@h:8080",
        "%ProgramFiles(x86)%\\dir\\bob@h:8080",
        "$env:APPDATA\\dir\\bob@h:8080",
        "--out=C:\\dir\\bob@h:8080",
        "C:\\Users\\bob@corp\\file.txt",
        '{"a":"{\\"to\\":\\"bob@corp.com\\"}"}',
        "\\\\?\\C:\\x@h/y",
        "\\\\?\\UNC\\srv\\x@h/y",
        "\\\\.\\pipe\\x@h/y",
        "path:'C:\\x@h/y'",
    ],
)
def test_a_windows_path_holding_an_at_is_kept_and_registers_nothing(path):
    from maljan.core.settings_masking import masked_text

    assert masked_text(path) == path
    assert masked_text(f"opened {path}") == f"opened {path}"
    assert configured_secret_values_of(path) == set()


@pytest.mark.parametrize(
    "account",
    ["CORP\\Administrator@dc01:389", "DOMAIN\\svc_sql_prod01@h:1433", "logs\\app@h/x"],
)
def test_a_backslashed_name_that_is_no_token_registers_nothing(account):
    from maljan.core.settings_masking import masked_text

    # Masked, as a token alone before a port or a path is; no part of it has
    # a token's shape, so the event scrub registers none of it.
    assert masked_text(account) == "***@" + account.rpartition("@")[2]
    assert configured_secret_values_of(account) == set()


# A path earlier in the same word, with no backslash before the password: the
# password goes from the separator after the path, and a drive's colon is no
# user name's. A path whose later name holds a colon is masked with it.
_PASSWORDS_AFTER_A_PATH = [
    ("'C:\\x','u:{pw}@h:8080'", "'C:\\x','***@h:8080'"),
    ("f(C:\\x,u:{pw}@h:8080)", "f(C:\\x,***@h:8080)"),
    ("C:\\x;u:{pw}@h:8080", "C:\\x;***@h:8080"),
    ("C:\\x,u:{pw}@h", "C:\\x,***@h"),
    ("C:\\x,D:\\y,u:{pw}@h:8080", "C:\\x,D:\\y,***@h:8080"),
    ("C:\\x,u:p,{pw}@h:8080", "C:\\x,***@h:8080"),
    ("C:\\a,b:{pw}@h:8080", "C:\\a,***@h:8080"),
    ("C:\\x,a:/{pw}@h:8080", "C:\\x,***@h:8080"),
    ("%ProgramFiles(x86)%\\x,u:{pw}@h:8080", "%ProgramFiles(x86)%\\x,***@h:8080"),
    ("\\\\srv\\share,u:{pw}@h/v1", "\\\\srv\\share,***@h/v1"),
    ("('C:\\x','{pw}@h:8080')", "('C:\\x','***@h:8080')"),
    # Inside a JSON object, whose member key holds a colon, and behind an
    # escaped quote.
    ('{"a":"C:\\\\x,u:{pw}@h:8080"}', '{"a":"C:\\\\x,***@h:8080"}'),
    ('{"a":"\\\\\\\\srv\\\\share,u:{pw}@h/v1"}', '{"a":"\\\\\\\\srv\\\\share,***@h/v1"}'),
    ('{"a":"C:\\\\x,\\\'{pw}@h:8080\\\'"}', '{"a":"C:\\\\x,\\\'***@h:8080\\\'"}'),
]


@pytest.mark.parametrize(("written", "masked"), _PASSWORDS_AFTER_A_PATH)
def test_a_path_before_a_password_in_the_same_word_does_not_shield_it(written, masked):
    from maljan.core.settings_masking import masked_text

    secret = _credential_shaped_token()
    text = written.replace("{pw}", secret)

    assert masked_text(text) == masked
    assert masked_text(f"Error: cannot connect to {text}") == f"Error: cannot connect to {masked}"
    assert any(secret in found for found in configured_secret_values_of(text))


# Words a reading after a path masks, each with what is left: a backslash in
# the password after the separator, colons and openers before it, and an
# escaped opener with a backslash run after the separator. Each reading only
# adds masking, so a later one never drops a row.
_WORDS_A_READING_AFTER_A_PATH_MASKS = [
    ("/a,u:{pw}\\s@h:8080", "/a,***@h:8080"),
    ('@443srv@SSL/,u:@1..\\@1{pw})@h:8080"', '@443srv@SSL/,***@h:8080"'),
    ("/\\\\\\\"@SSL$,/,a:/\\\\{pw}\\h@1@h:8080'", "/\\\\\\\"@SSL$,/,***@h:8080'"),
    ("/;u:,D:\\y@1\\\\\\\\\\{pw}u:%P(x86)%\\@h:5432)", "/;***@h:5432)"),
    ('/srv@SSL;$;a:/{pw}\\\\\\""@h:8080\')', "/srv@SSL;$;***@h:8080')"),
    ('/(",{"a":"{"a":"\\\\x,{pw}@h:8080', '/(",{"***@h:8080'),
    ("C:\\x,\\'\\\\{pw}@h:8080", "C:\\x,\\'***@h:8080"),
    ('{"a":"C:\\\\x,\\\'{pw}\\\\q@h:8080\\\'"}', '{"a":"C:\\\\x,\\\'***@h:8080\\\'"}'),
]


@pytest.mark.parametrize(("written", "masked"), _WORDS_A_READING_AFTER_A_PATH_MASKS)
def test_every_reading_after_a_path_masks_its_words(written, masked):
    from maljan.core.settings_masking import masked_text

    secret = _credential_shaped_token()
    text = written.replace("{pw}", secret)

    assert masked_text(text) == masked
    assert secret not in masked_text(f"Error: {text}")


@pytest.mark.parametrize(
    "path",
    [
        "\\\\srv@SSL\\DavWWWRoot\\x@h/y",
        "\\\\srv@ssl@443\\DavWWWRoot\\x@h:8080",
        "\\\\srv@8080\\share\\x@h/y",
        "\\\\srv$\\x@h/y",
        "\\\\\\\\srv@SSL\\\\DavWWWRoot\\\\x@h/y",
        '{"unc":"\\\\\\\\srv$\\\\x@h/y"}',
    ],
)
def test_a_webdav_or_hidden_unc_share_is_kept_and_registers_nothing(path):
    from maljan.core.settings_masking import masked_text

    assert masked_text(path) == path
    assert masked_text(f"opened {path}") == f"opened {path}"
    assert configured_secret_values_of(path) == set()


# A server name with any other "@" or "$", or with no backslash after it, is
# no share's: what stands before the last "@" stays userinfo.
@pytest.mark.parametrize(
    "written",
    [
        "\\\\{pw}@h:8080",
        "\\\\\\\\{pw}@h:8080",
        "\\\\{pw}@SSL@h:8080",
        "\\\\u@{pw}@h:8080",
        "\\\\{pw}$@h:8080",
        "\\\\s@x{pw}\\x@h:8080",
        "\\\\s$x{pw}\\x@h:8080",
    ],
)
def test_a_unc_shaped_password_is_still_masked(written):
    from maljan.core.settings_masking import masked_text

    secret = _credential_shaped_token()
    text = written.replace("{pw}", secret)

    assert masked_text(text) == "***@" + text.rpartition("@")[2]
    assert secret not in masked_text(f"Error: {text}")


# The accepted residual: a password written as a WebDAV or hidden share's
# server is kept, as one written as any share's server is (``\\pw\x@h``);
# without the backslash after it, it is still masked.
@pytest.mark.parametrize(
    ("written", "kept"),
    [
        ("\\\\{pw}@SSL\\x@h:8080", True),
        ("\\\\{pw}@1234\\x@h", True),
        ("\\\\{pw}$\\x@h/y", True),
        ("\\\\{pw}@SSL@h:8080", False),
        ("\\\\{pw}$@h:8080", False),
    ],
)
def test_a_password_written_as_a_webdav_or_hidden_share_is_the_named_residual(written, kept):
    from maljan.core.settings_masking import masked_text

    text = written.replace("{pw}", _credential_shaped_token())

    assert masked_text(text) == (text if kept else "***@" + text.rpartition("@")[2])


def test_masking_backslashed_words_costs_time_linear_in_the_text():
    from tests.linear_cost import assert_scales

    from maljan.core.settings_masking import bare_addresses, masked_text

    def masking(text: str) -> None:
        masked_text(text)
        bare_addresses(text)

    word = '{"password":"' + "p\\\\" * 200 + '@h:8080"} C:\\\\' + "d\\\\" * 200 + "b@h:8080"
    assert_scales(lambda size: " ".join([word] * size), 20, masking)
    # One long word for each way a path start is read: backslashes and a
    # quote, escaped quotes, a UNC share left open, an environment variable
    # left open, a path holding openers and a JSON string's escaped trailer.
    for build in (
        lambda size: '"' * size + "a\\\\" * size + "@h:8080",
        lambda size: "u:" + '\\\\\\"' * size + "\\x@h:8080",
        lambda size: "=\\\\" + "a" * size + "@h:8080",
        lambda size: "(%(" * size + "\\@h:8080",
        lambda size: "%P(" * size + "x%\\x@h:8080",
        lambda size: "u:p@h:8080" + '\\"}' * size,
        lambda size: "u:" + ",'.\\:" * size + "x@h:8080",
        lambda size: "C:\\" + "('" * size + "t\\@h:8080",
        # A path, then separators, drives and colons before the password, and
        # a WebDAV server name left open.
        lambda size: "C:\\x" + ",D:\\y" * size + ",u:p@h:8080",
        lambda size: "('" + "C:\\x'," * size + "'u:p@h:8080')",
        lambda size: "C:\\x" + ",;" * size + "u:p@h:8080",
        lambda size: "f(C:\\x" + ",a:/" * size + "@h:8080",
        lambda size: "=\\\\a@SSL" + "@1" * size + "\\x@h/y",
        lambda size: "\\\\a" + "@SSL$" * size + "\\x@h/y",
        # Escaped openers and backslash runs after the separator.
        lambda size: "C:\\x," + "\\" * size + "@h:8080",
        lambda size: "C:\\x," + "\\'" * size + "\\" * size + "@h:8080",
    ):
        assert_scales(build, 2_000, masking)


def configured_secret_values_of(text: str) -> set[str]:
    from maljan.core.settings_catalog import configured_secret_values

    return configured_secret_values(_with_fragment(text))


# --- The reference: where an address began, and what was registered, before a
# token alone could hold an opener (verbatim) ----------------------------------


def _bare_userinfo_before(token: str) -> tuple[str, str] | None:
    from maljan.core.settings_masking import bare_userinfo

    return None if "\\" in token.rpartition("@")[0] else bare_userinfo(token)


def _address_in_before(word: str) -> int | None:
    from maljan.core.settings_masking import TOKEN_OPENERS

    last_at = word.rfind("@")
    if last_at < 0:
        return None
    lead = len(word) - len(word.lstrip(TOKEN_OPENERS))
    start = max(word.rfind(opener, 0, last_at) for opener in TOKEN_OPENERS) + 1
    if start > lead and ":" in word[lead:start]:
        start = lead
    return start if _bare_userinfo_before(word[start:]) is not None else None


def _bare_secrets_before(address: str) -> list[str]:
    from maljan.core.settings_catalog import _reads_as_a_credential, _url_secrets

    parts = _bare_userinfo_before(address)
    if parts is None:
        return []
    head, tail = parts
    found: list[str] = []
    if ":" in head:
        found.extend(
            dict.fromkeys(p for p in (head.partition(":")[2], head.rpartition(":")[2]) if p)
        )
    elif _reads_as_a_credential(head):
        found.append(head)
    found.extend(_url_secrets("//host" + tail[len(tail.split("?", 1)[0]) :]))
    return found


# Characters, and the pieces a Windows path or a WebDAV share begins with.
_FUZZ_HEAD = [
    *(string.ascii_letters + string.digits + "\"'([{<:/=,.%-_@\\$;"),
    "@SSL",
    "\\\\srv",
    "C:\\",
]
_FUZZ_TAILS = [
    "h",
    "h:8080",
    "h/v1",
    "h:8080/v1",
    "[::1]:80",
    "example.com",
    "1.2.3",
    "h:5432)",
    'h:8080"',
    'h:8080")',
    'h/v1"]',
    'corp.com"}',
]


def _fuzzed_words(count: int) -> list[str]:
    draw = random.Random(371)
    words = []
    for _ in range(count):
        head = "".join(draw.choice(_FUZZ_HEAD) for _ in range(draw.randint(0, 12)))
        lead = "".join(draw.choice("\"'([{<") for _ in range(draw.randint(0, 2)))
        words.append(f"{lead}{head}@{draw.choice(_FUZZ_TAILS)}")
    return words


def test_masking_is_never_weaker_than_before_on_fuzzed_words():
    from maljan.core.settings_catalog import _bare_secrets
    from maljan.core.settings_masking import (
        _CLOSERS,
        TOKEN_OPENERS,
        _address_in,
        _left_unclosed,
        _opener_is_its_own,
        bare_userinfo,
    )

    def names_a_port_or_a_path(address: str) -> bool:
        tail = address.rpartition("@")[2]
        return bool(re.search(r"\A(?:\[[^\]]*\]|[^:/?#]*)(?::\d|[/?#])", tail))

    weaker = []
    for word in _fuzzed_words(20_000):
        before, now = _address_in_before(word), _address_in(word)
        if before is not None:
            # Masked at least from where it was, and registering what it did.
            if now is None or now > before:
                weaker.append(word)
            elif not set(_bare_secrets_before(word[before:])) <= set(_bare_secrets(word[now:])):
                weaker.append(word)
            elif now < before:
                # Read from further back only where the opener it was read
                # from is left unclosed after the "@".
                opener, last_at = word[before - 1], word.rfind("@")
                lead = len(word) - len(word.lstrip(TOKEN_OPENERS))
                assert _left_unclosed(word, opener, lead, last_at), word
                assert word.count(_CLOSERS[opener], last_at + 1) <= word.count(
                    opener, 0, lead
                ) or word.startswith("[", last_at + 1), word
                if "\\" in word[now:last_at]:
                    assert names_a_port_or_a_path(word[now:]), word
        elif now is not None:
            if "\\" in word[now:].rpartition("@")[0]:
                # A JSON escape is read only before a port or a path.
                assert names_a_port_or_a_path(word[now:]), word
                assert bare_userinfo(word[now:]) is not None, word
            elif "\\" in word[:now] and word[:now].rstrip(TOKEN_OPENERS + "\\")[-1:] in (",", ";"):
                # Or a user name and a password, or a quoted token alone,
                # after a separator that ends a backslashed value before them
                # in the same word.
                assert ":" in word[now:].rpartition("@")[0] or word[now - 1] in TOKEN_OPENERS, word
                assert bare_userinfo(word[now:]) is not None, word
            else:
                # Otherwise a new reading only where the token's own opener
                # stands right before the "@" of a token alone.
                head, _, tail = word.rpartition("@")
                assert head[-1] in TOKEN_OPENERS and ":" not in head, word
                assert _opener_is_its_own(head[-1], tail), word
    assert weaker == []


def test_a_token_alone_holding_openers_leaves_no_character_on_fuzzed_words():
    from maljan.core.settings_masking import masked_text

    draw = random.Random(3710)
    for _ in range(2_000):
        token = "".join(
            draw.choice(string.ascii_letters + string.digits + "\"'([{<") for _ in range(12)
        )
        token = f"{_marker(509)}{token}"
        tail = draw.choice(["h:8080", "h/v1", "h:8080/v1", "[::1]:80"])
        assert masked_text(f"x {token}@{tail} y") == f"x ***@{tail} y", token


def test_masking_a_ten_times_longer_text_costs_about_ten_times_as_much():
    from maljan.core.settings_masking import bare_addresses, masked_text

    def cost(text: str) -> float:
        best = float("inf")
        for _ in range(3):
            began = time.perf_counter()
            masked_text(text)
            bare_addresses(text)
            best = min(best, time.perf_counter() - began)
        return best

    word = '("' * 200 + "p'ss" * 200 + "@h:8080"
    one, ten = " ".join([word] * 20), " ".join([word] * 200)
    long_word = '"(' * 2_000 + "a@" * 2_000 + "h:8080"
    assert cost(ten) < 30 * cost(one)
    assert cost(long_word * 10) < 30 * cost(long_word)
