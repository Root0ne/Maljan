"""A credential no setting holds is masked by where it stands, whatever stands around it (T-481).

The structural rules (``maljan.core.settings_masking``) read a user name and
password after a path in the same word, and an address followed by more text in
that word. A path ends at a separator, an ``=`` or a closer, anything may follow
the host after a separator or a closer, and a backslash in a password before a
host with no port or path marks no path unless a path or an escaped quote stands
in it. Ordinary text (paths, mail addresses, URLs without userinfo, versions)
is kept as written.
"""

from __future__ import annotations

import json

import pytest
from tests.credential_shapes import lowercase_body

from maljan.core import settings_overrides as ov
from maljan.core.settings_catalog import configured_secret_values
from maljan.core.settings_masking import bare_addresses, masked_text


def _token() -> str:
    return "Kq" + lowercase_body(30)


# Each shape the rules kept before, with what is left once it is masked.
_SHAPES = [
    ("C:\\x=u:{pw}@h:8080", "C:\\x=***@h:8080"),
    ("C:\\x)u:{pw}@h:8080", "C:\\x)***@h:8080"),
    ("[C:\\x]u:{pw}@h:8080", "[C:\\x]***@h:8080"),
    ("C:\\x}u:{pw}@h/v1", "C:\\x}***@h/v1"),
    ("u:{pw}@h:8080,x", "***@h:8080,x"),
    ("u:{pw}@h,x", "***@h,x"),
    ("u:{pw}@h:8080)x", "***@h:8080)x"),
    ("u:{pw}@h:8080;D:\\y", "***@h:8080;D:\\y"),
    ("C:\\x,u:{pw}@h:8080,C:\\z", "C:\\x,***@h:8080,C:\\z"),
    ("C:\\x=u:{pw}@h:8080,C:\\z", "C:\\x=***@h:8080,C:\\z"),
    ('{"a":"C:\\\\x,\'{pw}@h:8080\'"}', '{"a":"C:\\\\x,\'***@h:8080\'"}'),
    ('{"a":"C:\\\\x,\'{pw}@h:8080\'","b":1}', '{"a":"C:\\\\x,\'***@h:8080\'","b":1}'),
    # The opener and its closer behind the backslashes JSON text, or JSON text
    # inside a JSON string, escapes them with.
    ('{"a":"C:\\\\x,\\\\\'{pw}@h:8080\\\\\'"}', '{"a":"C:\\\\x,\\\\\'***@h:8080\\\\\'"}'),
    ('{"a":"u:{pw}@h:8080\\\\\\"}"}', '{"***@h:8080\\\\\\"}"}'),
    # A backslash in a password before a host with no port or path.
    ("x;u:p\\{pw}@h", "***@h"),
    ("u:p\\{pw}@h", "***@h"),
    ("u:{pw}\\q@h.example", "***@h.example"),
]


@pytest.mark.parametrize(("written", "masked"), _SHAPES)
def test_a_credential_in_each_structural_shape_is_masked(written, masked):
    secret = _token()
    text = written.replace("{pw}", secret)

    assert masked_text(text, by_value=False) == masked
    assert masked_text(text) == masked
    assert (
        masked_text(f"Error: cannot connect to {text} now", by_value=False)
        == f"Error: cannot connect to {masked} now"
    )
    assert secret not in masked_text(json.dumps({"detail": text}), by_value=False)
    assert any(secret in address for address in bare_addresses(text))


# Words each part of the reading decides on its own, with what is left: ``>``
# and ``|`` ending a path's value, the list separators' own reading kept beside
# every value separator's, and any character but a letter or digit after a port.
_PINNED = [
    ("C:\\x>admin:{pw}:@[::1]]#f", "C:\\x>***@[::1]]#f"),
    ("PS C:\\>:/{pw}\\x@[::1]:;x'", "PS C:\\>***@[::1]:;x'"),
    (".\\,a/|:a{pw}@h/v1", ".\\,a/|***@h/v1"),
    ("..\\a;{pw}|@h:8080@x;x", "..\\a;***@x;x"),
    *(
        (f"u:{{pw}}@h.example:8080{after}", f"***@h.example:8080{after}")
        for after in ("|jq", "=x", "&x", "+x", "!", "*", "^", "~", "`", "\\x", "é")
    ),
]


@pytest.mark.parametrize(("written", "masked"), _PINNED)
def test_each_part_of_the_reading_masks_its_own_words(written, masked):
    secret = _token()
    text = written.replace("{pw}", secret)

    assert masked_text(text, by_value=False) == masked
    assert secret not in masked_text(f"Error: {text}", by_value=False)


@pytest.mark.parametrize(("written", "masked"), _SHAPES)
def test_the_event_scrub_registers_the_credential_of_each_shape(written, masked):
    secret = _token()
    text = written.replace("{pw}", secret)
    held = configured_secret_values(ov.build_settings({"llm.openai.base_url": text}))

    assert any(secret in found for found in held)


# Ordinary text around the same characters: no credential stands in it.
_ORDINARY = [
    "C:\\Users\\bob@corp",
    "C:\\Users\\bob@corp,x",
    "C:\\Users\\bob@corp.com;D:\\y",
    "C:\\dir(1)\\bob@h:8080",
    "C:\\dir(1)\\bob@h:8080,x",
    "C:\\x)bob@corp",
    "C:\\x]bob@corp",
    "C:\\x=bob@corp",
    "C:\\a=b\\bob@corp",
    "[C:\\x]\\bob@corp",
    "--out=C:\\dir\\bob@h:8080,x",
    "%ProgramFiles(x86)%\\dir\\bob@h:8080,x",
    "\\\\srv\\share\\bob@corp,x",
    "file:C:\\Users\\bob@corp",
    "path:\\\\srv\\share\\bob@corp",
    "log:.\\x\\bob@corp",
    '{"path":"C:\\\\Users\\\\bob@corp","n":1}',
    "CORP\\Administrator@dc01",
    "logs\\app@corp,x",
    "ops@example.com,",
    "ops@example.com,bob@example.com",
    "(ops@example.com),x",
    "x=ops@example.com,y",
    "user@host,x",
    "a@b.c.d,e",
    "mailto:ops@example.com,x",
    "From:alice@evil.com;x",
    '{"to":"\\"bob\\"@corp.com"}',
    '{"to":"\\"bob\\"@corp.com","cc":"x"}',
    '{"a":"{\\"to\\":\\"bob@corp.com\\"}"}',
    "pkg@1.2.3,x",
    "npx -y @scope/pkg@latest,x",
    "git@github.com:org/repo.git,x",
    "image@sha256:0123abcd,x",
    "https://h.example,x",
    "https://h.example/v1,x",
    "v1.2.3,v2.0",
    "release 2.4.1 (build 77) ok",
    # The characters a port may be followed by, after no port or in a path.
    "bob@corp.com|jq",
    "ops@example.com=x",
    "ops@example.com&x",
    "mailto:ops@example.com^",
    "pkg@1.2.3+build",
    "git@github.com:org/repo.git!",
    "image@sha256:0123abcd~",
    "a@b:12x",
    "C:\\Users\\bob@h:8080|x",
    "C:\\dir\\bob@h:8080=x",
    "%APPDATA%\\dir\\bob@h:8080&x",
]


# A word with no password whose token alone stands before a port is masked, as
# it is with nothing after the port (``sent@12:00``), whatever follows it.
@pytest.mark.parametrize("text", ["msg=sent@12:00,ok=true", "user@host:22!", "user@host:22|x"])
def test_a_token_alone_before_a_port_is_masked_whatever_follows(text):
    assert masked_text(text, by_value=False) == "***@" + text.rpartition("@")[2]


@pytest.mark.parametrize("text", _ORDINARY)
def test_ordinary_text_around_the_same_characters_is_kept(text):
    assert masked_text(text, by_value=False) == text
    assert masked_text(f"opened {text} now", by_value=False) == f"opened {text} now"


def test_masking_the_structural_shapes_costs_time_linear_in_the_text():
    from tests.linear_cost import assert_scales

    def masking(text: str) -> None:
        masked_text(text, by_value=False)
        bare_addresses(text)

    # One long word for each new reading: separators and closers after the
    # host, dots and colons the host may not end in, a backslash run before
    # no quote, UNC and environment-variable starts left open, and the value
    # separators between a path and a password.
    for build in (
        lambda size: "u:p@h" + ",;)" * size,
        lambda size: "u:p@h" + ".:" * size + "!",
        lambda size: "u:p@" + "a." * size + "!",
        lambda size: "u:p@h" + "\\" * size + "x",
        lambda size: "x:" + "\\\\a" * size + "@h",
        lambda size: "x:" + "%a" * size + "@h",
        lambda size: "C:\\x" + "=)]" * size + "u:p@h:8080",
        lambda size: "C:\\x" + ")D:\\y" * size + ",u:p@h:8080,z",
        lambda size: "u:" + "\\\\" * size + "@h",
        lambda size: "u:p@h:8080" + "|!" * size,
        lambda size: "u:p@" + "a:1" * size + "!",
    ):
        assert_scales(build, 2_000, masking)
