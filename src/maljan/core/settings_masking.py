"""One masking of settings values for every reader that is not the store itself.

The run settings snapshot (``settings_overrides.public_snapshot``), the
efficiency fingerprint (``analysis.efficiency``), the console's settings read
and the JSON export all show settings to someone other than the store. Each of
them masks with these functions, so what one hides the others hide too:

* every URL in a string: its user name and password, every query value (the
  keys stay) and its fragment, each replaced by the mask, never removed; an
  address written with no scheme (``user:pw@host:8080/v1``) loses its
  userinfo too (:func:`bare_userinfo`);
* a tool server's command arguments: the value after a flag whose name marks
  a credential (``--api-key T``), the value of such a ``--flag=T``, and every
  URL in them;
* every mapping entry whose key names a credential
  (``settings_catalog.names_a_credential_value``: ``api_token``,
  ``Authorization``), at any depth;
* a tool server's ``env`` map: every value, whatever its name (the names stay,
  sorted).

``mask`` is the placeholder the reader uses: ``***`` in a run record, the
console's ``TOKEN_MASK`` where a value comes back on a save. ``unmasked``
reads a value sent back with masks in it against what is stored.
"""

from __future__ import annotations

import re
import string
from collections.abc import Mapping
from typing import Any

SNAPSHOT_MASK = "***"

# The characters of a URL scheme after its first letter (RFC 3986).
_SCHEME_CHARS = frozenset(string.ascii_letters + string.digits + "+.-")


def _credential_name(name: str) -> bool:
    from maljan.core.settings_catalog import names_a_credential_value

    return names_a_credential_value(name)


def url_spans(text: str) -> list[tuple[int, int]]:
    """``(start, end)`` of every URL in ``text``: a scheme, ``://``, and what follows up to
    whitespace.

    A scheme is the whole run of scheme characters before ``://``, starting with
    a letter. Each character is read a bounded number of times (the scan back
    over a scheme never passes the end of the previous ``://`` it looked at),
    so the time is linear in ``text`` whatever it holds.
    """
    spans: list[tuple[int, int]] = []
    floor = 0
    at = text.find("://")
    while at >= 0:
        start = at
        while start > floor and text[start - 1] in _SCHEME_CHARS:
            start -= 1
        end = at + 3
        if start < at and text[start] in string.ascii_letters:
            while end < len(text) and not text[end].isspace():
                end += 1
            if end > at + 3:
                spans.append((start, end))
        floor = end
        at = text.find("://", end)
    return spans


def _masked_query(query: str, mask: str) -> str:
    """Every value of a query masked; its keys, separators and empty values kept as written."""
    pieces = []
    for piece in query.split("&"):
        key, sep, value = piece.partition("=")
        pieces.append(f"{key}={mask}" if sep and value else piece)
    return "&".join(pieces)


def _masked_one_url(url: str, mask: str) -> str:
    """``url`` with its user name and password, every query value and its fragment masked.

    Each masked part is replaced by the mask, never removed, so a value edited
    around a mask still carries it and is refused rather than saved without
    the part it hid (``settings_service.unmasked_changes``).
    """
    scheme, _, rest = url.partition("://")
    cut = min((i for i in (rest.find(c) for c in "/?#") if i >= 0), default=len(rest))
    authority, tail = rest[:cut], rest[cut:]
    if "@" in authority:
        authority = f"{mask}@{authority.rsplit('@', 1)[1]}"
    body, hash_sign, fragment = tail.partition("#")
    path, question, query = body.partition("?")
    out = f"{scheme}://{authority}{path}"
    if question:
        out += "?" + _masked_query(query, mask)
    if hash_sign:
        out += "#" + (mask if fragment else "")
    return out


# What follows the last "@" of an address written with no scheme: a host or a
# bracketed IPv6 address, an optional port, then an optional path, query or
# fragment; punctuation that closes a sentence, a quote or a JSON object may
# trail a bare host, a quote also as JSON text inside a JSON string escapes it
# (``{"a":"{\"u\":\"user:pw@h:8080\"}"}``).
_BARE_AUTHORITY_TAIL = re.compile(
    r"(?:\[[0-9A-Fa-f:.%]+\]|[A-Za-z0-9][A-Za-z0-9.-]*)(?P<port>:\d{1,5})?"
    r"(?:(?P<path>[/?#]\S*)|(?:\\(?=[\"'])|[)\]}>\"'.,;:])*)"
)
# What may open a token before an address's first character: a quote, a
# bracket, or a JSON object's brace (``{"u":"user:pw@host"}``).
TOKEN_OPENERS = "\"'(<[{"
# The characters no Windows path holds: what stands before the last of them is
# not the path an address may end in (``{"a":"C:\\x","b":"p\\ss@h:8080"}``).
_NO_PATH_CHARS = '"<>|'
# Where a Windows path begins, as written or as JSON text escapes it: a drive
# (``C:\``), a UNC share with its server's host name (``\\srv\``), a long-path
# or device prefix (``\\?\``, ``\\.\``), a relative path (``.\``, ``..\``), an
# environment variable (``%ProgramFiles(x86)%\``, ``$env:APPDATA\``), at the
# start of what may be a path or after a character that opens a value
# (``--out=C:\``, ``('C:\``); a drive written with a slash and a name after it
# (``C:/Users``) only at the start. The server's name may end as a WebDAV
# share's does, in ``@SSL``, a port or both (``\\srv@SSL@443\``), or in the
# ``$`` of a hidden name (``\\srv$\``); no other ``@`` or ``$`` stands in it,
# so ``\\pw@h:8080`` stays userinfo. A known residual: a password written as
# such a share is (``\\pw@SSL\x@h:8080``, ``\\pw@1234\x@h``, ``\\pw$\x@h/y``)
# is kept, as ``\\pw\x@h:8080`` is. Possessive, so each start costs time
# linear in what it reads.
_PATH_START = re.compile(
    r"\A[A-Za-z]:/(?=[\w.~$-])"
    r"|(?:\A|(?<=['(\[{=,;]))"
    r"(?:[A-Za-z]:\\|\\\\(?:\\\\)?[?.](?:\\\\)?\\"
    r"|\\\\(?:\\\\)?[\w.-]++(?:@[Ss][Ss][Ll])?+(?:@\d{1,5}+)?+\$?+\\|\.{1,2}\\"
    r"|%[A-Za-z_][A-Za-z0-9_() ]*+%\\|\$env:[A-Za-z_]\w*+\\)"
)
# A drive's colon at the start of a path (``C:\``, after an opener or a
# separator too; ``C:/`` only at the start, as in :data:`_PATH_START`), or any
# other colon.
_DRIVE_OR_COLON = re.compile(r"\A[A-Za-z]:[\\/]|(?<=[\"'(<\[{=,;])[A-Za-z]:\\|:")
# What ends a path's value before an address after it in the same word.
_VALUE_SEPARATORS = ",;"
# What may open the value a path stands in (``{"a":"C:\x``, ``--out=C:\x``).
_PATH_VALUE_OPENERS = "\"'([{=,;"
# Openers, each behind any run of backslashes that escapes it, that open a
# value after a separator (``,'tok``, ``,\'tok``). Possessive, so linear.
_ESCAPED_OPENERS = re.compile(r"(?:\\*+[\"'(<\[{])*+")
# A backslash with the character it escapes, or a quote it leaves unescaped.
_ESCAPE_OR_QUOTE = re.compile(r"\\.|[\"']", re.DOTALL)
# What may stand right before a single quote that opens a value.
_VALUE_OPENERS = ":=,;([{"
# The words before a colon that open a mailbox rather than a user name: the
# schemes whose address is one (``mailto:ops@example.com``) and the mail
# headers that name one (``From:alice@example.com``), any case.
_MAILBOX_WORDS = frozenset(
    {"mailto", "xmpp", "sip", "sips", "im", "pres", "acct", "from", "to", "cc", "bcc", "sender"}
)


def _reads_as_a_windows_path(head: str) -> bool:
    """Whether ``head``, what stands before an address's last ``@``, ends in a Windows path.

    It does where what follows its last character no path holds begins as a
    path does (:data:`_PATH_START`): at the start of ``head`` or of a quoted
    value (``path:'C:\\x``), or after a character that opens a value where
    no ``:`` stands between the quoted value's start and the path
    (``--out=C:\\``, but not ``user:pw;\\\\x``, whose colon marks userinfo).
    A double quote opens a value unescaped, a single quote also only after
    the start or a character that opens a value (:data:`_VALUE_OPENERS`). A
    path never follows a JSON-escaped quote (``p\\"C:\\\\k``). A backslash
    elsewhere, such as JSON's escape of a backslash before a letter in a
    password (``p\\\\ss``), marks no path.

    A rooted path (``\\Windows\\x``) and one behind a colon (``file:C:\\x``)
    read as userinfo and are masked: a password may begin that way, and
    masking a path costs less than keeping a password. A password that
    itself reads as a path after a separator with no colon before it stays
    kept: two escaped backslashes and a name (``Xy,\\\\\\\\9k\\\\z@h:8080``,
    a UNC share as JSON text writes it) or a relative path
    (``Xy,.\\k@h:8080``). Linear in ``head``.
    """
    cut = max(head.rfind(c) for c in _NO_PATH_CHARS)
    tail = head[cut + 1 :]
    if "\\" not in tail:
        return False
    opens = _value_starts(head)
    colons = [found.start() for found in re.finditer(":", head)]
    value, last_colon, next_open, next_colon = 0, -1, 0, 0
    for found in _PATH_START.finditer(tail):
        at = cut + 1 + found.start()
        while next_open < len(opens) and opens[next_open] <= at:
            value = opens[next_open]
            next_open += 1
        while next_colon < len(colons) and colons[next_colon] < at:
            last_colon = colons[next_colon]
            next_colon += 1
        if at == 0 or (value == at and value > 0):
            return True
        if at == cut + 1 and head[cut] == '"':
            continue  # a JSON-escaped quote
        if last_colon < value:
            return True
    return False


def _user_colon(text: str) -> int:
    """Where the first ``:`` in ``text`` that is no drive's (``C:\\``, ``C:/``) stands, or -1.

    Read only in a word already refused as a path, so a drive's colon there
    opens the path rather than a password. Linear in ``text``.
    """
    for found in _DRIVE_OR_COLON.finditer(text):
        if found.group() == ":":
            return found.start()
    return -1


def _after_a_path(word: str, start: int, last_at: int) -> int | None:
    """Where an address after a path in the same word begins, or ``None`` for none.

    A path ends at a separator (:data:`_VALUE_SEPARATORS`), so a user name
    and password after it (``C:\\x,u:pw@h:8080``, ``'C:\\x','u:pw@h:8080'``)
    are read from the last separator before the first colon that is no
    drive's (:func:`_user_colon`), and a token alone from the last separator
    before the ``@`` where an opener follows it (``('C:\\x','tok@h:8080')``);
    the path before it is kept. What follows the separator goes even where
    it could be a later name of the path (``C:\\a,b:c@h:8080`` keeps only
    ``C:\\a,``): no Windows name holds a colon, and where a path and a
    password read alike, the password goes. The colons are read from the
    value the path stands in, so a JSON member's key before it names no user
    (``{"a":"C:\\\\x,u:pw@h:8080"}``), and the opener after a separator may be
    escaped (``{"a":"C:\\\\x,\\'tok@h:8080\\'"}``). Each reading only adds
    masking, so the earliest of them is taken: from the value the path stands
    in and from ``start``, each with an opener escaped or as written. Linear
    in the word.
    """
    starts = [start]
    backslash = word.find("\\", start, last_at)
    if backslash >= 0:
        opened = max(word.rfind(c, start, backslash) for c in _PATH_VALUE_OPENERS)
        if opened >= start:
            starts.append(opened + 1)
    found = [
        begin
        for value in starts
        for escaped in (True, False)
        if (begin := _after_a_path_from(word, value, last_at, escaped)) is not None
    ]
    return min(found, default=None)


def _after_a_path_from(word: str, start: int, last_at: int, escaped: bool) -> int | None:
    """One reading of :func:`_after_a_path`: its colons read from ``start``.

    With ``escaped``, the opener after the separator may stand behind
    backslashes (:data:`_ESCAPED_OPENERS`); otherwise only openers as written
    are passed over. Linear in the word.
    """
    colon = _user_colon(word[start:last_at])
    end = start + colon if colon >= 0 else last_at
    cut = max(word.rfind(sep, start, end) for sep in _VALUE_SEPARATORS)
    if cut < start:
        return None
    if escaped:
        opening = _ESCAPED_OPENERS.match(word, cut + 1, last_at)
        begin = cut + 1 if opening is None else opening.end()
    else:
        rest = word[cut + 1 : last_at]
        begin = cut + 1 + len(rest) - len(rest.lstrip(TOKEN_OPENERS))
    if colon < 0 and begin == cut + 1:
        return None
    return begin if bare_userinfo(word[begin:]) is not None else None


def _value_starts(head: str) -> list[int]:
    """Where each value an unescaped quote opens in ``head`` begins, in order.

    A quote behind an odd run of backslashes is JSON's escape of one inside
    the value; a single quote opens one only at the start or after a
    character that opens a value. Linear in ``head``.
    """
    starts = []
    for found in _ESCAPE_OR_QUOTE.finditer(head):
        quote = found.start()
        if found.group() == '"' or (
            found.group() == "'" and (quote == 0 or head[quote - 1] in _VALUE_OPENERS)
        ):
            starts.append(quote + 1)
    return starts


def bare_userinfo(token: str) -> tuple[str, str] | None:
    """``(userinfo, rest)`` of an address written with no scheme, or ``None``.

    ``user:pw@llm.internal:8080/v1`` is the address ``http://user:pw@...``
    without its scheme, so everything before its last ``@`` is userinfo: a
    password may itself hold ``@`` or an encoded ``%40``. Read as userinfo
    where it holds a ``:`` before any ``/`` (a user name and a password), or
    where the address after it names a port or a path (a token alone). A mail
    address (``ops@example.com``), a package pin (``pkg@1.2.3``,
    ``@scope/pkg@latest``), a Git remote (``git@host:org/repo``), a mailbox
    after its scheme or header (``mailto:ops@example.com``,
    ``From:alice@example.com``) and a Windows path (``C:\\Users\\bob@corp``)
    are none. Where the address names a port or a path, a backslash marks a
    path only where the userinfo ends in one (:func:`_reads_as_a_windows_path`),
    so a password JSON text escapes (``{"password":"p\\"ss@h:8080"}``,
    ``{"password":"p\\\\ss@h:8080"}``) is masked and ``C:\\Users\\bob@h:8080``
    is kept; before a mail address's host (``{"to":"\\"bob\\"@corp.com"}``)
    any backslash refuses it. A known residual: a one-letter user name whose
    password begins with ``/`` and holds a backslash (``u:/p\\x@h``, with or
    without a port) is written as a drive and a path are (``C:/Users\\x``)
    and is kept; so is any password holding a backslash before a host with no
    port or path (``u:p\\x@h``), which reads as such a mail address does.
    """
    head, at, tail = token.rpartition("@")
    if not at or not head or not tail:
        return None
    found = _BARE_AUTHORITY_TAIL.fullmatch(tail)
    if found is None:
        return None
    if "\\" in head and (
        _reads_as_a_windows_path(head) or not (found.group("port") or found.group("path"))
    ):
        return None
    slash = head.find("/")
    colon = head.find(":")
    word = head[:colon] if colon >= 0 else ""
    # A mailbox after its scheme or header holds one name after the colon and
    # names no port or path; a second colon or a port is a user name and a
    # password behind a word that only looks like one (``to:pw@h:8080``).
    mailbox = (
        word.isascii()
        and word.isalpha()
        and word.lower() in _MAILBOX_WORDS
        and not head.startswith("//", colon + 1)
        and ":" not in head[colon + 1 :]
        and not found.group("port")
        and not found.group("path")
    )
    if 0 <= colon and (slash < 0 or colon < slash) and not mailbox:
        return head, tail
    if slash < 0 and not mailbox and (found.group("port") or found.group("path")):
        return head, tail
    return None


# The character that closes each opener.
_CLOSERS = dict(zip(TOKEN_OPENERS, "\"')>]}", strict=True))


def _left_unclosed(word: str, opener: str, lead: int, last_at: int) -> bool:
    """Whether what follows ``word``'s last ``@`` leaves an inner ``opener`` unclosed.

    The closers after the ``@`` go first to the word's ``lead`` leading
    openers; one left over closes the inner opener, which then quotes the
    address. A bracketed IPv6 host closes its own bracket.
    """
    after = last_at + 1
    if word.startswith("[", after):
        after = word.find("]", after) + 1 or len(word)
    return word.count(_CLOSERS[opener], after) <= word.count(opener, 0, lead)


def _opener_is_its_own(opener: str, tail: str) -> bool:
    """Whether an opener right before an address's last ``@`` is the token's own.

    It is where the address after it names a port, or where nothing after the
    ``@`` closes it: ``require("@scope/pkg")`` quotes a package name.
    """
    found = _BARE_AUTHORITY_TAIL.fullmatch(tail)
    return found is not None and (found.group("port") is not None or _CLOSERS[opener] not in tail)


def _path_start_holds(word: str, lead: int, start: int, last_at: int) -> bool:
    """Whether a path start (:data:`_PATH_START`) holds the opener right before ``start``.

    Only such a path is read from the word's ``lead`` leading openers rather
    than from that opener; a path that ends before it shields nothing after
    it (``.\\x('tok\\q@h:8080')``). Linear in the word.
    """
    head = word[lead:last_at]
    for found in _PATH_START.finditer(head):
        if found.start() >= start - lead:
            break
        if start - lead <= found.end():
            return _reads_as_a_windows_path(head)
    return False


def _address_in(word: str) -> int | None:
    """Where the address written with no scheme in ``word`` begins, or ``None`` for none.

    It begins after the last opener (:data:`TOKEN_OPENERS`) before the word's
    last ``@``, so a quoted value reads as the address it holds, where what
    stands between the word's leading openers and that opener holds no ``:``.
    Where it does, the opener may be a password's own character
    (``user:p"ss@host``), so the address begins after the leading openers and
    nothing of the password is left; a compact JSON member's key is then
    masked with it (``{"***@host"}``). A token alone (no ``:`` before the
    ``@``) may hold an opener the same way (``p"ss@h:8080``), so where the
    word from its leading openers reads as such an address and nothing after
    the ``@`` closes that opener beyond what closes the leading openers, it
    begins there too; where nothing stands between the opener and the ``@``,
    only where the opener is the token's own as well
    (:func:`_opener_is_its_own`). A closed opener is read as quoting the
    address (``func("user@host:22")``, ``url="tok@h:8080"``), so a token whose
    own opener is followed by its closer after the ``@`` (``p"ss@h:8080",``)
    keeps what stands before that opener. Where a path refuses the reading,
    an address after a separator that ends the path is still read
    (:func:`_after_a_path`).
    """
    last_at = word.rfind("@")
    if last_at < 0:
        return None
    lead = len(word) - len(word.lstrip(TOKEN_OPENERS))
    start = max(word.rfind(opener, 0, last_at) for opener in TOKEN_OPENERS) + 1
    if start > lead and ":" in word[lead:start]:
        start = lead
    elif start > lead and ":" not in word[lead:last_at]:
        whole = bare_userinfo(word[lead:])
        opener = word[start - 1]
        if (
            whole is not None
            and _left_unclosed(word, opener, lead, last_at)
            and (start < last_at or _opener_is_its_own(opener, whole[1]))
        ):
            start = lead
    if (
        start > lead
        and "\\" in word[start:last_at]
        and _path_start_holds(word, lead, start, last_at)
    ):
        # A path whose start holds an opener (``%ProgramFiles(x86)%\x@h:8080``),
        # and what may follow it (``%ProgramFiles(x86)%\x,u:pw@h:8080``).
        return _after_a_path(word, lead, last_at)
    if bare_userinfo(word[start:]) is not None:
        return start
    return _after_a_path(word, start, last_at) if "\\" in word[start:last_at] else None


def bare_addresses(text: str) -> list[str]:
    """Every address written with no scheme in ``text``, each as written.

    Read word by word, as :func:`masked_bare_userinfo` reads them, so a phrase
    around an address is never read as part of it. Linear in ``text``.
    """
    if "@" not in text:
        return []
    found: list[str] = []
    for word in re.finditer(r"\S+", text):
        if "://" in word.group(0):
            continue
        start = _address_in(word.group(0))
        if start is not None:
            found.append(word.group(0)[start:])
    return found


def masked_bare_userinfo(text: str, mask: str = SNAPSHOT_MASK) -> str:
    """``text`` with the userinfo of every address written with no scheme masked.

    Each whitespace-separated word outside a URL (:func:`url_spans`, which
    :func:`masked_text` masks) is read by :func:`bare_userinfo` from its last
    opener before its last ``@``; its userinfo is replaced by the mask, never
    removed. Linear in ``text``.
    """
    if "@" not in text:
        return text
    spans = url_spans(text) if "://" in text else []
    out: list[str] = []
    last = 0
    at = 0  # the first URL span that does not end before this word
    for word in re.finditer(r"\S+", text):
        begin, end = word.span()
        while at < len(spans) and spans[at][1] <= begin:
            at += 1
        if at < len(spans) and spans[at][0] < end:
            continue
        token = word.group(0)
        start = _address_in(token)
        if start is None:
            continue
        out.append(text[last : begin + start])
        out.append(f"{mask}@{token.rpartition('@')[2]}")
        last = end
    out.append(text[last:])
    return "".join(out)


def masked_text(text: str, mask: str = SNAPSHOT_MASK) -> str:
    """``text`` with every URL in it masked: userinfo, query values and fragment.

    An address written with no scheme has its userinfo masked too
    (:func:`masked_bare_userinfo`).
    """
    text = masked_bare_userinfo(text, mask)
    if "://" not in text:
        return text
    out: list[str] = []
    last = 0
    for start, end in url_spans(text):
        out.append(text[last:start])
        out.append(_masked_one_url(text[start:end], mask))
        last = end
    out.append(text[last:])
    return "".join(out)


def _flag_name(arg: str) -> str:
    return arg.lstrip("-").split("=", 1)[0]


# ``NAME=value`` as a whole argument (``docker -e API_KEY=v``, a bare
# ``TOKEN=v``), and ``Header: value`` (``-H "Authorization: Bearer v"``).
# Possessive, so each costs time linear in the argument.
_ASSIGNMENT_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_.-]*+)=(?=.)")
_HEADER_RE = re.compile(r"[ \t]*+([A-Za-z0-9_-]++)[ \t]*+:[ \t]*+(?!//)(?=\S)")


def _credential_header(name: str) -> bool:
    """Whether an HTTP header ``name`` carries a credential.

    Authorization, a cookie, a name holding a key or a token, or one the
    settings read as a credential's (``names_a_credential_value``: ``X-Secret``).
    """
    lowered = name.lower()
    return (
        lowered.endswith("authorization")
        or lowered in ("cookie", "set-cookie")
        or "key" in lowered
        or "token" in lowered
        or _credential_name(name)
    )


def _masked_assignment(arg: str, mask: str) -> str | None:
    """``arg`` with the value of a credential's ``NAME=value`` or ``Header: value`` masked.

    ``None`` when ``arg`` is neither, or names no credential.
    """
    assignment = _ASSIGNMENT_RE.match(arg)
    if assignment is not None and _credential_name(assignment.group(1)):
        return f"{assignment.group(1)}={mask}"
    header = _HEADER_RE.match(arg)
    if header is not None and _credential_header(header.group(1)):
        return f"{arg[: header.end()]}{mask}"
    return None


def masked_args(args: list[Any], mask: str = SNAPSHOT_MASK) -> list[Any]:
    """A command line with every credential in it masked, and every URL in it.

    The value after a flag whose name marks a credential (``--api-key T``,
    ``--token=T``): the argument after such a flag is its value unless it is
    another long flag (``--...``), since a credential may itself begin with
    ``-``. And, whatever flag stands before it, the value of a ``NAME=value``
    whose name marks a credential (``-e API_KEY=T``, ``--env=TOKEN=T``) and of
    a ``Header: value`` whose header carries one (``-H "Authorization: T"``,
    ``X-Api-Key: T``).
    """
    out: list[Any] = []
    after_flag = False
    for arg in args:
        if not isinstance(arg, str):
            out.append(arg)
            after_flag = False
            continue
        if after_flag and not arg.startswith("--"):
            out.append(mask if arg else arg)
            after_flag = False
            continue
        after_flag = False
        if arg.startswith("-") and _credential_name(_flag_name(arg)):
            if "=" in arg:
                flag, value = arg.split("=", 1)
                out.append(f"{flag}={mask}" if value else arg)
            else:
                out.append(arg)
                after_flag = True
            continue
        if arg.startswith("-") and "=" in arg:
            flag, value = arg.split("=", 1)
            inner = _masked_assignment(value, mask)
            if inner is not None:
                out.append(f"{flag}={inner}")
                continue
        elif not arg.startswith("-"):
            whole = _masked_assignment(arg, mask)
            if whole is not None:
                out.append(whole)
                continue
        out.append(masked_text(arg, mask))
    return out


# Every walk below keeps its own stack: a stored value can be nested deeper
# than the interpreter recurses (the declaration data is read at any depth),
# and a masking that raised on one would fail the read it stands in front of.
_NESTED = (Mapping, list, tuple)


def _masked_scalar(item: Any, mask: str) -> Any:
    """A credential's value as the mask; nothing set stays as it is."""
    if item in (None, "") or isinstance(item, bool) or not isinstance(item, str | int | float):
        return item
    return mask


def _copy_masked(value: Any, mask: str, *, read_names: bool) -> Any:
    """``value`` copied with every URL masked, and, with ``read_names``, every
    mapping entry whose key names a credential."""
    if not isinstance(value, _NESTED):
        return masked_text(value, mask) if isinstance(value, str) else value
    holder: list[Any] = [None]
    stack: list[tuple[Any, Any, Any]] = [(value, holder, 0)]
    while stack:
        source, target, slot = stack.pop()
        if isinstance(source, Mapping):
            out: Any = {}
            items: Any = source.items()
        else:
            out = [None] * len(source)
            items = enumerate(source)
        target[slot] = out
        named = read_names and isinstance(source, Mapping)
        for key, item in items:
            if isinstance(item, _NESTED):
                out[key] = None
                stack.append((item, out, key))
            elif named and _credential_name(str(key)):
                out[key] = _masked_scalar(item, mask)
            else:
                out[key] = masked_text(item, mask) if isinstance(item, str) else item
    return holder[0]


def masked_value(value: Any, mask: str = SNAPSHOT_MASK) -> Any:
    """Every entry whose key names a credential masked, and every URL, at any depth."""
    return _copy_masked(value, mask, read_names=True)


def masked_strings(value: Any, mask: str = SNAPSHOT_MASK) -> Any:
    """Every URL in ``value``'s strings masked, at any depth; no key's name is read.

    For a composite whose keys are field names of a model (a stage's ``key``
    is no credential), not an open mapping.
    """
    return _copy_masked(value, mask, read_names=False)


def masked_server(entry: Mapping[str, Any], mask: str = SNAPSHOT_MASK) -> dict[str, Any]:
    """A tool server's settings (``MCPServerConfig`` as a mapping) as a reader may see them.

    Its ``env`` values all masked, names kept and sorted; its arguments by
    :func:`masked_args`; a field whose name marks a credential (``auth_token``)
    masked when set; every URL in its other fields by :func:`masked_strings`.
    """
    out: dict[str, Any] = {}
    for key, item in entry.items():
        if key == "env" and isinstance(item, Mapping):
            out[key] = {name: mask for name in sorted(item, key=str)}
        elif key == "args" and isinstance(item, list | tuple):
            out[key] = masked_args(list(item), mask)
        elif _credential_name(str(key)) and not isinstance(item, _NESTED):
            out[key] = _masked_scalar(item, mask)
        else:
            out[key] = masked_strings(item, mask)
    return out


def masked_server_map(servers: Mapping[str, Any], mask: str = SNAPSHOT_MASK) -> dict[str, Any]:
    """Every entry of a tool-server map by :func:`masked_server`."""
    return {
        name: masked_server(entry, mask) if isinstance(entry, Mapping) else entry
        for name, entry in servers.items()
    }


def masked_dump(instance: Any, dumped: Any, mask: str = SNAPSHOT_MASK) -> Any:
    """``dumped`` (``instance.model_dump(mode="json")``) masked, read with its model.

    A tool-server block (``MCPServerConfig``) by :func:`masked_server`; a model's
    fields by their own value, never by their name (a stage's ``key`` is no
    credential); a value that is no model (an open mapping, a list of plain
    values) by :func:`masked_value`, whose entry names are read. The models
    nest only as deep as the settings model does; what is not a model is
    walked without recursion.
    """
    from pydantic import BaseModel

    from maljan.core.config import MCPServerConfig

    if isinstance(instance, MCPServerConfig) and isinstance(dumped, Mapping):
        return masked_server(dumped, mask)
    if isinstance(instance, BaseModel) and isinstance(dumped, Mapping):
        return {
            key: masked_dump(getattr(instance, key, None), item, mask)
            for key, item in dumped.items()
        }
    if isinstance(dumped, Mapping) and isinstance(instance, Mapping):
        return {
            key: (
                masked_dump(instance.get(key), item, mask)
                if isinstance(instance.get(key), BaseModel)
                else masked_value({key: item}, mask)[key]
            )
            for key, item in dumped.items()
        }
    if isinstance(dumped, list) and isinstance(instance, list | tuple):
        items = list(instance)
        return [
            masked_dump(items[index], item, mask)
            if index < len(items) and isinstance(items[index], BaseModel)
            else masked_value(item, mask)
            for index, item in enumerate(dumped)
        ]
    return masked_value(dumped, mask)


def unmasked(incoming: Any, stored: Any, shown: Any) -> tuple[Any, list[tuple[Any, ...]]]:
    """``(incoming read back, the paths it read back)``.

    ``shown`` is ``stored`` as the reader was shown it (masked by the same
    function and mask). Mappings are matched by key and lists by position
    when the three kept one length; a plain value equal to its shown form,
    where that differs from the stored one, is read as the stored one, and its
    path (keys and indexes from the root) is returned. Every other part is the
    reader's own. A caller masks the result again and refuses it unless every
    returned path reads there exactly as the reader sent it (:func:`value_at`):
    a stored value read back into a place masked otherwise, or not at all,
    would be shown in clear.
    """
    holder: list[Any] = [None]
    restored: list[Any] = []
    # Each node keeps its parent and its key, so a path is spelled only when read back.
    stack: list[tuple[Any, Any, Any, Any, Any, Any]] = [(incoming, stored, shown, holder, 0, None)]
    while stack:
        sent, held, seen, target, slot, node = stack.pop()
        if isinstance(sent, Mapping) and isinstance(held, Mapping) and isinstance(seen, Mapping):
            out: Any = {}
            target[slot] = out
            for key, item in sent.items():
                out[key] = None
                stack.append((item, held.get(key), seen.get(key), out, key, (node, key)))
        elif (
            isinstance(sent, list)
            and isinstance(held, list)
            and isinstance(seen, list)
            and len(sent) == len(held) == len(seen)
        ):
            out = [None] * len(sent)
            target[slot] = out
            for index, item in enumerate(sent):
                stack.append((item, held[index], seen[index], out, index, (node, index)))
        elif (
            not isinstance(sent, _NESTED)
            and not isinstance(seen, _NESTED)
            and held is not None
            and not isinstance(held, _NESTED)
            and sent == seen
            and seen != held
        ):
            target[slot] = held
            restored.append(node)
        else:
            target[slot] = sent
    paths: list[tuple[Any, ...]] = []
    for node in restored:
        parts: list[Any] = []
        while node is not None:
            node, key = node
            parts.append(key)
        paths.append(tuple(reversed(parts)))
    return holder[0], paths


def value_at(value: Any, path: tuple[Any, ...]) -> Any:
    """The part of ``value`` at ``path`` (keys and indexes), or ``None`` where there is none."""
    for key in path:
        if isinstance(value, Mapping):
            value = value.get(key)
        elif isinstance(value, list) and isinstance(key, int) and 0 <= key < len(value):
            value = value[key]
        else:
            return None
    return value


def mask_left_in(value: Any, mask: str) -> list[str]:
    """The dotted paths in ``value`` whose string still carries ``mask``.

    ``""`` names ``value`` itself.
    """
    found: list[str] = []
    # Each node keeps its parent and its key, so a path is spelled only when found.
    stack: list[tuple[Any, Any]] = [(value, None)]
    while stack:
        item, node = stack.pop()
        if isinstance(item, str):
            if mask in item:
                parts: list[str] = []
                while node is not None:
                    node, key = node
                    parts.append(str(key))
                found.append(".".join(reversed(parts)))
        elif isinstance(item, Mapping):
            stack.extend((child, (node, key)) for key, child in item.items())
        elif isinstance(item, list | tuple):
            stack.extend((child, (node, index)) for index, child in enumerate(item))
    return sorted(found)
