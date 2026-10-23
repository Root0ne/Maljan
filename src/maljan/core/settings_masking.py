"""One masking of settings values for every reader that is not the store itself.

The run settings snapshot (``settings_overrides.public_snapshot``), the
efficiency fingerprint (``analysis.efficiency``), the console's settings read
and the JSON export all show settings to someone other than the store. Each of
them masks with these functions, so what one hides the others hide too:

* every URL in a string: its user name and password, every query value (the
  keys stay) and its fragment, each replaced by the mask, never removed;
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


def masked_text(text: str, mask: str = SNAPSHOT_MASK) -> str:
    """``text`` with every URL in it masked: userinfo, query values and fragment."""
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
