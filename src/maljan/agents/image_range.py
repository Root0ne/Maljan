"""The loaded image's address range, and what a failed call outside it is told.

A reversing model that drops a hex digit from an address (``0x1360bcfa00``
for ``0x1360bc0fa00``) asks a static server for bytes below the image, and the
server answers only that it could not read them. The model then has nothing
to correct. The range is read from facts the run already holds, never
guessed:

* the static server's own program statement (a tool of kind
  ``program_info``): its ``image_base`` to its ``max_address``, the latest
  one the run read;
* else the pack's: the one image base its answers state, to the image size
  an answer states (``size_of_image``) or, with none, the end of the last
  section the PE header lists; the sample's own names are the ones the
  pack's answers record (its identity answers' file, the working copy a
  pack answer names), so an analyst that opens the sample itself keeps it.

A call is held against it only where its tool declares an ``address``
argument (``ToolFacts.arguments``) and declares that it does not run the
sample's code (``ToolEffects.executes`` ``no``): a static reading of any
server, never one picked by name. Only a call that *failed* is told
(:func:`out_of_image_note`); the server's answer stays as it was and the
sentence is added beside it and to the entry's remediation. A server that
maps more than the image (Ghidra lists blocks below the image base) answers
such an address as it always did, and an address inside the image is never
touched.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any

from maljan.core.declared_reading import facts_of, kind_free_facts, kind_of
from maljan.pipeline.validation import _address_value, image_bases_in

_PROGRAM_KIND = "program_info"
_PE_HEADER_READER = "pe_header"
_IDENTITY_KIND = "identity"
# The declared kinds of a call that opens or selects a program: the file its
# ``path`` argument names is then a program the agent named, as a ``program``
# argument is (Ghidra's open, load, project load, import and switch; radare2's
# open).
_OPENS_A_PROGRAM = frozenset(
    {
        "load_sample",
        "open_project_program",
        "project_load",
        "file_import",
        "select_sample",
        "open_sample",
    }
)


@dataclass(frozen=True)
class ImageRange:
    """The loaded image's first and last address (inclusive), and the program they are of.

    ``program`` is the name the server's program statement gives, ``""``
    for a range read from the pack's answers; ``names`` are the sample's own
    file names the pack's answers record, for a range read from them.
    """

    start: int
    end: int
    program: str = ""
    # Whether the agent's own entries name a program other than the range's
    # (``program``, or one of ``names``): a call that names none may then be
    # about another program, and is told nothing.
    others: bool = False
    names: tuple[str, ...] = ()


def _held(entry: Any) -> bool:
    return getattr(entry, "ok", True) is not False and not getattr(entry, "repeated_of", None)


def _program_range(entry: Any) -> ImageRange | None:
    data = getattr(entry, "structured", None)
    if not isinstance(data, Mapping):
        return None
    start = _address_value(data.get("image_base")) if data.get("image_base") is not None else None
    end = _address_value(data.get("max_address")) if data.get("max_address") is not None else None
    if not start or end is None or end < start:
        return None
    return ImageRange(start, end, str(data.get("name") or ""))


def _size(value: Any) -> int:
    """A size as a tool writes it: an integer, decimal digits, or hex with ``0x``."""
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return max(value, 0)
    text = str(value or "").strip()
    if text[:2].lower() == "0x":
        return _address_value(text) or 0
    return int(text) if text.isascii() and text.isdigit() else 0


def _pack_extent(entry: Any) -> int:
    """The image size one answer states, or the end of the last section its PE header lists."""
    data = getattr(entry, "structured", None)
    if not isinstance(data, Mapping):
        return 0
    extent = max(_size(data.get(key)) for key in ("size_of_image", "image_size"))
    facts = facts_of(entry)
    if facts is not None and facts.reader == _PE_HEADER_READER:
        for row in data.get("sections") or ():
            if isinstance(row, Mapping):
                start = _address_value(row.get("virtual_address"))
                if start is not None:
                    extent = max(extent, start + _size(row.get("virtual_size")))
    return extent


def _programs_named(entries: Iterable[Any]) -> list[str]:
    """The programs ``entries`` name.

    A call's declared ``program`` argument; the file name a declared ``path``
    argument gives a call of a kind that opens or selects a program
    (:data:`_OPENS_A_PROGRAM`); a program statement's name.
    """
    named: list[str] = []
    for entry in entries:
        roles = getattr(kind_free_facts(entry), "arguments", None)
        roles = roles if isinstance(roles, Mapping) else {}
        args = getattr(entry, "args", None)
        args = args if isinstance(args, Mapping) else {}
        held = [str(roles.get("program") or "")]
        if kind_of(entry) in _OPENS_A_PROGRAM:
            held.append(str(roles.get("path") or ""))
        for role in held:
            value = args.get(role) if role else None
            if value not in (None, ""):
                named.append(_basename(value))
        if _held(entry) and kind_of(entry) == _PROGRAM_KIND:
            stated = _program_range(entry)
            if stated is not None and stated.program:
                named.append(stated.program)
    return named


def _basename(value: Any) -> str:
    return str(value).strip().replace("\\", "/").rsplit("/", 1)[-1]


def _sample_names(pack: Iterable[Any]) -> tuple[str, ...]:
    """The sample's own file names the pack's answers record, once each.

    The file its identity answers (declared kind ``identity``) read, by
    their declared ``path`` argument, and the job's working copy where a
    pack answer names the program it read (a declared ``program`` argument,
    or the answer's ``program``).
    """
    names: dict[str, None] = {}
    for entry in pack:
        roles = getattr(kind_free_facts(entry), "arguments", None)
        roles = roles if isinstance(roles, Mapping) else {}
        args = getattr(entry, "args", None)
        args = args if isinstance(args, Mapping) else {}
        held: list[Any] = []
        if kind_of(entry) == _IDENTITY_KIND and roles.get("path"):
            held.append(args.get(str(roles["path"])))
        if roles.get("program"):
            held.append(args.get(str(roles["program"])))
        data = getattr(entry, "structured", None)
        if _held(entry) and isinstance(data, Mapping) and isinstance(data.get("program"), str):
            held.append(data["program"])
        for value in held:
            name = _basename(value) if value not in (None, "") else ""
            if name:
                names.setdefault(name, None)
    return tuple(names)


def image_range_of(pack: Iterable[Any], own: Iterable[Any] = ()) -> ImageRange | None:
    """The loaded image's range by the facts ``pack`` and ``own`` entries hold, else ``None``.

    The latest program statement of either wins; with none, the pack's one
    image base and its extent. Two image bases, or none, or no extent: no
    range. ``others`` says whether ``own`` names a program other than the
    range's (for the pack's, other than the sample's own names).
    """
    pack, own = list(pack), list(own)
    named = _programs_named(own)
    stated: ImageRange | None = None
    for entry in (*pack, *own):
        if _held(entry) and kind_of(entry) == _PROGRAM_KIND:
            stated = _program_range(entry) or stated
    if stated is not None:
        others = any(not _same_program(name, stated) for name in named)
        return replace(stated, others=others)
    held = [entry for entry in pack if _held(entry)]
    bases = image_bases_in(held)
    extent = max((_pack_extent(entry) for entry in held), default=0)
    if len(bases) != 1 or extent <= 0:
        return None
    found = ImageRange(bases[0], bases[0] + extent - 1, names=_sample_names(pack))
    return replace(found, others=any(not _same_program(name, found) for name in named))


class ImageRangeReader:
    """:func:`image_range_of`, read again only when either list of entries has grown.

    An agent asks on every failed call; the range it read stands until an
    entry is added.
    """

    def __init__(self) -> None:
        self._key: tuple[int, int] | None = None
        self._range: ImageRange | None = None

    def __call__(self, pack: Sequence[Any], own: Sequence[Any]) -> ImageRange | None:
        key = (len(pack), len(own))
        if key != self._key:
            self._range = image_range_of(pack, own)
            self._key = key
        return self._range


def _same_program(named: str, image: ImageRange) -> bool:
    """Whether a call's program argument names the program ``image`` was read for."""
    own = {image.program, *image.names} - {""}
    named = named.strip().replace("\\", "/")
    return named in own or named.rsplit("/", 1)[-1] in own


def _number(value: Any) -> int | None:
    """An address argument as a number: an integer, or a string with ``0x`` or a decimal digit.

    A string of hex letters alone (``fade``) is a name, never an address.
    """
    if isinstance(value, str):
        text = value.strip()
        if text[:2].lower() != "0x" and not any(c.isdigit() for c in text):
            return None
    return _address_value(value)


def _decimal_inside(value: Any, image: ImageRange) -> bool:
    """Whether a string of decimal digits alone, read as decimal, lies inside ``image``."""
    text = value.strip() if isinstance(value, str) else ""
    return text.isascii() and text.isdigit() and image.start <= int(text) <= image.end


def _digits(value: int) -> int:
    return len(f"{value:x}")


def locates_in_image(facts: Any) -> bool:
    """Whether a tool declares an ``address`` argument and that it does not run the sample's code."""
    roles = getattr(facts, "arguments", None)
    effects = getattr(facts, "effects", None)
    return (
        isinstance(roles, Mapping)
        and bool(roles.get("address"))
        and getattr(effects, "executes", "") == "no"
    )


def out_of_image_note(facts: Any, args: Mapping[str, Any], image: ImageRange | None) -> str:
    """The sentence for a call whose declared address argument lies outside ``image``, else ``""``.

    ``""`` with no range, for a tool that declares no address argument or
    does not declare that it leaves the sample's code unrun, for an address
    that is not a number, or one inside the image; and where the call names
    a program the range was not read for, or names none while the agent's
    own entries name another program (:attr:`ImageRange.others`). A string
    of decimal digits that, read as decimal, lies inside the image is told
    nothing either.
    """
    if image is None or not locates_in_image(facts):
        return ""
    roles = facts.arguments
    value = args.get(str(roles["address"]))
    if value is None or value == "":
        return ""
    address = _number(value)
    if address is None or image.start <= address <= image.end or _decimal_inside(value, image):
        return ""
    program = args.get(str(roles.get("program") or "")) if roles.get("program") else None
    if program in (None, ""):
        if image.others:
            return ""
    elif not _same_program(str(program), image):
        return ""
    note = f"address {address:#x} is outside the image {image.start:#x}–{image.end:#x}"
    low, high = _digits(image.start), _digits(image.end)
    held = low if low == high else f"{low} to {high}"
    if _digits(address) < low:
        note += f" (did a digit drop? in-image addresses here have {held} hex digits)"
    elif _digits(address) > high:
        note += f" (is a digit extra? in-image addresses here have {held} hex digits)"
    return f"{note}; pass an address inside the image"
