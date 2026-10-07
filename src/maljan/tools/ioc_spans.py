"""The indicator scan's rows, each with the place in the bytes its value was matched.

``tools.strings.iter_string_iocs`` states which indicators a blob holds; this
module states the same rows, in the same order, and where each one's match
stands, so ``transform_bytes`` can give an offset that is the scan's own match
rather than a search for the value afterwards. It reads with the same patterns
and the same tests (``tools.strings``) and keeps a value under the same rule;
it is a path of its own so the scan every other caller runs is not changed by
it. A test holds its rows equal to ``iter_string_iocs``'s.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Any

from maljan.tools import strings as S

# One match: its kind, its text as matched, its notes, its length floor, and
# where it starts and ends in the scanned blob.
_Hit = tuple[str, str, str | None, int, int, int]


def _runs(blob: bytes, stopped: list[int]) -> Iterator[tuple[str, int, int]]:
    """``strings._iter_strings``'s runs, with each one's offset and character width."""
    scanned = 0
    for pattern, width in ((S._PRINTABLE_RE, 1), (S._WIDE_RE, 2)):
        for match in pattern.finditer(blob):
            yield match.group()[::width].decode("ascii", errors="ignore"), match.start(), width
            scanned += 1
            if scanned >= S._MAX_STRINGS_SCANNED:
                stopped.append(match.end())
                return


def _email_spans(data: bytes) -> list[tuple[int, int]]:
    """Where each of ``strings.emails_in``'s matches starts and ends, read the same way."""
    found: list[tuple[int, int]] = []
    floor = 0
    at = data.find(b"@")
    while at != -1:
        start = at
        while start > floor and data[start - 1] in S._EMAIL_NAME_BYTES:
            start -= 1
        domain = S._EMAIL_DOMAIN_RE.match(data, at + 1) if start < at else None
        if domain is not None:
            found.append((start, domain.end()))
            floor = domain.end()
            at = data.find(b"@", floor)
        else:
            at = data.find(b"@", at + 1)
    return found


def _domain_spans(text: str) -> list[tuple[int, int, str]]:
    """``strings._domains_in``'s names, each with where it stands in ``text``."""
    found: list[tuple[int, int, str]] = []
    for match in S._DOMAIN_RE.finditer(text.encode("ascii", errors="ignore")):
        candidate = match.group().decode("ascii", errors="ignore")
        if S._looks_like_domain(candidate):
            found.append((match.start(), match.end(), candidate))
    if all(found[index][1] <= found[index + 1][0] for index in range(len(found) - 1)):
        return found
    return [(s, e, v) for s, e, v in found if not S._inside_a_longer_host(s, e, found)]


def _hits(blob: bytes, stopped: list[int]) -> Iterator[_Hit]:
    """Every match ``iter_string_iocs`` makes, in its order, with its span in ``blob``."""
    for text, base, width in _runs(blob, stopped):
        encoded = text.encode("ascii", errors="ignore")

        def at(span: tuple[int, int], base: int = base, width: int = width) -> tuple[int, int]:
            return base + span[0] * width, base + span[1] * width

        for match in S._URL_RE.finditer(encoded):
            yield (
                "url",
                match.group().decode("ascii", errors="ignore"),
                None,
                0,
                *at(match.span()),
            )
        for found in S._IP_RE.finditer(encoded):
            ip = found.group().decode("ascii", errors="ignore")
            if S._is_meaningful_ip(ip) and not S._written_as_a_version(encoded, found.start()):
                yield ("ip", ip, None, 0, *at(found.span()))
        for match in S._REG_RE.finditer(encoded):
            value = match.group().decode("ascii", errors="ignore")
            yield ("registry", value, None, 0, *at(match.span()))
        for match in S._PATH_RE.finditer(encoded):
            candidate = match.group().decode("ascii", errors="ignore")
            if S._looks_like_path(candidate):
                yield ("path", candidate, None, 0, *at(match.span()))
        for span in _email_spans(encoded):
            value = encoded[span[0] : span[1]].decode("ascii", errors="ignore")
            yield ("email", value, None, 0, *at(span))
        for match in S._MUTEX_RE.finditer(encoded):
            value = match.group().decode("ascii", errors="ignore")
            yield ("mutex", value, None, 0, *at(match.span()))
        for start, end, candidate in _domain_spans(text):
            short = S.two_character_label_with_a_digit(candidate.split(".", 1)[0])
            floor = S._SHORT_RUN_LENGTH if short else 0
            yield ("domain", candidate, None, floor, *at((start, end)))
        for label, pattern in S._SECRET_PATTERNS:
            for hit in pattern.finditer(text):
                yield ("secret", hit.group(), label, 0, *at(hit.span()))
        for label, pattern in S._WALLET_PATTERNS:
            for hit in pattern.finditer(text):
                yield ("crypto_wallet", hit.group(), label, 0, *at(hit.span()))
        for hit in S._ONION_RE.finditer(text):
            yield ("domain", hit.group(), "tor_hidden_service", 0, *at(hit.span()))
    for host_pattern, width in ((S._SHORT_HOST_RE, 1), (S._SHORT_WIDE_HOST_RE, 2)):
        first: dict[bytes, tuple[int, int]] = {}
        for match in host_pattern.finditer(blob):
            first.setdefault(match.group(1), match.span(1))
        for run, (start, end) in first.items():
            host = S._short_host(run[::width].decode("ascii"))
            if host:
                yield ("domain", host, None, S._SHORT_RUN_LENGTH, start, end)


def string_iocs_with_spans(
    blob: bytes, kinds: Iterable[str] | None = None
) -> tuple[list[dict[str, Any]], int | None]:
    """``iter_string_iocs``'s rows, each with the span its value was matched at.

    The same rows in the same order, narrowed to ``kinds`` when given; each
    also carries ``start`` and ``end``, the offsets in ``blob`` of the value as
    kept (its NULs and then its whitespace stripped from both ends), and
    ``width``, 1 for a match in an ASCII run and 2 for one in a UTF-16LE run.
    The second value is the offset at which the run bound stopped the scan,
    or ``None`` when it read every run.
    """
    keep = set(kinds) if kinds else None
    stopped: list[int] = []
    seen: set[tuple[str, str]] = set()
    rows: list[dict[str, Any]] = []
    for kind, matched, notes, floor, start, end in _hits(blob, stopped):
        decoded = matched.strip("\x00").strip()
        if len(decoded) < (floor or S._MIN_STRING_LENGTH):
            continue
        key = (kind, decoded.lower())
        if key in seen:
            continue
        seen.add(key)
        if keep is not None and kind not in keep:
            continue
        without_nul = matched.strip("\x00")
        front = len(matched) - len(matched.lstrip("\x00"))
        front += len(without_nul) - len(without_nul.lstrip())
        width = (end - start) // len(matched)
        rows.append(
            {
                "kind": kind,
                "value": decoded,
                "notes": notes,
                "source": S._IOC_SOURCE,
                "start": start + front * width,
                "end": start + (front + len(decoded)) * width,
                "width": width,
            }
        )
    return rows, (stopped[0] if stopped else None)
