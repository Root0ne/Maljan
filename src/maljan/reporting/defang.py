"""Write a live indicator so that nobody can click it, keyed on what it is.

The human-readable renderings — the Markdown, and the HTML and PDF made from
it — print network indicators the way analysts exchange them: ``hxxps://``,
``[.]``, ``[:]`` and ``[@]``, so a value pasted into a chat or a ticket does not
become a live link. The machine surfaces (the STIX bundle, MISP, the JSON report
and ``/reports/{id}/iocs``) carry the value live, because a consumer matching on
it needs the real one.

The rule is decided by the indicator's **kind**, never by the shape of the
string. The earlier rule defanged anything with a dot and no backslash, which
turned the file name ``update_data.dat`` into ``update_data[.]dat`` and wrote
URLs as ``hxxp[://]``, a form nobody else uses. A hash, a path, a registry key,
a mutex, a pipe, a user agent or a command is returned exactly as given.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

# The kinds that are written defanged, by the name each producer uses for them.
# ``ip`` is the string sweep's word for an address of either family.
_URL_KINDS = frozenset({"url", "c2 url"})
_DOMAIN_KINDS = frozenset({"domain", "fqdn", "tls sni", "sni"})
_IPV4_KINDS = frozenset({"ipv4", "ipv4-addr"})
_IPV6_KINDS = frozenset({"ipv6", "ipv6-addr"})
_IP_KINDS = frozenset({"ip", "address"})
_EMAIL_KINDS = frozenset({"email", "email-addr"})

# The schemes and the spellings they take once defanged.
_SCHEMES = {"http": "hxxp", "https": "hxxps", "ftp": "fxp"}
_SCHEME_RE = re.compile(r"^(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*)://")
# A live scheme in prose whose host has just been defanged: the URL around an
# indexed host that is not itself in the index.
_LIVE_SCHEME_BEFORE_DEFANGED_RE = re.compile(
    r"(?<![A-Za-z0-9+.-])(?P<scheme>https?|ftp)://(?=[^\s/?#]*\[[.:]\])", re.IGNORECASE
)


def _dots(value: str) -> str:
    """Every ``.`` bracketed, and never twice."""
    return value.replace("[.]", ".").replace(".", "[.]")


def _url(value: str) -> str:
    """Scheme renamed, the host's dots bracketed, path and query left alone."""
    match = _SCHEME_RE.match(value)
    if match is None:
        # A URL written without its scheme: the host runs to the first slash.
        host, slash, rest = value.partition("/")
        return _dots(host) + slash + rest
    scheme = match.group("scheme")
    written = _SCHEMES.get(scheme.lower(), scheme)
    if written != scheme and scheme.isupper():
        written = written.upper()
    remainder = value[match.end() :]
    cut = len(remainder)
    for separator in ("/", "?", "#"):
        index = remainder.find(separator)
        if index != -1:
            cut = min(cut, index)
    authority, tail = remainder[:cut], remainder[cut:]
    return f"{written}://{_dots(authority)}{tail}"


def _ipv6(value: str) -> str:
    if "[:]" in value:
        return value
    return value.replace(":", "[:]", 1)


def _email(value: str) -> str:
    local, at, domain = value.replace("[@]", "@").rpartition("@")
    if not at:
        return value
    return f"{local}[@]{_dots(domain)}"


def defang(value: str, kind: str) -> str:
    """``value`` written for reading, by the rule for ``kind``.

    Idempotent: a value already defanged comes back as it went in. A kind this
    function does not name is returned unchanged, which is the rule for every
    kind that is not a network indicator.
    """
    if not value:
        return value
    key = str(kind or "").strip().lower()
    if key in _URL_KINDS:
        return _url(value)
    if key in _DOMAIN_KINDS or key in _IPV4_KINDS:
        return _dots(value)
    if key in _IPV6_KINDS:
        return _ipv6(value)
    if key in _IP_KINDS:
        return _ipv6(value) if ":" in value.replace("[:]", ":") else _dots(value)
    if key in _EMAIL_KINDS:
        return _email(value)
    return value


class ProseDefanger:
    """Defangs exactly the given indicators wherever they occur in a text.

    Model prose names the run's endpoints in passing, and a sentence carrying a
    live URL is the same hazard a table cell is. Only the values the run's own
    network block and IOC table hold are touched, and only where one stands as
    a whole token, so an ordinary word, a file name or a version number is
    never rewritten: this changes how a value is written, never which value.
    The longest value is tried first, so a URL is defanged as a URL and not as
    the domain inside it. Built once per rendering and applied to every piece
    of prose in it.
    """

    def __init__(self, indicators: Iterable[tuple[str, str]]) -> None:
        self._kinds: dict[str, str] = {}
        for value, kind in indicators:
            written = str(value or "").strip()
            if written and defang(written, kind) != written:
                self._kinds.setdefault(written.lower(), kind)
        self._pattern: re.Pattern[str] | None = None
        if self._kinds:
            alternatives = "|".join(
                re.escape(value) for value in sorted(self._kinds, key=len, reverse=True)
            )
            self._pattern = re.compile(
                rf"(?<![A-Za-z0-9_.@-])(?:{alternatives})(?![A-Za-z0-9_-]|\.[A-Za-z0-9])",
                re.IGNORECASE,
            )

    def __call__(self, text: str) -> str:
        if not text or self._pattern is None:
            return text
        written = self._pattern.sub(
            lambda m: defang(m.group(0), self._kinds[m.group(0).lower()]), text
        )
        # A host defanged inside a URL the index does not hold would otherwise
        # leave the URL's scheme live in front of it.
        return _LIVE_SCHEME_BEFORE_DEFANGED_RE.sub(_renamed_scheme, written)


def _renamed_scheme(match: re.Match[str]) -> str:
    scheme = match.group("scheme")
    written = _SCHEMES[scheme.lower()]
    return (written.upper() if scheme.isupper() else written) + "://"


def defang_text(text: str, indicators: Iterable[tuple[str, str]]) -> str:
    """``text`` with exactly the given indicators defanged; see :class:`ProseDefanger`."""
    return ProseDefanger(indicators)(text)
