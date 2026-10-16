"""Whether a host is this machine's, read from the host as written and nothing else.

One rule, written once, for every reader that has to say where something
went: the run's disclosure block (``analysis.disclosure``) classifies every
model endpoint, tool server, lookup service and sandbox it names by it, and
the analyst-mode decision (``pipeline.analyst_mode``) reads the same address
and name rules before it resolves a name.

A host is **local** when the text alone establishes it:

* an address literal in a loopback, private, link-local or shared
  (``100.64.0.0/10``) range, an IPv4 address mapped into IPv6 read as the
  IPv4 address it carries;
* a name only a local resolver answers: ``localhost``, a container runtime's
  name for the host it runs on (``host.docker.internal`` and its kin), and
  any name under ``.localhost``, ``.local`` or ``.internal``;
* a single label with no dot (``qdrant``, ``ghidra-mcp``): the name a
  compose network gives a service, which no public resolver answers. A label
  of digits alone (``2130706433``, ``0x7f000001``) is an address written as
  one number, as the system's address parser reads it, and is classified as
  that address.

Any other host is **remote**: a public address, or a dotted name the text
cannot place, which is taken as reaching beyond this machine because nothing
here resolves it. Resolving would make the answer depend on the resolver of
whichever process asks, and a stored run would read differently next week.
An address with no host in it is **unknown**, never local.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

LOCAL = "local"
REMOTE = "remote"
UNKNOWN = "unknown"

# Names only a local resolver answers: a container runtime's name for the host
# it runs on, and the machine's own.
LOCAL_NAMES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "host.docker.internal",
        "gateway.docker.internal",
        "host.containers.internal",
        "host.lima.internal",
    }
)
# The suffixes under which every name is answered locally.
LOCAL_SUFFIXES: tuple[str, ...] = (".localhost", ".local", ".internal")

_SHARED_RANGE = ipaddress.ip_network("100.64.0.0/10")
# One DNS label: what a compose network names a service by.
_SERVICE_NAME = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")


def local_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Whether ``address`` is in a loopback, private, link-local or shared range."""
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return bool(
        address.is_loopback
        or address.is_private
        or address.is_link_local
        or (isinstance(address, ipaddress.IPv4Address) and address in _SHARED_RANGE)
    )


def named_locally(host: str) -> bool:
    """Whether ``host`` is a name only a local resolver answers."""
    return host in LOCAL_NAMES or host.endswith(LOCAL_SUFFIXES)


def service_name(host: str) -> bool:
    """Whether ``host`` is a single label that is not a number: a compose service's name."""
    return bool(_SERVICE_NAME.match(host)) and _number(host) is None


def _number(host: str) -> int | None:
    """``host`` read as one number the way the system's address parser reads it, or ``None``.

    Decimal, octal with a leading zero, and hexadecimal with ``0x``. A number
    with more significant digits than any 32-bit value has in its base is
    answered as the first value past 32 bits, so no text of any length is
    converted whole.
    """
    if re.fullmatch(r"0x[0-9a-f]+", host):
        digits, base = host[2:], 16
    elif re.fullmatch(r"0[0-7]+", host):
        digits, base = host[1:], 8
    elif re.fullmatch(r"[0-9]+", host):
        digits, base = host, 10
    else:
        return None
    significant = digits.lstrip("0") or "0"
    if len(significant) > 12:
        return 1 << 32
    return int(significant, base)


def _one_number(host: str) -> ipaddress.IPv4Address | None:
    """``host`` as an IPv4 address written as one number; ``None`` for any other text.

    A number past 32 bits is no address, and no service's name either: it is
    left to be read as a name nothing here places.
    """
    value = _number(host)
    return ipaddress.IPv4Address(value) if value is not None and value <= 0xFFFFFFFF else None


def normal_host(host: object) -> str:
    """``host`` lowercased, without IPv6 brackets, a zone or a trailing dot."""
    text = str(host or "").strip().lower()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    return text.split("%", 1)[0].rstrip(".")


def host_of(url: object) -> str:
    """The host an address names, normalised; ``""`` when it names none.

    A value with no scheme (``box:8080``) is read as an address without one.
    Only the host is kept: never the userinfo, the port, the path or the
    query, so nothing a reader may not see travels with it.
    """
    text = str(url or "").strip()
    if not text:
        return ""
    if "://" not in text:
        text = "//" + text
    try:
        return normal_host(urlsplit(text).hostname or "")
    except ValueError:
        return ""


def host_locality(host: object) -> str:
    """:data:`LOCAL`, :data:`REMOTE` or :data:`UNKNOWN` for one host, from its text alone."""
    name = normal_host(host)
    if not name:
        return UNKNOWN
    literal: ipaddress.IPv4Address | ipaddress.IPv6Address | None
    try:
        literal = ipaddress.ip_address(name)
    except ValueError:
        literal = _one_number(name)
    if literal is not None:
        return LOCAL if local_address(literal) else REMOTE
    if named_locally(name) or service_name(name):
        return LOCAL
    return REMOTE
