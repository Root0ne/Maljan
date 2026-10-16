"""Whether a host is this machine's, read from the host as written and nothing else.

One rule, written once, for every reader that has to say where something
went: the run's disclosure block (``analysis.disclosure``) classifies every
model endpoint, tool server, lookup service and sandbox it names by it, and
the analyst-mode decision (``pipeline.analyst_mode``) reads the same address
and name rules before it resolves a name.

A host is **local** when the text alone establishes it:

* an address literal in one of the networks written out in
  :data:`LOCAL_NETWORKS`: loopback, the private ranges (RFC 1918 and the IPv6
  unique local range), link-local, the shared range (RFC 6598) and the two
  unspecified addresses. An address of a transition range that carries an
  IPv4 address — IPv4-mapped, 6to4, Teredo, NAT64 in its well-known and its
  local-use prefix — is read as the IPv4 address it carries, since that is
  where it routes;
* a name only a local resolver answers: ``localhost``, a container runtime's
  name for the host it runs on (``host.docker.internal`` and its kin), and
  any name under ``.localhost``, ``.local`` or ``.internal``;
* a single label with no dot and no trailing dot: the name a compose network
  gives a service. This one is an assumption, not a fact: a resolver's search
  domains expand a single label, and a top-level domain may answer one, so a
  reader is told when a host was taken as local on it
  (:func:`taken_as_service_name`). A label of digits alone (``2130706433``,
  ``0x7f000001``) is an address written as one number, as the system's
  address parser reads it, and is classified as that address.

Any other host is **remote**: a public address, an address of any other
reserved range, or a dotted name the text cannot place, taken as reaching
beyond this machine because nothing here resolves it. Resolving would make
the answer depend on the resolver of whichever process asks, and a stored run
would read differently next week. An address with no host in it, or one too
malformed to name one, is **unknown**, never local.

``ipaddress.is_private`` is not used: it also answers "private" for ranges
that route to public IPv4 addresses (6to4, Teredo, local-use NAT64) and for
documentation and reserved ranges, which is the cautious answer for a filter
of outgoing requests and the wrong one for a record that says "local".
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

# The networks an address literal is local in, written out.
LOCAL_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = tuple(
    ipaddress.ip_network(network)
    for network in (
        "127.0.0.0/8",  # loopback
        "10.0.0.0/8",  # RFC 1918
        "172.16.0.0/12",  # RFC 1918
        "192.168.0.0/16",  # RFC 1918
        "169.254.0.0/16",  # link-local
        "100.64.0.0/10",  # shared address space (RFC 6598)
        "0.0.0.0/32",  # unspecified
        "::1/128",  # loopback
        "::/128",  # unspecified
        "fe80::/10",  # link-local
        "fc00::/7",  # unique local
    )
)
# The transition ranges whose addresses carry an IPv4 address.
_NAT64_WELL_KNOWN = ipaddress.ip_network("64:ff9b::/96")
_NAT64_LOCAL_USE = ipaddress.ip_network("64:ff9b:1::/48")
# The local-use NAT64 prefix carries the IPv4 address in its last 32 bits only
# where it is used as a /96: the other prefix lengths split the address around
# a reserved octet, and an address in them is not read as one.
_NAT64_LOCAL_USE_96 = ipaddress.ip_network("64:ff9b:1::/96")

# One DNS label: what a compose network names a service by.
_SERVICE_NAME = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")
# A host, with an optional port and path, written with no scheme (``box:8080``).
_BARE_HOST = re.compile(r"[^/:@\s\[\]]+(?::\d+)?(?:/.*)?|\[[0-9a-fA-F:.%]+\](?::\d+)?(?:/.*)?")


def carried_ipv4(address: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """The IPv4 address a transition-range address carries, or ``None`` for any other.

    IPv4-mapped (``::ffff:0:0/96``), 6to4 (``2002::/16``), Teredo
    (``2001::/32``, the client's address), NAT64's well-known prefix
    (``64:ff9b::/96``) and its local-use prefix used as a /96.
    """
    if address.ipv4_mapped is not None:
        return address.ipv4_mapped
    if address.sixtofour is not None:
        return address.sixtofour
    if address.teredo is not None:
        return address.teredo[1]
    if address in _NAT64_WELL_KNOWN or address in _NAT64_LOCAL_USE_96:
        return ipaddress.IPv4Address(int(address) & 0xFFFFFFFF)
    return None


def local_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Whether ``address`` is in :data:`LOCAL_NETWORKS`, a carried IPv4 address read as itself.

    An address of the local-use NAT64 prefix that is not a /96 address carries
    no IPv4 address this rule can read, and is not local.
    """
    if isinstance(address, ipaddress.IPv6Address):
        if address.scope_id:
            address = ipaddress.IPv6Address(int(address))
        carried = carried_ipv4(address)
        if carried is not None:
            address = carried
        elif address in _NAT64_LOCAL_USE:
            return False
    return any(
        address in network for network in LOCAL_NETWORKS if network.version == address.version
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
    """``host`` lowercased, without IPv6 brackets or a zone; a trailing dot is kept.

    The dot says the name is absolute, which decides whether a single label may
    be a service's name (:func:`host_locality`).
    """
    text = str(host or "").strip().lower()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    return text.split("%", 1)[0]


def host_of(url: object) -> str:
    """The host an address names, normalised; ``""`` when it names none.

    A value with no scheme (``box:8080``) is read as a host, a port and a path.
    A value that is neither an address with ``://`` nor such a host — ``http:/x/``
    or ``http:box:8080`` — is too malformed to name a host, and names none; so
    is one holding a backslash or white space, which parsers split differently
    (``http://a:80\\@b/`` names ``a`` to one and ``b`` to another). Only the
    host is kept: never the userinfo, the port, the path or the query, so
    nothing a reader may not see travels with it.
    """
    text = str(url or "").strip()
    if not text or re.search(r"[\\\s]", text):
        return ""
    if "://" not in text:
        if not _BARE_HOST.fullmatch(text):
            return ""
        text = "//" + text
    try:
        return normal_host(urlsplit(text).hostname or "")
    except ValueError:
        return ""


def _literal(name: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(name)
    except ValueError:
        return _one_number(name)


def taken_as_service_name(host: object) -> bool:
    """Whether ``host`` is local only by the assumption that a single label names a service."""
    raw = normal_host(host)
    name = raw.rstrip(".")
    if not name or raw.endswith(".") or _literal(name) is not None or named_locally(name):
        return False
    return service_name(name)


def host_locality(host: object) -> str:
    """:data:`LOCAL`, :data:`REMOTE` or :data:`UNKNOWN` for one host, from its text alone."""
    raw = normal_host(host)
    name = raw.rstrip(".")
    if not name:
        return UNKNOWN
    literal = _literal(name)
    if literal is not None:
        return LOCAL if local_address(literal) else REMOTE
    if named_locally(name):
        return LOCAL
    # An absolute single label (``ai.``) is a name in the public tree, never a
    # service's name.
    if not raw.endswith(".") and service_name(name):
        return LOCAL
    return REMOTE
