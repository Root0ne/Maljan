"""Which certificate in an Authenticode blob belongs to the publisher.

A signed PE carries a PKCS#7 ``SignedData`` whose ``certificates`` set holds
the signer's chain *and*, whenever the file was timestamped, the timestamp
authority's chain as well. So the set normally has two leaves, and picking
"the certificate that issued none of the others" picks whichever of them the
producer happened to write first. Measured over the local corpus: one signed
binary in four came back naming a timestamp authority as its publisher — a
deterministic fact in the pack, citable, and wrong.

The publisher is the certificate the ``SignerInfo`` names, by issuer and
serial number. That is a fact in the blob rather than a guess about it, so it
is asked first; the reader below is a small definite-length DER walk because
``cryptography`` exposes the certificates but not the ``SignerInfo``.

When the blob cannot be walked, the extended key usage decides: among the
leaves, the one that carries code signing and not time stamping. When neither
settles it, this module answers ``None`` and the caller states no publisher at
all, because a name that might be the timestamp authority's is worse than no
name.
"""

from __future__ import annotations

from typing import Any

# The two extended key usages that tell a publisher's certificate from a
# timestamp authority's.
_CODE_SIGNING = "1.3.6.1.5.5.7.3.3"
_TIME_STAMPING = "1.3.6.1.5.5.7.3.8"

_SEQUENCE = 0x30
_SET = 0x31
_INTEGER = 0x02
_CONTEXT_0 = 0xA0

# Ceilings on the walk. A SignedData has a handful of fields and a certificate
# set of a few dozen; anything past these is malformed or hostile, and this
# runs over an untrusted file.
_MAX_CHILDREN = 64
_MAX_LENGTH_BYTES = 4


def _read(blob: bytes, at: int, end: int) -> tuple[int, int, int, int] | None:
    """One definite-length TLV: ``(tag, start, content_start, content_end)``."""
    if at >= end:
        return None
    tag = blob[at]
    cursor = at + 1
    if cursor >= end:
        return None
    first = blob[cursor]
    cursor += 1
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        if count == 0 or count > _MAX_LENGTH_BYTES or cursor + count > end:
            return None
        length = int.from_bytes(blob[cursor : cursor + count], "big")
        cursor += count
    if cursor + length > end:
        return None
    return tag, at, cursor, cursor + length


def _children(
    blob: bytes, start: int, end: int, limit: int = _MAX_CHILDREN
) -> list[tuple[int, int, int, int]]:
    """Every TLV directly inside ``[start, end)``, bounded."""
    out: list[tuple[int, int, int, int]] = []
    at = start
    while at < end and len(out) < limit:
        node = _read(blob, at, end)
        if node is None:
            break
        out.append(node)
        at = node[3]
    return out


def signer_identifier(der: bytes) -> tuple[bytes, int] | None:
    """The first ``SignerInfo``'s issuer name (whole DER TLV) and serial number.

    ``None`` when the blob is not a definite-length ``SignedData``, when the
    signer is identified by subject key identifier instead (a v3 ``SignerInfo``,
    which Authenticode does not use), or when anything along the path is
    malformed.
    """
    outer = _read(der, 0, len(der))
    if outer is None or outer[0] != _SEQUENCE:
        return None
    # ContentInfo: the signedData OID, then [0] EXPLICIT SignedData.
    explicit = next((c for c in _children(der, outer[2], outer[3]) if c[0] == _CONTEXT_0), None)
    if explicit is None:
        return None
    signed = _read(der, explicit[2], explicit[3])
    if signed is None or signed[0] != _SEQUENCE:
        return None
    # SignedData ends with signerInfos, the last SET among its fields; the
    # first SET is digestAlgorithms and the optional [0]/[1] are tagged.
    sets = [f for f in _children(der, signed[2], signed[3]) if f[0] == _SET]
    if len(sets) < 2:
        return None
    infos = _children(der, sets[-1][2], sets[-1][3], limit=1)
    if not infos or infos[0][0] != _SEQUENCE:
        return None
    fields = _children(der, infos[0][2], infos[0][3], limit=3)
    if len(fields) < 2 or fields[1][0] != _SEQUENCE:
        return None
    issuer_and_serial = _children(der, fields[1][2], fields[1][3], limit=2)
    if len(issuer_and_serial) < 2:
        return None
    issuer, serial = issuer_and_serial
    if issuer[0] != _SEQUENCE or serial[0] != _INTEGER:
        return None
    return der[issuer[1] : issuer[3]], int.from_bytes(
        der[serial[2] : serial[3]], "big", signed=True
    )


def _extended_key_usages(certificate: Any) -> set[str]:
    try:
        from cryptography import x509

        extension = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        return {usage.dotted_string for usage in extension.value}
    except Exception:  # noqa: BLE001 — a certificate with no EKU simply says nothing
        return set()


def _leaves(certificates: list[Any]) -> list[Any]:
    """The certificates in the bundle that issued none of the others.

    A self-issued certificate names itself as its own issuer, and counting
    that would make every self-signed certificate look like somebody's
    authority and leave the bundle with no leaves at all.
    """
    issuers = {c.issuer for c in certificates if c.issuer != c.subject}
    return [c for c in certificates if c.subject not in issuers]


def publisher_certificate(der: bytes, certificates: list[Any]) -> Any | None:
    """The certificate that signed the file, or ``None`` when nothing decides.

    ``None`` is a real answer and the caller must treat it as one: no subject,
    no issuer, no thumbprint. A timestamp authority is never the publisher, and
    naming one would put a wrong fact where a reader can cite it.
    """
    if not certificates:
        return None
    named = signer_identifier(der)
    if named is not None:
        issuer_der, serial = named
        for certificate in certificates:
            try:
                if certificate.serial_number != serial:
                    continue
                if certificate.issuer.public_bytes() == issuer_der:
                    return certificate
            except Exception:  # noqa: BLE001 — an unreadable name is not a match
                continue
    signing = [
        certificate
        for certificate in _leaves(certificates)
        if _CODE_SIGNING in (usages := _extended_key_usages(certificate))
        and _TIME_STAMPING not in usages
    ]
    if len(signing) == 1:
        return signing[0]
    return None
