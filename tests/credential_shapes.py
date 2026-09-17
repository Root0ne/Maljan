"""The shapes a credential really arrives in, built rather than written down.

What the redaction tests need is the *shape* of a key — a vendor's prefix, a
run past the length floor, the standard base64 alphabet, three base64url
segments with dots between them — and a source line carrying that shape whole
is a secret as far as a scanner is concerned, however invented its characters
are. Every value here is assembled at call time from a prefix and a generated
body, so the assertions keep their exact meaning and no line of the suite
matches a detector.

Generated, not random: the same value on every run is what makes a failure
reproducible, and what is under test is the shape rather than the entropy.
"""

from __future__ import annotations

import base64
import string

# Lowercase letters and digits, which is the whole alphabet of the formats
# below. A stride of seven is coprime with the alphabet's length, so a body
# under thirty-six characters repeats nothing.
_ALPHABET = string.ascii_lowercase + string.digits
_STRIDE = 7


def lowercase_body(length: int = 32) -> str:
    """A run of lowercase letters and digits of exactly ``length``."""
    return "".join(_ALPHABET[(index * _STRIDE + 3) % len(_ALPHABET)] for index in range(length))


def prefixed_key(prefix: str, body_length: int = 32) -> str:
    """A vendor key: the format's own prefix, and a body of the right shape.

    The prefixes are the four lowercase formats that a shape test around "the
    keys this system issues are lowercase" let through — Mailgun's ``key-``,
    Google's ``gocspx-``, GitHub's ``ghs_`` — plus the bare run of a provider
    that uses no prefix at all.
    """
    return f"{prefix}{lowercase_body(body_length)}"


def lowercase_base64_blob(text: bytes = b"a very long secret value 1234567890") -> str:
    """A base64 run with no capitals in it, which is the hardest case to see.

    Encoded and then lower-cased: a real blob of this shape is what a config
    file or an API answer carries, and nothing but its length and its alphabet
    tells it apart from a sentence with no spaces.
    """
    return base64.b64encode(text).decode().lower().rstrip("=")


def standard_base64_key(payload: bytes = bytes(range(200, 230))) -> str:
    """A run in the *standard* base64 alphabet, carrying a ``+`` and a ``/``.

    Those two characters are the whole point of the shape — a rule anchored to
    ``[A-Za-z0-9_-]`` reads the run as ending at the first of them — so the
    payload is chosen to produce both, and that is checked here rather than
    assumed by the caller.
    """
    encoded = base64.b64encode(payload).decode().rstrip("=")
    assert "+" in encoded and "/" in encoded, encoded
    return encoded


def _segment(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def jwt(header: bytes = b'{"alg":"HS256"}') -> str:
    """A JSON Web Token: three base64url segments joined at call time.

    The default header encodes to the ``eyJ`` every base64url-encoded ``{"``
    begins with, which is the prefix the rule looks for first. Pass a header
    whose JSON starts with anything else — a space after the brace — for a
    token that can only be recognised by decoding its head.
    """
    return ".".join(
        (
            _segment(header),
            _segment(b'{"sub":"1234567890","name":"a subject"}'),
            _segment(b"a signature of a plausible length for one"),
        )
    )
