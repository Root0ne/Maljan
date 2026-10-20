"""No ``addr:None`` and no "0 bytes" where the run recorded neither (RC-19)."""

from __future__ import annotations

from maljan.reporting.evidence_bundles import _carved_line, _endpoint
from maljan.reporting.models import NetworkIP


def test_an_address_with_no_port_is_the_bare_address() -> None:
    assert _endpoint(NetworkIP(address="203.0.113.7")) == "203.0.113.7"
    assert _endpoint(NetworkIP(address="203.0.113.7", port=443)) == "203.0.113.7:443"


def test_a_payload_with_no_size_states_none() -> None:
    assert _carved_line({"id": "r1", "type": "PE", "sha256": "ab"}) == "r1 (PE, sha256 ab)"
    assert _carved_line({"id": "r1", "type": "PE", "size": 0, "sha256": "ab"}) == (
        "r1 (PE, 0 bytes, sha256 ab)"
    )
