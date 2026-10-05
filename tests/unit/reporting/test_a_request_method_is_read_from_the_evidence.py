"""A URL's HTTP method is the one the evidence records, and absent when it records none.

Every URL row defaulted to ``GET``. A C2 URL the decoder read out of the
sample's bytes was printed "GET" in the IOC table beside a key whose beacon is
a POST: nothing in the run said GET, and the default contradicted the
sample. The method is now read from the sandbox request that carries it, and
a URL no request carries states none.
"""

from __future__ import annotations

import json
from typing import Any

from maljan.reporting.ledger_projection import network_from_ledger
from maljan.schemas.evidence import build_entry

POSTED = "http://beacon.example.com/gate"
READ_ONLY = "https://other.example.net/live/"


def _entry(seq: int, tool: str, payload: dict[str, Any]) -> Any:
    return build_entry(
        entry_id=f"ev_{seq:04d}",
        seq=seq,
        agent="static",
        tool=tool,
        args={},
        server="analysis",
        output=json.dumps(payload),
    )


def _urls() -> dict[str, Any]:
    network = network_from_ledger(
        [
            _entry(
                1,
                "sandbox_network",
                {
                    "http": [
                        {"host": "beacon.example.com", "uri": "/gate", "method": "POST"},
                        {"host": "plain.example.org", "uri": "/"},
                    ]
                },
            ),
            _entry(2, "iocs_from_file", {"iocs": [{"kind": "url", "value": READ_ONLY}]}),
        ]
    )
    assert network is not None
    return {row.url: row for row in network.urls}


def test_a_sandbox_request_states_its_own_method() -> None:
    assert _urls()[POSTED].method == "POST"


def test_a_request_that_records_no_method_states_none() -> None:
    assert _urls()["http://plain.example.org/"].method is None


def test_a_url_read_from_the_file_states_no_method() -> None:
    assert _urls()[READ_ONLY].method is None
