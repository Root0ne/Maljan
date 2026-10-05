"""A step marked observed is observed whole, and a network step for its own value.

A local run's first execution step joined the rundll32 load the sandbox
watched to the hashing a static tool read, cited both, and kept "(observed in
sandbox)": the existing question asked only whether some sandbox entry was
cited. A step marked observed now has every entry it cites be a sandbox
observation, and a step that names an address, a host or a URL needs a flow
the sandbox attributes to the sample's process tree for that value. Otherwise
the composer is asked once; the mark stays the model's.
"""

from __future__ import annotations

import json
from typing import Any

from maljan.pipeline.validation import FLOW_VOICE_CODE, flow_voice_violations
from maljan.reporting.evidence_bundles import sample_flow_fact
from maljan.reporting.ledger_projection import network_from_ledger
from maljan.reporting.models import (
    FileHashes,
    MalwareReport,
    NetworkDomain,
    NetworkIOCs,
    NetworkIP,
    SampleIdentity,
)
from maljan.schemas.evidence import build_entry

TOOLS = {"ev_0012": "sandbox_processes", "ev_0020": "resolve_api_hashes"}
REACHED = "192.0.2.10"
BACKGROUND = "198.51.100.7"


def _step(action: str, refs: list[str], voice: str = "observed") -> dict[str, Any]:
    return {"steps": [{"order": 1, "action": action, "voice": voice, "evidence_refs": refs}]}


def _report() -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        network=NetworkIOCs(
            ips=[
                NetworkIP(address=REACHED, source="sandbox", sample_process_tree=True),
                NetworkIP(address=BACKGROUND, source="sandbox"),
            ],
            domains=[
                NetworkDomain(fqdn="gate.example.com", source="sandbox", resolved_ips=[REACHED]),
                NetworkDomain(fqdn="cdn.example.net", source="sandbox", resolved_ips=[BACKGROUND]),
            ],
        ),
    )


def _asked(payload: dict[str, Any], sandbox: list[str]) -> list[Any]:
    return flow_voice_violations(
        payload, sandbox, tools=TOOLS, flow_fact=sample_flow_fact(_report())
    )


def test_a_step_citing_a_static_entry_beside_the_sandbox_one_is_asked_about() -> None:
    (found,) = _asked(
        _step("Loads through rundll32 and resolves its imports by hash.", ["ev_0012", "ev_0020"]),
        ["ev_0012"],
    )

    assert found.code == FLOW_VOICE_CODE
    assert found.message.startswith("step 1 is marked observed")
    assert "ev_0020 (resolve_api_hashes)" in found.message
    assert "assessed" in found.message


def test_a_step_citing_only_sandbox_entries_is_not_asked_about() -> None:
    assert _asked(_step("Loads through rundll32.", ["ev_0012"]), ["ev_0012"]) == []


def test_an_address_the_sample_reached_stands_observed() -> None:
    assert _asked(_step(f"Connects to {REACHED} over TLS.", ["ev_0012"]), ["ev_0012"]) == []


def test_an_address_no_flow_of_the_sample_reached_is_asked_about_with_the_fact() -> None:
    (found,) = _asked(_step(f"Connects to {BACKGROUND} over TLS.", ["ev_0012"]), ["ev_0012"])

    assert BACKGROUND in found.message
    assert "does not say which process made the flows to it" in found.message


def test_a_host_that_resolved_to_the_reached_address_stands_observed() -> None:
    step = _step("Beacons to https://gate.example.com/in/ every minute.", ["ev_0012"])

    assert _asked(step, ["ev_0012"]) == []


def test_a_host_only_the_guest_reached_is_asked_about() -> None:
    (found,) = _asked(_step("Fetches from cdn.example.net.", ["ev_0012"]), ["ev_0012"])

    assert "cdn.example.net" in found.message


def test_a_defanged_value_is_read_as_the_value() -> None:
    (found,) = _asked(_step("Connects to 198.51.100[.]7.", ["ev_0012"]), ["ev_0012"])

    assert BACKGROUND in found.message


def test_an_assessed_step_is_not_asked_about() -> None:
    step = _step(f"Connects to {BACKGROUND}.", ["ev_0020"], voice="assessed")

    assert _asked(step, ["ev_0012"]) == []


def test_the_projection_states_what_a_name_resolved_to() -> None:
    entry = build_entry(
        entry_id="ev_0001",
        seq=1,
        agent="pipeline",
        tool="sandbox_network",
        args={},
        server="pipeline",
        output=json.dumps(
            {"dns": [{"request": "gate.example.com", "answers": [{"data": REACHED}]}]}
        ),
    )

    network = network_from_ledger([entry])

    assert network is not None
    (domain,) = network.domains
    assert domain.resolved_ips == [REACHED]


def test_a_step_numbered_zero_is_named_by_its_number() -> None:
    step = _step("Loads through rundll32 and resolves by hash.", ["ev_0012", "ev_0020"])
    step["steps"][0]["order"] = 0
    uncited = _step("Loads through rundll32.", [])
    uncited["steps"][0]["order"] = 0

    (mixed,) = _asked(step, ["ev_0012"])
    (bare,) = _asked(uncited, ["ev_0012"])

    assert mixed.message.startswith("step 0 is marked observed")
    assert bare.message.startswith("step 0 is marked observed")


def test_the_question_says_what_the_platform_knows_of_the_other_entries() -> None:
    (found,) = _asked(
        _step("Loads through rundll32 and resolves by hash.", ["ev_0012", "ev_0020"]),
        ["ev_0012"],
    )

    assert "which are not sandbox entries" in found.message


def test_a_step_with_both_problems_is_asked_both_in_one_round() -> None:
    found = _asked(
        _step(f"Resolves by hash and connects to {BACKGROUND}.", ["ev_0012", "ev_0020"]),
        ["ev_0012"],
    )

    assert len(found) == 2
    assert "not sandbox entries" in found[0].message
    assert BACKGROUND in found[1].message
