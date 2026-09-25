"""A value an analyst kept is kept however the analyst wrote it.

A sandbox address the sample's tree did not make is published when a model
keeps it as an indicator. "Kept" used to be one exact row shape —
``["ip", address]`` in an ``endpoints``, ``network`` or ``iocs`` artifact — so a
C2 kept with its port, under ``ipv4``, in an ``Address | Port`` table, in a
``c2`` artifact, or inside a URL stayed ``no:``. Each such shape now keeps it,
and so does the host of a URL the judge kept.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from maljan.reporting.ledger_projection import kept_network_values, network_from_ledger
from maljan.reporting.models import JudgeIndicator, MalwareReport
from maljan.reporting.renderers.stix_renderer import emulation_kwargs, publish_answer
from maljan.schemas.evidence import build_entry
from maljan.schemas.isr_models import AgentISR, Artifact

CONTACT = "185.199.108.153"
CONTACT_V6 = "2a00:1450:4001:82b::200e"


def _ledger(address: str) -> list[Any]:
    return [
        build_entry(
            entry_id="ev_0001",
            seq=1,
            agent="dynamic",
            tool="sandbox_network",
            args={},
            server=None,
            output=json.dumps({"tcp": [{"dst": address, "dport": 443}]}),
        )
    ]


def _answer(artifact: Artifact | None, address: str = CONTACT, **extra: Any) -> str:
    isrs = (
        {"network": AgentISR(agent_id="network", domain="network", artifacts=[artifact])}
        if artifact
        else {}
    )
    network = network_from_ledger(_ledger(address), isrs)
    assert network is not None
    report = MalwareReport.model_validate(
        {
            "identity": {"hashes": {"sha256": "a" * 64}},
            "verdict": "Malware",
            "overall_confidence": 0.9,
            "network": network.model_dump(),
            **extra,
        }
    )
    return publish_answer("ip", address, "sandbox", None, **emulation_kwargs(report, "ip", address))


@pytest.mark.parametrize(
    "artifact",
    [
        Artifact(kind="endpoints", rows=[["ip", CONTACT]]),
        Artifact(kind="endpoints", rows=[["ip", f"{CONTACT}:443"]]),
        Artifact(kind="endpoints", rows=[["ipv4", CONTACT]]),
        Artifact(kind="endpoints", rows=[[CONTACT, "ip"]]),
        Artifact(kind="endpoints", columns=["Address", "Port"], rows=[[CONTACT, "443"]]),
        Artifact(kind="c2", rows=[["ip", CONTACT]]),
        Artifact(kind="network_iocs", rows=[["address", CONTACT]]),
        Artifact(kind="endpoints", rows=[["url", f"http://{CONTACT}/gate.php"]]),
        Artifact(kind="c2", value=f"{CONTACT}:8443"),
        Artifact(kind="notes", rows=[["ip", CONTACT]]),
    ],
    ids=[
        "ip",
        "ip-with-port",
        "ipv4-alias",
        "value-first",
        "address-port-table",
        "c2-kind",
        "network-iocs-kind",
        "url-host",
        "single-value",
        "typed-row-in-any-kind",
    ],
)
def test_each_shape_keeps_the_address(artifact: Artifact) -> None:
    assert _answer(artifact) == "yes"


def test_an_ipv6_address_in_bracket_form_with_its_port_is_kept() -> None:
    artifact = Artifact(kind="endpoints", rows=[["ipv6", "[2A00:1450:4001:82B::200E]:443"]])

    assert _answer(artifact, CONTACT_V6) == "yes"


def test_the_host_of_a_url_the_judge_kept_is_kept() -> None:
    answer = _answer(
        None,
        judge_indicators=[JudgeIndicator(kind="url", value=f"http://{CONTACT}/gate.php")],
    )

    assert answer == "yes"


def test_nothing_is_kept_without_a_model() -> None:
    assert _answer(None).startswith("no: ")


def test_a_table_of_imports_keeps_no_host() -> None:
    artifact = Artifact(
        kind="imports", columns=["Library", "Function"], rows=[["KERNEL32.dll", "CreateMutexW"]]
    )

    assert kept_network_values(artifact) == []


def test_a_kind_that_only_spells_ip_inside_a_word_is_not_a_network_table() -> None:
    artifact = Artifact(kind="scripts", rows=[["stage.ps1", "relay-alpha-7f3c.top"]])

    assert kept_network_values(artifact) == []


def test_a_file_name_in_a_network_table_is_not_a_host() -> None:
    artifact = Artifact(kind="network", rows=[["payload.dll", "relay-alpha-7f3c.top"]])

    assert kept_network_values(artifact) == [("domain", "relay-alpha-7f3c.top")]


def test_a_well_known_host_is_not_kept_through_a_url_on_it() -> None:
    artifact = Artifact(kind="endpoints", rows=[["url", "https://www.googleapis.com/x"]])

    assert kept_network_values(artifact) == [("url", "https://www.googleapis.com/x")]
