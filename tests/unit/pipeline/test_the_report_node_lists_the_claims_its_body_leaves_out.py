"""The report node reads the composed body against the claims in force and lists what it leaves out.

Driven through the node, the way a run reaches it: a claim in force that the
body neither cites nor discusses is on the stored report, counted in its run
summary, and printed in the served markdown under its label.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from maljan.reporting.models import MalwareReport
from maljan.reporting.renderers import MarkdownRenderer
from maljan.schemas.isr_models import AgentISR, ClaimEvidence
from tests.stages import paper_profile
from tests.unit.pipeline.test_what_is_served_is_the_final_report import _state

CLAIM = "FUN_0x4a10 refuses to run on a host whose table length exceeds 0x600."


@pytest.fixture
def container() -> Any:
    fake = MagicMock()
    fake.agent_registry.list_agents.return_value = ["static"]
    fake.analyst_keys.return_value = ["static"]
    fake.agent_role.side_effect = lambda n: n
    fake.is_mock = False
    fake.config.reporting.enabled = True
    fake.config.llm.parallel_analysts = False
    fake.config.negotiation.max_iterations = 3
    fake.active_profile.return_value = paper_profile(["static"], parallel=False)
    fake.get_narrative_agent.return_value = None
    fake.get_report_composer.return_value = None
    fake.get_static_provider.return_value.capabilities.provides_evidence = False
    return fake


@pytest.mark.asyncio
async def test_a_claim_the_body_leaves_out_is_stored_counted_and_printed(container: Any) -> None:
    from maljan.pipeline.nodes import make_report_node

    state = _state()
    state["isr_reports"] = {
        "static": AgentISR(
            agent_id="static",
            domain="static",
            claims=[ClaimEvidence(claim=CLAIM, evidence_ref="[ev_0001]", confidence=0.8)],
        )
    }
    stage = next(step for step in container.active_profile().stages if step.kind == "report")
    node = make_report_node(container, stage=stage, announces=False)

    result = await node(state)  # type: ignore[arg-type]

    stored = MalwareReport.model_validate(result["malware_report"])
    (row,) = stored.claims_not_discussed
    assert (row.agent, row.claim_number, row.claim) == ("static", 1, CLAIM)
    assert stored.run_summary["claims_not_discussed"] == 1
    served = MarkdownRenderer().render(stored)
    assert "Claims whose code locations or API names the body does not name" in served
    assert "**static claim 1** (confidence 0.80; " in served
