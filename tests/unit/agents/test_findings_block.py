"""The optional structured channel: parsed, stripped, and never trusted blindly."""

from __future__ import annotations

from maljan.agents.findings_block import parse_findings_block

_VALID = """Here is what I found.

CLAIM: The sample allocates memory in a remote process
EVIDENCE: import KERNEL32.dll!VirtualAllocEx
CONFIDENCE: 0.8
TECHNIQUE: T1055
---

```maljan-findings
{"artifacts": [{"kind": "imports", "label": "Suspicious imports",
  "columns": ["Library", "Function"],
  "rows": [["KERNEL32.dll", "VirtualAllocEx"]],
  "evidence_ids": ["ev_0002"]}],
 "findings": [{"title": "Allocates memory in a remote process",
  "technique_ids": ["T1055"], "confidence": 0.8, "evidence_ids": ["ev_0002"]}]}
```
"""


class TestValidBlock:
    def test_findings_and_artifacts_are_parsed(self) -> None:
        block = parse_findings_block(_VALID)
        assert len(block.findings) == 1
        assert block.findings[0].title == "Allocates memory in a remote process"
        assert block.findings[0].evidence_ids == ["ev_0002"]
        assert len(block.artifacts) == 1
        assert block.artifacts[0].kind == "imports"
        assert block.artifacts[0].rows == [["KERNEL32.dll", "VirtualAllocEx"]]
        assert block.dropped == 0

    def test_the_block_is_stripped_from_the_prose(self) -> None:
        block = parse_findings_block(_VALID)
        assert "maljan-findings" not in block.prose
        assert "VirtualAllocEx" in block.prose  # the ISR evidence line survives
        assert block.prose.rstrip().endswith("---")


class TestInvalidItems:
    def test_an_item_that_does_not_validate_is_dropped_and_counted(self) -> None:
        text = (
            "prose\n\n```maljan-findings\n"
            '{"findings": [{"title": "kept"}, {"detail": "no title"}, "not an object"]}\n'
            "```"
        )
        block = parse_findings_block(text)
        assert [f.title for f in block.findings] == ["kept"]
        assert block.dropped == 2

    def test_a_block_that_is_not_json_is_dropped_whole(self) -> None:
        text = "prose\n\n```maljan-findings\nnot json at all\n```"
        block = parse_findings_block(text)
        assert block.findings == []
        assert block.artifacts == []
        assert block.dropped == 1
        assert "maljan-findings" not in block.prose

    def test_a_block_holding_a_list_is_dropped(self) -> None:
        block = parse_findings_block('x\n\n```maljan-findings\n[{"title": "a"}]\n```')
        assert block.findings == []
        assert block.dropped == 1


class TestNoBlock:
    def test_an_answer_without_a_block_is_returned_untouched(self) -> None:
        text = "CLAIM: something\nEVIDENCE: somewhere\nCONFIDENCE: 0.5\n"
        block = parse_findings_block(text)
        assert block.prose == text
        assert block.findings == []
        assert block.artifacts == []
        assert not block

    def test_empty_input_is_safe(self) -> None:
        assert parse_findings_block("").prose == ""


class TestAgentPlumbing:
    def test_the_analyst_drains_the_block_onto_its_isr(self) -> None:
        from maljan.agents.base_agent import BaseAnalyst
        from maljan.schemas.isr_models import AgentISR

        class _Stub(BaseAnalyst):
            def analyze(self, data: str) -> str:  # pragma: no cover - unused
                return ""

            def revise(  # pragma: no cover - unused
                self,
                original_data: str,
                own_report: str,
                peer_reports: dict[str, str],
                mediator_feedback: str,
            ) -> str:
                return ""

        agent = _Stub(llm=None, name="static")  # type: ignore[arg-type]
        prose = agent._capture_findings(_VALID)
        assert "maljan-findings" not in prose

        isr = agent._drain_findings(AgentISR(agent_id="static", domain="static"))
        assert len(isr.findings) == 1
        assert len(isr.artifacts) == 1
        # Drained once: a second ISR does not inherit the first one's channel.
        second = agent._drain_findings(AgentISR(agent_id="static", domain="static"))
        assert second.findings == []
        assert second.artifacts == []


class TestPrompts:
    def test_every_built_in_analyst_is_told_about_the_channel(self) -> None:
        from maljan.agents.dynamic_analyst import _DYN_TAIL
        from maljan.agents.network_analyst import _NET_TAIL
        from maljan.agents.prompt_fragments import FINDINGS_BLOCK_FRAGMENT
        from maljan.agents.static_analyst import _ISR_TAIL

        for tail in (_ISR_TAIL, _DYN_TAIL, _NET_TAIL):
            assert tail == FINDINGS_BLOCK_FRAGMENT
            assert "maljan-findings" in tail
            assert "ev_0007" in tail
