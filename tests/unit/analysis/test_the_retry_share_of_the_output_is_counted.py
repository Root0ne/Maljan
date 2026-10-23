"""The validation retries' and drops questions' share of each agent's output is counted.

The token ledger keeps each agent's calls by the name each call was made
under, outside its snapshot so the summary's token block is unchanged. The
efficiency record takes each agent's totals from the summary's own ``tokens``
block, and from the ledger only the split by call name, so the two state one
set of numbers; an agent with no name has no row.
"""

from __future__ import annotations

from types import SimpleNamespace

from maljan.analysis.efficiency import efficiency_lines, efficiency_record, output_record
from maljan.analysis.run_summary import spend_blocks
from maljan.core.token_ledger import (
    RETRY_DROPS_QUESTION_CALL,
    VALIDATION_RETRY_CALL,
    WHOLE_ANSWER_RETRY_CALL,
    TokenLedger,
)


def _ledger() -> TokenLedger:
    ledger = TokenLedger()
    ledger.add({"input_tokens": 100, "output_tokens": 700}, agent="static", call="tool loop turn")
    ledger.add(
        {"input_tokens": 50, "output_tokens": 200}, agent="static", call=VALIDATION_RETRY_CALL
    )
    ledger.add(None, agent="static", call=WHOLE_ANSWER_RETRY_CALL)
    ledger.add(
        {"input_tokens": 9, "output_tokens": 100}, agent="static", call=RETRY_DROPS_QUESTION_CALL
    )
    ledger.add({"input_tokens": 9, "output_tokens": 40}, agent="judge", call="verdict")
    ledger.add({"input_tokens": 1, "output_tokens": 1}, agent="", call=VALIDATION_RETRY_CALL)
    return ledger


def _tokens(ledger: TokenLedger) -> dict:
    return spend_blocks(ledger.snapshot())["tokens"]


def _container(ledger: TokenLedger) -> SimpleNamespace:
    return SimpleNamespace(get_token_ledger=lambda: ledger)


def test_the_ledger_keeps_calls_by_name_outside_its_snapshot() -> None:
    ledger = _ledger()

    assert ledger.by_call()["static"][VALIDATION_RETRY_CALL] == {
        "calls": 1,
        "unreported_calls": 0,
        "input_tokens": 50,
        "output_tokens": 200,
    }
    assert ledger.by_call()["static"][WHOLE_ANSWER_RETRY_CALL]["unreported_calls"] == 1
    assert "by_call" not in ledger.snapshot()
    assert not any("by_call" in row for row in ledger.snapshot()["agents"].values())


def test_each_agent_s_output_and_the_two_shares() -> None:
    ledger = _ledger()
    record = output_record(_container(ledger), _tokens(ledger))

    assert record == {
        "judge": {
            "calls": 1,
            "unreported_calls": 0,
            "output_tokens": 40,
            "retry": {"calls": 0, "unreported_calls": 0, "output_tokens": 0},
            "drop_question": {"calls": 0, "unreported_calls": 0, "output_tokens": 0},
        },
        "static": {
            "calls": 4,
            "unreported_calls": 1,
            "output_tokens": 1000,
            "retry": {"calls": 2, "unreported_calls": 1, "output_tokens": 200},
            "drop_question": {"calls": 1, "unreported_calls": 0, "output_tokens": 100},
        },
    }


def test_the_report_line_names_an_agent_that_was_asked_again() -> None:
    ledger = _ledger()
    record = efficiency_record(_container(ledger), tokens=_tokens(ledger))
    assert record is not None

    assert efficiency_lines(record) == [
        "Output of `static`: of its 1,000 reported output tokens, validation retries 200 "
        "(20%, 2 calls, 1 of them reporting no usage) and drops questions 100 (10%, 1 call); "
        "1 call of the agent's reported no usage."
    ]


def test_a_run_never_asked_again_says_so() -> None:
    ledger = TokenLedger()
    ledger.add({"input_tokens": 1, "output_tokens": 2}, agent="static", call="tool loop turn")
    record = efficiency_record(_container(ledger), tokens=_tokens(ledger))
    assert record is not None

    assert efficiency_lines(record) == [
        "Output: no validation retry and no drops question was asked."
    ]


def test_the_totals_are_the_summary_s_own_figures() -> None:
    ledger = _ledger()
    tokens = _tokens(ledger)
    record = output_record(_container(ledger), tokens)
    assert record is not None

    for agent, row in record.items():
        stated = tokens["per_agent"][agent]
        assert (row["calls"], row["output_tokens"]) == (
            stated["llm_calls"],
            stated["output_tokens"],
        )
    assert "" not in record


def test_no_tokens_block_is_no_part() -> None:
    assert output_record(SimpleNamespace()) is None
    assert output_record(_container(_ledger()), None) is None
