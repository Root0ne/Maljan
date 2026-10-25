"""Each degradation reason and each operator choice the report lists is on every surface (T-338).

A reason moved out of the degradations is not dropped: the checker looks for
every one in the Markdown and the HTML, for each choice in the run summary,
and fails a choice the header lists, where the DEGRADED RUN banner is.
"""

from __future__ import annotations

from typing import Any

from scripts.audit import surfaces

from tests.unit.scripts._surfaces_run import clean_run, clean_spec, defects

LOST = "server.analysis.capa_unavailable(capa is not installed)"
CHOSEN = "server.threatintel.check_hash_unavailable(VIRUSTOTAL_API_KEY is not configured)"


def _with_reasons(markdown_tail: str = "", *, head: str = "", summary: bool = True) -> Any:
    run = clean_run()
    mr = run["report_row"]["malware_report"]
    mr["degradation_reasons"] = [LOST]
    mr["operator_choices"] = [CHOSEN]
    if summary:
        run["run_summary"]["operator_choices"] = [CHOSEN]
        run["report_row"]["run_summary"]["operator_choices"] = [CHOSEN]
    title, rest = run["markdown"].split("\n", 1)
    run["markdown"] = f"{title}\n{head}{rest}\n## 13. Limitations\n{markdown_tail}"
    run["html"] = run["html"].replace(
        "</body>", "".join(f"<p>{line}</p>" for line in markdown_tail.split("\n")) + "</body>"
    )
    return run


_LISTED = f"- {LOST}\n**Not configured or withheld by choice:**\n- {CHOSEN}"


def test_every_listed_reason_found_is_clean() -> None:
    result = surfaces.audit(_with_reasons(_LISTED), clean_spec())
    assert defects(result) == []
    assert result["checked"]["degradation_reason"] == 2
    assert result["checked"]["operator_choice"] == 3


def test_a_choice_left_off_the_rendering_is_missing() -> None:
    result = surfaces.audit(_with_reasons(f"- {LOST}"), clean_spec())
    assert defects(result) == [
        ("missing", "operator_choice", "markdown"),
        ("missing", "operator_choice", "html"),
    ]


def test_a_choice_in_the_header_differs() -> None:
    result = surfaces.audit(_with_reasons(_LISTED, head=f"{CHOSEN}\n"), clean_spec())
    assert defects(result) == [("differs", "operator_choice", "markdown")]


def test_a_choice_the_run_summary_lacks_is_missing() -> None:
    result = surfaces.audit(_with_reasons(_LISTED, summary=False), clean_spec())
    assert defects(result) == [("missing", "operator_choice", "run_summary")]
