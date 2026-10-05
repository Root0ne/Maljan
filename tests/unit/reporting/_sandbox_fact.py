"""The run summary a judge leaves when it keeps an indicator after the sandbox's fact.

A value the sandbox attributes no flow of the sample to is the judge's only by
its answer to the question that told it so
(``validation.unattributed_indicator_violations``). A test whose judge keeps
such a value records that answer with this.
"""

from __future__ import annotations

from typing import Any

from maljan.pipeline.validation import UNATTRIBUTED_INDICATOR_CODE


def answered_the_sandbox_fact(*subjects: str) -> dict[str, Any]:
    """``run_summary`` with the judge's kept answer for each ``kind:value`` subject."""
    return {
        "validation": {
            "unresolved": [
                {
                    "agent": "judge",
                    "code": UNATTRIBUTED_INDICATOR_CODE,
                    "message": "kept",
                    "answered": "true",
                    "subject": subject,
                }
                for subject in subjects
            ]
        }
    }
