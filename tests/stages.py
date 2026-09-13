"""Stage and profile shapes the pipeline tests build their doubles from.

A node is built from a stage now, and a graph is built from a profile, so a
``MagicMock`` container has to answer ``active_profile()`` with something real.
Written once here rather than in every test module: a test that invented its
own four-stage profile would be pinning this file's idea of the default rather
than the settings model's.
"""

from __future__ import annotations

from maljan.core.config import ProfileDefinition, StageDefinition, stages_from_analysts

# The stage a bare analyst node belongs to when the test is about the analyst
# rather than about the team.
ANALYSIS_STAGE = StageDefinition(key="analysis", kind="analysis", inject_upstream="none")


def paper_profile(analysts: list[str], *, parallel: bool = False) -> ProfileDefinition:
    """The four-stage form of ``analysts``, exactly as a stored profile converts."""
    return ProfileDefinition(
        label="test",
        stages=stages_from_analysts(analysts, parallel=parallel),
        analysts=list(analysts),
    )
