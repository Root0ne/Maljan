"""The attached report is fetched by owner, not fetched and then checked.

API-1 (dev audit 2026-09-06): the worker selected a sandbox report by id alone
and compared ``row.sample_id`` to the job's sample afterwards. The refusal was
correct, but the row of somebody else's sample was read out of the database
first, and a check that lives beside the query rather than inside it is one
edit away from being separated from it. The ownership is part of the question
now: a report that is not this sample's simply does not come back.
"""

from __future__ import annotations

import uuid

from app.worker.analysis_worker import attached_report_stmt


def test_the_query_names_both_the_report_and_its_sample():
    report_id = uuid.uuid4()
    sample_id = uuid.uuid4()
    compiled = str(
        attached_report_stmt(report_id, sample_id).compile(compile_kwargs={"literal_binds": True})
    )
    assert report_id.hex in compiled
    assert sample_id.hex in compiled
    assert "sandbox_reports.sample_id" in compiled
