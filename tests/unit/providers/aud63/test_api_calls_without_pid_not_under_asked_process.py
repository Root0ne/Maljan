"""PS-L10: a flat API call with no pid is not listed under the process that was asked for."""

from __future__ import annotations

from maljan.providers.sandbox_tools import sandbox_api_calls


def test_a_pidless_call_is_left_out_of_a_process_view():
    report = {
        "behavior": {
            "processes": [{"pid": 4, "process_name": "a.exe"}],
            "calls": [
                {"api": "CreateFileW", "pid": 4},
                {"api": "WriteFile"},
            ],
        }
    }
    asked = sandbox_api_calls(report, process="a.exe")
    assert [row["api"] for row in asked["apis"]] == ["CreateFileW"]
    assert asked["left_out_without_pid"] == 1
    everything = sandbox_api_calls(report)
    assert {row["api"] for row in everything["apis"]} == {"CreateFileW", "WriteFile"}
    assert "left_out_without_pid" not in everything
