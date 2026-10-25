"""A model's endpoint prints as configured where the run's own record says so, on any machine.

A run records a model as ``<model> @ <label>``; a rate line prints the label
undefanged only where the run's settings configured that endpoint. The labels
are kept in the run's disclosure record when it is built
(``disclosure.endpoint_labels``), as its addressed hosts are, so a stored
report renders the same wherever it is rendered: the process's settings are
never read. A record kept before the labels were keeps no endpoint, which is
how such a run rendered where no model endpoint was configured. A label is a
scheme, a host and a port: no credential, path or query reaches the record.
The labels and the addressed hosts are read off the job's own settings, by the
function that writes a model's label, so a key whose text a host holds
(``ollama`` beside ``http://ollama:11434``) does not mask that host in the
record as the snapshot's secret scrub does.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from maljan.analysis.disclosure import addressed_hosts, disclosure_record, endpoint_labels
from maljan.core.config import Settings
from maljan.core.model_assignments import assignment_chain_for
from maljan.core.settings_overrides import public_snapshot
from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity
from maljan.reporting.renderers.markdown import MarkdownRenderer
from tests.credential_shapes import password

# Built at run time: a credential written down is a secret to a scanner.
PW = password()
KEY = password(10, variant=1)
LABEL = "http://127.0.0.1:8080"
RATE_LINE = f"Generation rate of `local/x @ {LABEL}`"


def _snapshot() -> tuple[Settings, dict]:
    settings = Settings.model_validate(
        {
            "llm": {
                "provider": "openai",
                "openai": {"base_url": f"http://user:{PW}@127.0.0.1:8080/v1?api_key={KEY}"},
                "agents": {
                    "static": {
                        "provider": "openai",
                        "model": "q",
                        "base_url": f"https://u:{PW}@llm.example.org:8443/v1?token={KEY}",
                        "fallbacks": [{"provider": "anthropic", "model": "claude-haiku-5-5"}],
                    }
                },
            }
        }
    )
    return settings, public_snapshot(settings, ())


def _report(disclosure: dict | None) -> MalwareReport:
    summary: dict = {
        "final_decision": "Malware",
        "generation": {"models": {f"local/x @ {LABEL}": {"tokens_per_second": 10.0, "tokens": 10}}},
    }
    if disclosure is not None:
        summary["disclosure"] = disclosure
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        run_summary=summary,
        generated_at=datetime(2026, 9, 1, tzinfo=UTC),
    )


def test_the_record_keeps_every_label_the_run_records_its_models_under() -> None:
    settings, snapshot = _snapshot()

    record = disclosure_record(snapshot, agents=["static"])

    assert record["endpoint_labels"] == endpoint_labels(snapshot)
    assert {LABEL, "https://llm.example.org:8443"} <= set(record["endpoint_labels"])
    recorded = {
        choice.label.rpartition(" @ ")[2]
        for agent in ("static", "judge")
        for choice in assignment_chain_for(settings, agent)
        if " @ " in choice.label
    }
    assert recorded <= set(record["endpoint_labels"])
    # A vendor API's own name is no address.
    assert all("://" in label for label in record["endpoint_labels"])


def test_no_credential_path_or_query_reaches_the_labels() -> None:
    _settings, snapshot = _snapshot()

    held = json.dumps(endpoint_labels(snapshot))

    assert PW not in held and KEY not in held
    assert "/v1" not in held and "token" not in held and "user" not in held


def test_a_label_the_record_keeps_prints_as_configured() -> None:
    markdown = MarkdownRenderer().render(_report({"endpoint_labels": [LABEL]}))

    assert RATE_LINE in markdown


@pytest.mark.parametrize("disclosure", [None, {}, {"endpoint_labels": None}, {"addressed": []}])
def test_a_record_without_the_labels_keeps_no_endpoint(disclosure: dict | None) -> None:
    markdown = MarkdownRenderer().render(_report(disclosure))

    assert RATE_LINE not in markdown
    assert "Generation rate of `local/x @ hxxp://127[.]0[.]0[.]1:8080`" in markdown


@pytest.mark.parametrize("disclosure", [None, {"endpoint_labels": [LABEL]}])
def test_the_render_never_reads_the_process_settings(
    monkeypatch: pytest.MonkeyPatch, disclosure: dict | None
) -> None:
    from maljan.core import config

    before = MarkdownRenderer().render(_report(disclosure))

    def _refused() -> None:
        raise AssertionError("the renderer read the process's settings")

    monkeypatch.setattr(config, "get_settings", _refused)
    after = MarkdownRenderer().render(_report(disclosure))

    # Each render draws its own tokens, which never print; the text is the same.
    assert after == before


# A key whose text the endpoint's host holds: the snapshot's secret scrub masks
# it there (``http://***:11434``), the label a run records keeps it.
_KEY_IN_THE_HOST = [
    ("ollama", "http://ollama:11434/v1"),
    ("llama", "http://llama:8080/v1"),
    ("local", "http://localhost:8080/v1"),
]


def _run_record(api_key: str, base_url: str) -> tuple[Settings, dict]:
    from types import SimpleNamespace

    from maljan.analysis.disclosure import run_disclosure
    from maljan.core.settings_overrides import build_settings

    settings = build_settings(
        {
            "llm.provider": "openai",
            "llm.openai.api_key": api_key,
            "llm.openai.base_url": base_url,
            "llm.agents": {"static": {"provider": "openai", "model": "q", "base_url": base_url}},
        }
    )
    record = run_disclosure(SimpleNamespace(config=settings), entries=[], tokens=None)
    assert record is not None
    return settings, record


@pytest.mark.parametrize(("api_key", "base_url"), _KEY_IN_THE_HOST)
def test_every_label_the_run_records_is_kept_whatever_the_key_says(
    api_key: str, base_url: str
) -> None:
    from maljan.core.host_locality import host_of

    settings, record = _run_record(api_key, base_url)

    recorded = {
        choice.label.rpartition(" @ ")[2]
        for agent in ("static", "judge")
        for choice in assignment_chain_for(settings, agent)
        if " @ " in choice.label
    }
    assert recorded and recorded <= set(record["endpoint_labels"])
    assert not any("***" in label for label in record["endpoint_labels"])
    # The scrubbed snapshot would have lost it.
    assert not recorded <= set(endpoint_labels(public_snapshot(settings, ())))
    # A host the settings address is kept as written too, which the scrub also lost.
    assert host_of(base_url) not in addressed_hosts(public_snapshot(settings, ()))
    assert host_of(base_url) in record["addressed"]
    assert not any("***" in host for host in record["addressed"])


@pytest.mark.parametrize(("api_key", "base_url"), _KEY_IN_THE_HOST)
def test_a_rate_line_of_such_an_endpoint_prints_as_configured(api_key: str, base_url: str) -> None:
    settings, record = _run_record(api_key, base_url)
    (label,) = {
        choice.label for choice in assignment_chain_for(settings, "static") if " @ " in choice.label
    }
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        run_summary={
            "disclosure": record,
            "generation": {"models": {label: {"tokens_per_second": 10.0, "tokens": 10}}},
        },
        generated_at=datetime(2026, 9, 1, tzinfo=UTC),
    )

    assert f"Generation rate of `{label}`" in MarkdownRenderer().render(report)
