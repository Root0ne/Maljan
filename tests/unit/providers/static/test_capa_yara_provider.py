"""Evidence, not tools — and a missing library is a warning, not a failure."""

from __future__ import annotations

import builtins
import os
import sys
import time

import pytest

from maljan.core.config import Settings
from maljan.providers.static.capa_yara import CapaYaraStaticProvider
from maljan.tools import staging


def _provider(tmp_path=None):
    cfg = Settings(_env_file=None)
    cfg.static.provider = "capa_yara"
    if tmp_path is not None:
        cfg.static.capa.rules_dir = str(tmp_path)
        cfg.static.yara.rules_dir = str(tmp_path)
    return CapaYaraStaticProvider.from_settings(cfg)


def test_capabilities_are_evidence_only():
    caps = _provider().capabilities
    assert caps.provides_evidence is True
    assert caps.provides_tools is False
    assert caps.needs_sample_mirror is False, "capa and YARA read the host bytes in place"
    assert caps.degrade_on_failure is True


def test_a_missing_capa_lowers_the_capability_and_warns(monkeypatch, tmp_path, caplog):
    real_import = builtins.__import__

    def no_capa(name, *args, **kwargs):
        if name.startswith("capa"):
            raise ImportError("No module named 'capa'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_capa)
    provider = _provider(tmp_path)
    with caplog.at_level("WARNING"):
        bundle = provider.collect_evidence(str(tmp_path / "missing.exe"))
    assert bundle is None or bundle.api_capabilities == {}
    assert any("capa" in r.getMessage() for r in caplog.records)
    assert provider.capabilities.provides_evidence is False


def test_capa_results_become_capabilities_techniques_and_a_table(monkeypatch, tmp_path):
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 128)
    provider = _provider(tmp_path)
    monkeypatch.setattr(
        provider,
        "_run_capa",
        lambda path: {
            "rules": {
                "encrypt data using RC4": {
                    "meta": {
                        "namespace": "data-manipulation/encryption/rc4",
                        "attack": [{"id": "T1027", "technique": "Obfuscated Files or Information"}],
                    },
                    "matches": [[{"type": "absolute", "value": 4198400}, {}]],
                },
                "create process": {
                    "meta": {
                        "namespace": "host-interaction/process/create",
                        "attack": [{"id": "T1106", "technique": "Native API"}],
                    },
                    "matches": [[{"type": "absolute", "value": 4198500}, {}]],
                },
            }
        },
    )
    monkeypatch.setattr(provider, "_run_yara", lambda path: [])
    bundle = provider.collect_evidence(str(sample))
    assert bundle is not None
    ids = {hit["technique_id"] for hit in bundle.technique_hits}
    assert ids == {"T1027", "T1106"}
    # Same row shape the import-capability Layer 0 already writes into
    # ``api_technique_hits`` (analysis/import_capability_layer.py) and the
    # Markdown renderer reads (renderers/markdown.py): technique_id, name,
    # confidence, matched_apis — plus "source" as an extra, harmless key.
    by_id = {hit["technique_id"]: hit for hit in bundle.technique_hits}
    assert by_id["T1027"]["name"] == "encrypt data using RC4"
    assert by_id["T1027"]["matched_apis"] == ["data-manipulation/encryption/rc4"]
    # capa states that a rule matched, not a probability: no number is added.
    assert all("confidence" not in hit for hit in bundle.technique_hits)
    assert all(hit["source"] == "capa" for hit in bundle.technique_hits)
    assert "encrypt data using RC4" in bundle.technical_evidence["capa"]


def test_yara_hits_land_in_the_technical_evidence(monkeypatch, tmp_path):
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"MZ")
    provider = _provider(tmp_path)
    monkeypatch.setattr(provider, "_run_capa", lambda path: {"rules": {}})
    monkeypatch.setattr(
        provider, "_run_yara", lambda path: [{"rule": "ransom_note", "strings": ["$a at 0x40"]}]
    )
    bundle = provider.collect_evidence(str(sample))
    assert bundle is not None
    assert "ransom_note" in bundle.technical_evidence["yara"]


def test_the_evidence_text_carries_every_hit():
    from maljan.providers.static.capa_yara import _render_table

    text = _render_table([{"rule": f"rule_{i}", "namespace": "x"} for i in range(5000)])
    assert "rule_4999" in text and "…" not in text


# A real (un-mocked) ``_run_capa`` smoke test against ``data/samples`` was
# deliberately left out: a real vivisect pass over one of the malware samples
# in this repo measured well over two minutes on this box — a cost not worth
# paying in every test run for a call sequence already verified by hand
# against the installed flare-capa 9.4.0 (module docstring) and covered here
# through the monkeypatched ``_run_capa`` seam.


def _child(code: str) -> list[str]:
    """A stand-in for the capa child's command: the same arguments follow it, the answer path last.

    Used to drive ``_run_capa_bounded``'s timeout, kill and answer paths
    without a real capa install or a multi-minute analysis.
    """
    return [sys.executable, "-c", code]


def test_a_capa_run_past_its_budget_is_killed_not_waited_out(tmp_path, monkeypatch):
    monkeypatch.setenv(staging.STAGING_DIR_ENV, str(tmp_path / "staging"))
    pid_file = tmp_path / "child.pid"
    sleepy = _child(
        f"import os, time; open({str(pid_file)!r}, 'w').write(str(os.getpid())); time.sleep(30)"
    )
    provider = _provider(tmp_path)
    provider._capa.timeout_seconds = 1
    started = time.monotonic()
    result = provider._run_capa_bounded(str(tmp_path / "s.exe"), tmp_path, child=sleepy)
    elapsed = time.monotonic() - started
    assert result is None
    # Killed well before the child's 30s sleep would have elapsed on its own,
    # and reaped: nothing is left behind for the caller (an arq worker, in
    # production) to wait on later.
    assert elapsed < 15
    with pytest.raises(ProcessLookupError):
        os.kill(int(pid_file.read_text()), 0)


# A real capa ResultDocument is routinely well over the 64 KiB OS pipe buffer;
# the answer goes through a file, so a large one arrives whole and in time.
_BIG_ANSWER = (
    "import json, sys\n"
    "rules = {f'rule_{i}': {'meta': {'namespace': 'x' * 200, 'attack': []},"
    " 'matches': [[{'type': 'absolute', 'value': i}, {}]]} for i in range(2000)}\n"
    "open(sys.argv[-1], 'w').write(json.dumps({'ok': {'rules': rules}}))\n"
)


def test_a_large_capa_result_arrives_intact_within_the_budget(tmp_path, monkeypatch):
    monkeypatch.setenv(staging.STAGING_DIR_ENV, str(tmp_path / "staging"))
    provider = _provider(tmp_path)
    provider._capa.timeout_seconds = 10
    started = time.monotonic()
    result = provider._run_capa_bounded(
        str(tmp_path / "s.exe"), tmp_path, child=_child(_BIG_ANSWER)
    )
    elapsed = time.monotonic() - started
    assert result is not None
    assert len(result["rules"]) == 2000
    assert elapsed < 10
