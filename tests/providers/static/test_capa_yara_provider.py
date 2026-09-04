"""Evidence, not tools — and a missing library is a warning, not a failure."""

from __future__ import annotations

import builtins

from maljan.core.config import Settings
from maljan.providers.static.capa_yara import CapaYaraStaticProvider


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
    assert caps.provides_tools is False and caps.supports_tool_curation is False
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
    assert bundle.api_capabilities["data-manipulation"] == 1
    assert bundle.api_capabilities["host-interaction"] == 1
    ids = {hit["technique_id"] for hit in bundle.technique_hits}
    assert ids == {"T1027", "T1106"}
    assert all(hit["evidence"] for hit in bundle.technique_hits)
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


def test_the_evidence_text_is_capped():
    from maljan.providers.static.capa_yara import _render_table
    from maljan.schemas.tool_evidence import MAX_OUTPUT_CHARS

    text = _render_table([{"rule": f"rule_{i}", "namespace": "x"} for i in range(5000)])
    assert len(text) <= MAX_OUTPUT_CHARS


# A real (un-mocked) ``_run_capa`` smoke test against ``data/samples`` was
# deliberately left out: a real vivisect pass over one of the malware samples
# in this repo measured well over two minutes on this box, and a timed-out
# run leaves its worker thread running in the background afterwards (see the
# ``ThreadPoolExecutor`` note in ``capa_yara.py``) — a cost not worth paying
# in every test run for a call sequence already verified by hand against the
# installed flare-capa 9.4.0 (module docstring) and covered here through the
# monkeypatched ``_run_capa`` seam.
