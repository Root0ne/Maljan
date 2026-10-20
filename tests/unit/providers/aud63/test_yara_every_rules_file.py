"""PS-L7: every YARA rules file in the directory is scanned, not the first one found."""

from __future__ import annotations

from types import SimpleNamespace

from maljan.analysis import yara_layer
from maljan.core.config import Settings
from maljan.providers.static.capa_yara import CapaYaraStaticProvider


def test_every_rules_file_is_scanned_and_a_bad_one_costs_only_itself(monkeypatch, tmp_path):
    for name in ("a.yml", "b.yaml", "c.yml"):
        (tmp_path / name).write_text("x")
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"data")

    def from_yaml(path):
        if path.name == "b.yaml":
            raise ValueError("broken")
        match = SimpleNamespace(rule_id=path.stem, evidence_ref="e", technique_id="T1")
        return SimpleNamespace(scan=lambda data: [match])

    monkeypatch.setattr(yara_layer.YaraLayer, "from_yaml", staticmethod(from_yaml))
    cfg = Settings(_env_file=None)
    cfg.static.provider = "capa_yara"
    cfg.static.yara.rules_dir = str(tmp_path)
    provider = CapaYaraStaticProvider.from_settings(cfg)
    hits = provider._run_yara(str(sample))
    assert [h["rule"] for h in hits] == ["a", "c"]
