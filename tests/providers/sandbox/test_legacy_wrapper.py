"""``as_sandbox_client`` keeps ``SandboxClient``'s contract, including fetch_pcap."""

from __future__ import annotations

import json
from pathlib import Path

from maljan.core.config import Settings
from maljan.loaders.sandbox_client import SandboxClient
from maljan.providers.registry import get_sandbox_provider
from maljan.providers.sandbox._legacy import as_sandbox_client

ROOT = Path(__file__).resolve().parents[3]


def test_the_wrapper_satisfies_the_protocol():
    client = as_sandbox_client(get_sandbox_provider(Settings(_env_file=None)))
    assert isinstance(client, SandboxClient)


def test_the_mock_provider_round_trips_a_fixture(tmp_path):
    raw = json.loads(
        (ROOT / "data" / "samples" / "dynamic" / "sample_1.json").read_text(encoding="utf-8")
    )
    (tmp_path / "dynamic").mkdir()
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"payload")
    import hashlib

    sha = hashlib.sha256(b"payload").hexdigest()
    (tmp_path / "dynamic" / f"{sha}.json").write_text(json.dumps(raw), encoding="utf-8")

    cfg = Settings(_env_file=None)
    provider = get_sandbox_provider(cfg)
    provider.fixtures_dir = str(tmp_path)  # the mock provider's only knob
    client = as_sandbox_client(provider)
    task_id = client.submit(sample)
    assert client.wait_for_completion(task_id) == "reported"
    result = client.fetch_report(task_id)
    assert result.report == raw
    assert result.normalized is not None and result.normalized.source_format == "mock"
