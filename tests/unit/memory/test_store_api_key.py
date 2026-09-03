from unittest.mock import MagicMock

import pytest


@pytest.mark.parametrize(
    "module,cls", [("qdrant_store", "QdrantStore"), ("function_hash_store", "FunctionHashStore")]
)
def test_api_key_is_forwarded_to_the_client(monkeypatch, module, cls):
    import importlib

    mod = importlib.import_module(f"maljan.memory.{module}")
    fake = MagicMock()
    monkeypatch.setattr("qdrant_client.QdrantClient", fake)
    getattr(mod, cls)(url="http://q:6333", api_key="k")
    assert fake.call_args.kwargs == {"url": "http://q:6333", "api_key": "k"}
    fake.reset_mock()
    getattr(mod, cls)(url="http://q:6333")
    assert fake.call_args.kwargs == {"url": "http://q:6333", "api_key": None}
