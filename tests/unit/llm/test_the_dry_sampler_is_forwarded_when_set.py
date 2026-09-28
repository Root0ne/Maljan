"""llama.cpp's DRY sampler is forwarded to a llama.cpp server when the operator sets it.

A local answer that writes the same claims again and again is a sampling
failure as much as a model's; llama.cpp's DRY sampler penalises a sequence
that extends a repetition already in the context. Its four parameters are an
opt-in passthrough beside the repetition penalty: unset by default, sent in
``extra_body`` only to an endpoint that takes llama.cpp's extras, and only the
ones set.
"""

from __future__ import annotations

from typing import Any

import pytest

from maljan.core.config import OpenAIConfig, Settings
from maljan.llm.openai_provider import LLAMA_CPP_EXTRA_KEYS, OpenAIProvider, forget_standard_only

DRY = {"dry_multiplier": 0.8, "dry_base": 1.75, "dry_allowed_length": 2, "dry_penalty_last_n": -1}


@pytest.fixture(autouse=True)
def _forget() -> Any:
    forget_standard_only()
    yield
    forget_standard_only()


def _extras(base_url: str | None, **openai: Any) -> dict[str, Any]:
    cfg = Settings(
        _env_file=None,
        llm={"openai": {"api_key": "sk-test", "base_url": base_url, **openai}},
    )
    model = OpenAIProvider(cfg).build_model("m", 0.0, max_tokens=512)
    return dict(getattr(model, "extra_body", None) or {})


def test_nothing_is_set_by_default() -> None:
    config = OpenAIConfig()
    assert [getattr(config, key) for key in DRY] == [None, None, None, None]
    assert not any(key in _extras("http://127.0.0.1:8080/v1") for key in DRY)


def test_the_set_parameters_reach_a_llama_cpp_server() -> None:
    extras = _extras("http://127.0.0.1:8080/v1", **DRY)

    assert {key: extras[key] for key in DRY} == DRY


def test_only_the_ones_set_are_sent() -> None:
    extras = _extras("http://127.0.0.1:8080/v1", dry_multiplier=0.8)

    assert extras["dry_multiplier"] == 0.8
    assert not any(
        key in extras for key in ("dry_base", "dry_allowed_length", "dry_penalty_last_n")
    )


def test_a_hosted_api_is_not_sent_them() -> None:
    assert not any(key in _extras("https://api.deepseek.com", **DRY) for key in DRY)
    assert not any(key in _extras(None, **DRY) for key in DRY)


def test_the_self_heal_knows_them_as_llama_cpp_s() -> None:
    assert set(DRY) <= set(LLAMA_CPP_EXTRA_KEYS)


def test_values_out_of_range_are_refused() -> None:
    with pytest.raises(ValueError):
        OpenAIConfig(dry_multiplier=-1.0)
    with pytest.raises(ValueError):
        OpenAIConfig(dry_penalty_last_n=-2)
