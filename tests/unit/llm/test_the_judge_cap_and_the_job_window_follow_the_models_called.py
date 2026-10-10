"""The judge's output cap and the job's one window come from the models each role really calls.

The judge's cap is derived from the chain its model is built from: its own
``llm.agents.judge`` entry with its fallbacks, or else the global judge model
(``get_judge_llm``). The job's window is the smallest served over every model
the job's tool-calling agents call, each read as its builder reads it: every
analyst, the judge on the judge role, the mediator whenever the profile
debates and the function summariser whenever it is on, with or without an
entry of their own (``composition.window_assignments``).

Windows and maximum outputs are the vendored table's (``probe=False`` in a mock
container): claude-haiku-5-5 serves 1,000,000 with a 128,000 maximum output,
deepseek-v4-flash and deepseek-v4-pro 1,048,576 with 393,216, deepseek-v3
65,536 with no declared maximum.
"""

from __future__ import annotations

from typing import Any

DEEPSEEK = "https://api.deepseek.com"


def _settings(values: dict[str, Any]) -> Any:
    from maljan.core.settings_overrides import build_settings

    return build_settings(values)


def _deepseek(expert: str, judge: str, **more: Any) -> Any:
    return _settings(
        {
            "llm.provider": "openai",
            "llm.openai.base_url": DEEPSEEK,
            "llm.openai.expert_model": expert,
            "llm.openai.judge_model": judge,
            **more,
        }
    )


def _haiku_everywhere(**more: Any) -> Any:
    return _settings(
        {
            "llm.provider": "anthropic",
            "llm.anthropic.expert_model": "claude-haiku-5-5",
            "llm.anthropic.judge_model": "claude-haiku-5-5",
            **more,
        }
    )


def _entry(model: str, *fallbacks: dict[str, Any]) -> dict[str, Any]:
    return {
        "provider": "openai",
        "model": model,
        "base_url": DEEPSEEK,
        **({"fallbacks": list(fallbacks)} if fallbacks else {}),
    }


def _lead_team() -> list[str]:
    """The shipped lead team's lead and every specialist it can ask."""
    from maljan.agents.composition import analyst_keys, reachable_agents

    settings = _settings({"agents.profile": "team_lead"})
    team = reachable_agents(settings, analyst_keys(settings))
    assert len(team) > 1
    return team


def _container(settings: Any) -> Any:
    from maljan.core.container import ServiceContainer

    return ServiceContainer(settings, mock=True)


def _judge_cap(settings: Any) -> Any:
    return _container(settings)._built_cap("judge_max_tokens", "judge", role="judge")


def _window(settings: Any) -> int:
    return int(_container(settings).get_context_budget().window.tokens)


class TestTheJudgesCap:
    def test_its_entry_decides_over_the_global_judge_model(self) -> None:
        settings = _haiku_everywhere(**{"llm.agents": {"judge": _entry("deepseek-v4-pro")}})

        cap = _judge_cap(settings)

        assert cap.tokens == 262144
        assert "1048576-token context window" in cap.sentence

    def test_an_entry_on_a_smaller_window_than_the_global_judge_model_bounds_it(self) -> None:
        settings = _deepseek(
            "deepseek-v4-flash",
            "deepseek-v4-pro",
            **{"llm.agents": {"judge": _entry("deepseek-v3")}},
        )

        cap = _judge_cap(settings)

        assert cap.tokens < 65536
        assert "65536-token context window" in cap.sentence

    def test_with_no_entry_the_global_judge_model_decides_not_the_expert_one(self) -> None:
        cap = _judge_cap(_deepseek("deepseek-v4-flash", "deepseek-v3"))

        assert cap.tokens < 65536
        assert "65536-token context window" in cap.sentence

    def test_it_fits_the_tightest_model_of_the_entry_s_fallbacks(self) -> None:
        fallback = {"provider": "anthropic", "model": "claude-haiku-5-5"}
        settings = _deepseek(
            "deepseek-v4-flash",
            "deepseek-v4-flash",
            **{"llm.agents": {"judge": _entry("deepseek-v4-pro", fallback)}},
        )

        assert _judge_cap(settings).tokens == 128000

    def test_haiku_everywhere_keeps_its_cap(self) -> None:
        cap = _judge_cap(_haiku_everywhere())

        assert cap.tokens == 128000
        assert "1000000-token context window" in cap.sentence

    def test_the_built_judge_model_carries_the_cap_of_its_entry(self) -> None:
        from maljan.llm.context_window import built_output_cap
        from maljan.llm.registry import LLMProviderRegistry

        settings = _deepseek(
            "deepseek-v4-flash",
            "deepseek-v4-pro",
            **{"llm.openai.api_key": "sk-test", "llm.agents": {"judge": _entry("deepseek-v3")}},
        )
        container = _container(settings)
        container._llm_registry = LLMProviderRegistry(settings)

        built = built_output_cap(container.get_judge_llm())

        assert built is not None
        assert built.tokens == _judge_cap(settings).tokens
        assert "65536-token context window" in built.sentence

    def test_an_operator_cap_is_used_as_set(self) -> None:
        settings = _haiku_everywhere(
            **{"llm.judge_max_tokens": 4096, "llm.agents": {"judge": _entry("deepseek-v3")}}
        )

        assert _judge_cap(settings).tokens == 4096


class TestTheJobsWindow:
    def test_a_judge_with_no_entry_counts_with_the_global_judge_model(self) -> None:
        assert _window(_deepseek("deepseek-v4-flash", "deepseek-v3")) == 65536

    def test_haiku_everywhere_keeps_its_window(self) -> None:
        assert _window(_haiku_everywhere()) == 1000000

    def test_a_judge_entry_on_a_smaller_window_narrows_it(self) -> None:
        settings = _deepseek(
            "deepseek-v4-flash",
            "deepseek-v4-flash",
            **{"llm.agents": {"judge": _entry("deepseek-v3")}},
        )

        assert _window(settings) == 65536

    def test_a_judge_entry_on_a_larger_window_keeps_the_global_judge_model_out(self) -> None:
        settings = _deepseek(
            "deepseek-v4-flash",
            "deepseek-v3",
            **{"llm.agents": {"judge": _entry("deepseek-v4-pro")}},
        )

        assert _window(settings) == 1048576

    def test_the_mediator_counts_on_the_global_expert_model_without_an_entry(self) -> None:
        own = {agent: _entry("deepseek-v4-flash") for agent in ("static", "dynamic", "network")}
        settings = _deepseek(
            "deepseek-v3",
            "deepseek-v4-pro",
            **{"llm.agents": {**own, "judge": _entry("deepseek-v4-pro")}},
        )

        assert _window(settings) == 65536

    def test_the_summariser_counts_on_the_global_expert_model_without_an_entry(self) -> None:
        own = {agent: _entry("deepseek-v4-flash") for agent in _lead_team()}
        values = {
            "agents.profile": "team_lead",
            "llm.agents": {**own, "judge": _entry("deepseek-v4-pro")},
        }

        assert _window(_deepseek("deepseek-v3", "deepseek-v4-pro", **values)) == 1048576
        summarising = {**values, "preprocessing.use_function_summarizer": True}
        assert _window(_deepseek("deepseek-v3", "deepseek-v4-pro", **summarising)) == 65536

    def test_a_lead_s_specialists_count_on_the_global_expert_model_without_entries(self) -> None:
        """The lead asks specialists that sit in no stage; each runs on the global expert model."""
        settings = _deepseek(
            "deepseek-v3",
            "deepseek-v4-pro",
            **{"agents.profile": "team_lead", "llm.agents": {"lead": _entry("deepseek-v4-pro")}},
        )

        assert _window(settings) == 65536

    def test_a_lead_team_with_every_agent_on_a_larger_entry_takes_the_larger_window(
        self,
    ) -> None:
        own = {agent: _entry("deepseek-v4-flash") for agent in _lead_team()}
        settings = _deepseek(
            "deepseek-v3", "deepseek-v4-pro", **{"agents.profile": "team_lead", "llm.agents": own}
        )

        assert _window(settings) == 1048576

    def test_a_specialist_s_own_entry_on_a_smaller_window_narrows_it(self) -> None:
        team = _lead_team()
        specialist = next(agent for agent in team if agent != "lead")
        own = {agent: _entry("deepseek-v4-flash") for agent in team}
        own[specialist] = _entry("deepseek-v3")
        settings = _deepseek(
            "deepseek-v4-flash",
            "deepseek-v4-flash",
            **{"agents.profile": "team_lead", "llm.agents": own},
        )

        assert _window(settings) == 65536

    def test_an_analyst_s_fallback_counts(self) -> None:
        settings = _deepseek(
            "deepseek-v4-flash",
            "deepseek-v4-flash",
            **{"llm.agents": {"static": _entry("deepseek-v4-pro", _entry("deepseek-v3"))}},
        )

        assert _window(settings) == 65536

    def test_the_judge_s_fallback_counts(self) -> None:
        settings = _deepseek(
            "deepseek-v4-flash",
            "deepseek-v4-flash",
            **{"llm.agents": {"judge": _entry("deepseek-v4-pro", _entry("deepseek-v3"))}},
        )

        assert _window(settings) == 65536

    def test_the_settings_page_reports_the_window_the_job_uses(self) -> None:
        import asyncio

        from app.services.settings_probes import context_window_facts

        # An operator cap: the page then asks the table and no endpoint.
        settings = _deepseek(
            "deepseek-v4-flash", "deepseek-v3", **{"preprocessing.max_tool_output_chars": 9000}
        )

        answer = asyncio.run(context_window_facts(settings))

        assert answer["tokens"] == _window(settings) == 65536


class TestTheWindowsModels:
    def test_every_role_is_read_on_the_role_its_builder_reads(self) -> None:
        from maljan.agents.composition import window_assignments

        settings = _deepseek("deepseek-v4-flash", "deepseek-v3")

        read = {(a.agent, a.model) for a in window_assignments(settings)}

        assert ("judge", "deepseek-v3") in read
        assert ("judge", "deepseek-v4-flash") not in read
        assert ("mediator", "deepseek-v4-flash") in read
        assert {("static", "deepseek-v4-flash"), ("network", "deepseek-v4-flash")} <= read

    def test_a_job_on_one_model_asks_one_question(self) -> None:
        from maljan.agents.composition import window_assignments
        from maljan.llm.context_window import _questions

        settings = _haiku_everywhere(**{"preprocessing.use_function_summarizer": True})

        assert len(_questions(settings, window_assignments(settings))) == 1

    def test_a_hostile_roster_is_read_in_linear_time(self) -> None:
        """A chain of agents each asking the next is walked once, each model asked once."""
        import time
        from types import SimpleNamespace

        from maljan.agents.composition import window_assignments
        from maljan.llm.context_window import _questions

        def _timed(count: int) -> float:
            definitions = {
                f"a{i}": {
                    "role": "generic",
                    "prompt": "p",
                    "tools": [{"kind": "agent", "agent": f"a{i + 1}"}] if i + 1 < count else [],
                }
                for i in range(count)
            }
            entries = {f"a{i}": _entry(f"model-{i}") for i in range(count)}
            settings = _deepseek(
                "deepseek-v4-flash",
                "deepseek-v3",
                **{"agents.definitions": definitions, "llm.agents": entries},
            )
            stages = [SimpleNamespace(kind="analysis", agents=["a0"])]
            started = time.perf_counter()
            chain = window_assignments(settings, stages)
            _questions(settings, chain * 10)
            elapsed = time.perf_counter() - started
            assert len(chain) == count + 1
            return elapsed

        small, large = _timed(200), _timed(2000)

        assert large < small * 30 + 0.05


class TestAnEntryTheRegistryCannotBuild:
    def test_it_is_read_as_the_role_s_global_model_as_the_builder_builds_it(self) -> None:
        from maljan.core.model_assignments import assignment_chain_for

        settings = _deepseek(
            "deepseek-v4-flash",
            "deepseek-v3",
            **{"llm.agents": {"judge": {"provider": "no-such-provider", "model": "x"}}},
        )

        chain = assignment_chain_for(settings, "judge", role="judge")

        assert [a.model for a in chain] == ["deepseek-v3"]
        assert _judge_cap(settings).tokens < 65536

    def test_a_provider_registered_later_is_read_as_built(self) -> None:
        from maljan.core.model_assignments import assignment_chain_for
        from maljan.llm.registry import _PROVIDER_REGISTRY

        settings = _deepseek(
            "deepseek-v4-flash",
            "deepseek-v3",
            **{"llm.agents": {"judge": {"provider": "acme-plugged", "model": "acme-judge"}}},
        )
        _PROVIDER_REGISTRY["acme-plugged"] = object
        try:
            chain = assignment_chain_for(settings, "judge", role="judge")
        finally:
            _PROVIDER_REGISTRY.pop("acme-plugged", None)

        assert [a.model for a in chain] == ["acme-judge"]

    def test_a_registry_that_cannot_load_is_logged(self, monkeypatch: Any, caplog: Any) -> None:
        import logging

        from maljan.core.logger import logger
        from maljan.core.model_assignments import builds_provider
        from maljan.llm import registry

        def _broken() -> None:
            raise ImportError("a provider module is missing")

        monkeypatch.setattr(registry, "discover_providers", _broken)
        logger.addHandler(caplog.handler)
        caplog.set_level(logging.DEBUG)
        monkeypatch.setattr(logger, "level", logging.DEBUG)
        try:
            assert builds_provider("acme-anything") is True
        finally:
            logger.removeHandler(caplog.handler)

        assert any(
            "could not load every built-in provider (ImportError)" in r.getMessage()
            for r in caplog.records
        )


class TestTheReporter:
    def test_it_is_called_only_while_reporting_is_on(self) -> None:
        from maljan.agents.composition import called_assignments

        on = _haiku_everywhere()
        off = _haiku_everywhere(**{"reporting.enabled": False})

        assert "reporter" in {a.agent for a in called_assignments(on)}
        assert "reporter" not in {a.agent for a in called_assignments(off)}

    def test_the_pack_it_reads_fits_its_own_smaller_window(self, monkeypatch: Any) -> None:
        from maljan.pipeline import nodes

        settings = _deepseek(
            "deepseek-v4-flash",
            "deepseek-v4-flash",
            **{"llm.agents": {"reporter": _entry("deepseek-v3")}},
        )
        container = _container(settings)
        cut: list[int] = []
        monkeypatch.setattr(nodes, "pack_block", lambda _entries, chars: cut.append(chars) or "")

        job = nodes.upstream_chars(container)
        own = nodes.upstream_chars(container, reporter=True)
        nodes.pack_text({}, container)
        nodes.pack_text({}, container, for_reporter=True)

        assert container.get_context_budget().window.tokens == 1048576
        assert container.get_reporter_context_budget().window.tokens == 65536
        assert own < job
        assert cut == [job, own]

    def test_a_reporter_on_a_larger_window_keeps_the_job_s_cut(self, monkeypatch: Any) -> None:
        from maljan.pipeline import nodes

        settings = _deepseek(
            "deepseek-v3",
            "deepseek-v3",
            **{"llm.agents": {"reporter": _entry("deepseek-v4-pro")}},
        )
        container = _container(settings)
        cut: list[int] = []
        monkeypatch.setattr(nodes, "pack_block", lambda _entries, chars: cut.append(chars) or "")

        nodes.pack_text({}, container)
        nodes.pack_text({}, container, for_reporter=True)

        assert cut[0] == cut[1] == nodes.upstream_chars(container)
