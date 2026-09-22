"""The served window is learned for free, and it is what sizes a tool answer.

Three claims, tested apart:

* the probe reads a window out of the shapes the four server kinds answer with,
  and it can reach nothing but the metadata paths it names;
* the arithmetic that turns a window into a character cap is a function of its
  inputs, with the two properties the design rests on — the answers of one
  conversation sum to less than the room it started with, and the floor holds;
* what could not be learned is said in words rather than guessed at.

Everything runs against hand-written fixtures and a stub transport. No server
is started and none is asked for.
"""

from __future__ import annotations

import json
import time
from typing import Any

import httpx
import pytest

from maljan.llm import context_window as cw


def _client(handler: Any) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


# Anything a model produces on. A path is refused if it merely contains one of
# these, so the list covers the shapes rather than the exact spellings: the
# chat and legacy completion endpoints, the Responses API, both embedding
# endpoints, Ollama's and Anthropic's and Gemini's own generation paths.
FORBIDDEN = (
    "completion",
    "/chat",
    "generate",
    "/messages",
    "generatecontent",
    "/invoke",
    "/v1/responses",
    "embeddings",
)

# The only request this module may make that is not a GET, named rather than
# inferred: Ollama describes a model on a POST because its body carries the
# model's name. Everything else must be a GET, and a guard that allowed "any
# POST to a listed path" would allow a POST to ``/v1/models``.
ALLOWED_NON_GET = frozenset({("POST", "/api/show")})


def _record_every_request() -> tuple[list[httpx.Request], Any]:
    """A handler that writes down what it was asked and answers 404.

    Records rather than asserts, deliberately: ``probe_window`` catches
    ``Exception`` around its whole send loop, so an ``AssertionError`` raised
    inside the transport would be swallowed and the guard would pass on
    precisely the call it exists to catch.
    """
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(404, json={})

    return seen, handler


def _sent_by(call: Any) -> list[httpx.Request]:
    """Every request ``call`` makes through a synchronous client."""
    seen, handler = _record_every_request()
    real = httpx.Client

    def stub(**_kwargs: Any) -> httpx.Client:
        return real(transport=httpx.MockTransport(handler))

    try:
        httpx.Client = stub  # type: ignore[assignment,misc]
        call()
    finally:
        httpx.Client = real  # type: ignore[misc]
    return seen


def _sent_by_await(call: Any) -> list[httpx.Request]:
    """Every request ``call`` makes through an asynchronous client."""
    import asyncio

    seen, handler = _record_every_request()
    real = httpx.AsyncClient

    def stub(**_kwargs: Any) -> httpx.AsyncClient:
        return real(transport=httpx.MockTransport(handler))

    try:
        httpx.AsyncClient = stub  # type: ignore[assignment,misc]
        asyncio.run(call())
    finally:
        httpx.AsyncClient = real  # type: ignore[misc]
    return seen


def _nothing_but_metadata(sent: list[httpx.Request], where: Any) -> None:
    """Every recorded request is a GET, or the one named POST, on a listed path."""
    for request in sent:
        url = str(request.url).lower()
        path = request.url.path
        assert path.endswith(cw.PROBE_PATHS), (where, str(request.url))
        assert not any(word in url for word in FORBIDDEN), (where, str(request.url))
        if request.method != "GET":
            suffix = next(p for p in cw.PROBE_PATHS if path.endswith(p))
            assert (request.method, suffix) in ALLOWED_NON_GET, (where, request.method, path)


class TestWhatEachServerKindReports:
    """One shape per server kind, written the way the server writes it."""

    def test_llama_cpp_props_gives_the_window_the_server_was_started_with(self) -> None:
        payload = {
            "default_generation_settings": {"n_ctx": 32768, "n_predict": -1},
            "total_slots": 1,
        }
        assert cw.window_from_llama_props(payload) == 32768

    def test_llama_cpp_per_slot_window_is_read_when_the_whole_one_is_absent(self) -> None:
        payload = {"default_generation_settings": {"n_ctx_per_seq": 16384}}
        assert cw.window_from_llama_props(payload) == 16384

    def test_a_props_answer_without_a_window_reports_nothing(self) -> None:
        assert cw.window_from_llama_props({"default_generation_settings": {}}) == 0
        assert cw.window_from_llama_props(["not a mapping"]) == 0

    def test_a_vllm_model_entry_carries_max_model_len(self) -> None:
        payload = {"object": "list", "data": [{"id": "qwen3-8b", "max_model_len": 40960}]}
        assert cw.window_from_model_list(payload, "qwen3-8b") == 40960

    def test_an_openrouter_entry_carries_context_length(self) -> None:
        payload = {
            "data": [
                {"id": "openai/gpt-4o", "context_length": 128000},
                {"id": "anthropic/claude-sonnet-4", "context_length": 200000},
            ]
        }
        assert cw.window_from_model_list(payload, "anthropic/claude-sonnet-4") == 200000

    def test_a_server_with_one_model_answers_for_it_whatever_it_is_called(self) -> None:
        """A local server advertises the file it loaded, not the tag configured."""
        payload = {"data": [{"id": "/models/Qwen3-35B.gguf", "max_model_len": 32768}]}
        assert cw.window_from_model_list(payload, "qwen3.5:9b") == 32768

    def test_a_model_list_that_names_no_window_reports_nothing(self) -> None:
        payload = {"data": [{"id": "gpt-4o", "object": "model"}, {"id": "gpt-4o-mini"}]}
        assert cw.window_from_model_list(payload, "gpt-4o") == 0

    def test_ollama_reports_the_window_under_its_architecture(self) -> None:
        payload = {
            "model_info": {"general.architecture": "qwen3", "qwen3.context_length": 40960},
            "parameters": 'stop "<|im_end|>"\n',
        }
        assert cw.window_from_ollama_show(payload) == 40960

    def test_an_ollama_num_ctx_parameter_is_the_served_window(self) -> None:
        """The Modelfile's own setting binds below whatever the weights allow."""
        payload = {
            "model_info": {"qwen3.context_length": 40960},
            "parameters": 'num_ctx 8192\nstop "<|im_end|>"\n',
        }
        assert cw.window_from_ollama_show(payload) == 8192

    def test_text_generation_inference_reports_max_total_tokens(self) -> None:
        assert cw.window_from_tgi_info({"max_total_tokens": 8192}) == 8192
        assert cw.window_from_tgi_info({"model_id": "a/b"}) == 0


class TestTheProbeCanReachNothingThatGenerates:
    """The guard. A window is learned for free or it is not learned."""

    MATRIX = [
        ("openai", "http://127.0.0.1:8080/v1", "qwen3"),
        ("openai", "http://127.0.0.1:8080", "qwen3"),
        ("openai", "https://api.openai.com/v1", "gpt-4o-mini"),
        ("openai", "https://openrouter.ai/api/v1", "openai/gpt-4o"),
        ("ollama", "http://localhost:11434", "qwen3.5:9b"),
        ("ollama", "", "qwen3.5:9b"),
        ("anthropic", "the Anthropic API", "claude-sonnet-4-20250514"),
        ("gemini", "the Gemini API", "gemini-2.5-pro"),
        ("", "", ""),
    ]

    def test_every_request_the_module_can_plan_is_a_metadata_path(self) -> None:
        """A plan is the configured address plus one of four fixed suffixes."""
        for provider, endpoint, model in self.MATRIX:
            for ask in cw.probe_plan(provider, endpoint, model):
                assert ask.url.endswith(cw.PROBE_PATHS), (provider, endpoint, ask.url)
                suffix = next(p for p in cw.PROBE_PATHS if ask.url.endswith(p))
                root = ask.url[: -len(suffix)]
                assert root, ask.url
                configured = str(endpoint).rstrip("/")
                assert not configured or configured.startswith(root), (endpoint, ask.url)

    def test_no_planned_path_is_one_a_model_answers_on(self) -> None:
        for path in cw.PROBE_PATHS:
            assert not any(word in path.lower() for word in FORBIDDEN), path

    def test_the_real_probe_sends_nothing_but_metadata_requests(self) -> None:
        """The whole of what ``probe_window`` puts on a wire, recorded.

        ``probe_window`` itself is driven, not a second copy of its send loop:
        a guard over a re-implementation guards the re-implementation. The
        handler only *records* — an assertion inside it would be swallowed by
        the probe's own catch-all and the guard would pass on a rogue call.
        """
        for provider, endpoint, model in self.MATRIX:
            sent = _sent_by(
                lambda p=provider, e=endpoint, m=model: cw.probe_window(p, endpoint=e, model=m)
            )
            _nothing_but_metadata(sent, (provider, endpoint))

    def test_the_awaited_probe_sends_nothing_but_metadata_requests(self) -> None:
        for provider, endpoint, model in self.MATRIX:
            sent = _sent_by_await(
                lambda p=provider, e=endpoint, m=model: cw.aprobe_window(p, endpoint=e, model=m)
            )
            _nothing_but_metadata(sent, (provider, endpoint))

    def test_learning_a_window_end_to_end_sends_nothing_else(self) -> None:
        """The path a job takes, from settings to a window, under the same watch."""
        from maljan.core.config import Settings

        cw.forget_learned_windows()
        settings = Settings(
            _env_file=None, llm={"openai": {"base_url": "http://127.0.0.1:8080/v1"}}
        )
        sent = _sent_by(lambda: cw.window_for_settings(settings, ["static", "judge"]))
        _nothing_but_metadata(sent, ("settings",))
        cw.forget_learned_windows()

    def test_the_module_never_asks_a_model_to_produce_anything(self) -> None:
        """The source itself carries no path a generation call is made on."""
        from pathlib import Path

        source = Path(cw.__file__).read_text(encoding="utf-8").lower()
        for word in FORBIDDEN:
            assert word not in source, word


class TestLearningTheWindow:
    def setup_method(self) -> None:
        cw.forget_learned_windows()

    def teardown_method(self) -> None:
        cw.forget_learned_windows()

    def test_a_declared_window_short_circuits_everything(self) -> None:
        fact = cw.learn_window("openai", endpoint="http://x/v1", model="gpt-4o", declared=65536)
        assert (fact.tokens, fact.source) == (65536, cw.DECLARED)

    def test_a_model_the_table_names_is_answered_without_the_network(self) -> None:
        fact = cw.learn_window("anthropic", endpoint="the Anthropic API", model="claude-3-5-haiku")
        assert (fact.tokens, fact.source) == (200000, cw.TABLE)

    def test_a_model_nothing_knows_falls_back_and_says_so(self) -> None:
        fact = cw.learn_window("anthropic", endpoint="the Anthropic API", model="a-private-build")
        assert fact.tokens == cw.FALLBACK_WINDOW_TOKENS
        assert fact.source == cw.FALLBACK
        assert fact.detail.strip(), "a fallback with no reason is a guess"

    def test_an_endpoint_that_cannot_be_reached_never_raises(self) -> None:
        fact = cw.learn_window(
            "openai",
            endpoint="http://127.0.0.1:1/v1",
            model="qwen3",
            probe=True,
        )
        assert fact.source in (cw.TABLE, cw.FALLBACK)

    def test_the_table_is_matched_on_the_longest_family(self) -> None:
        assert cw.table_window("gpt-4o-mini").tokens == 128000
        assert cw.table_window("gpt-4").tokens == 8192

    def test_a_vendor_prefix_and_a_tag_are_not_part_of_the_family(self) -> None:
        assert cw.model_family("openrouter/qwen/qwen3:32b") == "qwen3"
        assert cw.model_family("Qwen3.5:9B") == "qwen3.5"


class TestANumberAnEndpointReportsIsUntrusted:
    """One integer must not be able to switch the output guardrail off."""

    def test_an_absurd_window_is_refused_rather_than_believed(self) -> None:
        for reported in (10**18, 10**15, 999_999_999_999, cw.MAX_BELIEVABLE_WINDOW_TOKENS + 1):
            assert cw.believable(reported) == 0, reported

    def test_the_boundary_itself_is_believed(self) -> None:
        assert cw.believable(cw.MAX_BELIEVABLE_WINDOW_TOKENS) == cw.MAX_BELIEVABLE_WINDOW_TOKENS
        assert cw.believable(cw.MAX_BELIEVABLE_WINDOW_TOKENS - 1) > 0

    def test_every_window_the_vendored_table_ships_is_believed(self) -> None:
        import json

        from maljan.core.paths import resolve_data

        raw = json.loads(resolve_data(cw.TABLE_PATH).read_text(encoding="utf-8"))
        for key, value in raw["windows"].items():
            assert cw.believable(value) == value, key

    def test_a_shape_that_is_not_a_window_is_not_one(self) -> None:
        for reported in ("32768", -5, 32768.0, True, False, None, [32768]):
            assert cw.believable(reported) == 0, reported

    def test_a_refused_figure_travels_as_a_reason_rather_than_a_silence(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path != "/props":
                return httpx.Response(404, json={})
            return httpx.Response(200, json={"default_generation_settings": {"n_ctx": 10**18}})

        real = httpx.Client

        def stub(**_kwargs: Any) -> httpx.Client:
            return real(transport=httpx.MockTransport(handler))

        cw.forget_learned_windows()
        try:
            httpx.Client = stub  # type: ignore[assignment,misc]
            fact = cw.probe_window("openai", endpoint="http://127.0.0.1:8080/v1", model="q")
        finally:
            httpx.Client = real  # type: ignore[misc]
            cw.forget_learned_windows()

        assert fact is not None
        assert fact.source == cw.FALLBACK
        assert "refused" in fact.detail

    def test_the_guardrail_is_not_switched_off_by_one(self) -> None:
        """The whole point: an unbelievable window cannot make every answer fit."""
        budget = cw.ContextBudget(cw.unknown_window("a proxy reported bytes"))
        assert budget.chars_for_one_answer() == cw.UNKNOWN_WINDOW_TOOL_OUTPUT_CHARS


class TestOneQuestionPerEndpointAndModel:
    def setup_method(self) -> None:
        cw.forget_learned_windows()

    def teardown_method(self) -> None:
        cw.forget_learned_windows()

    def test_a_team_on_one_endpoint_asks_once(self) -> None:
        """Four agents used to mean four full plans against a dead endpoint."""
        from maljan.core.config import Settings

        settings = Settings(_env_file=None, llm={"openai": {"base_url": "http://127.0.0.1:1/v1"}})
        asked = _sent_by(
            lambda: cw.window_for_settings(settings, ["static", "dynamic", "network", "judge"])
        )
        assert len({str(request.url) for request in asked}) == len(asked)
        assert len(asked) <= len(cw.PROBE_PATHS)

    def test_a_failure_is_remembered_so_the_next_job_does_not_repeat_it(self) -> None:
        from maljan.core.config import Settings

        settings = Settings(_env_file=None, llm={"openai": {"base_url": "http://127.0.0.1:1/v1"}})
        first = _sent_by(lambda: cw.window_for_settings(settings, ["static"]))
        again = _sent_by(lambda: cw.window_for_settings(settings, ["static"]))
        assert first, "the first job asked"
        assert again == [], "the second job asked again"

    def test_a_remembered_answer_is_asked_again_once_it_is_old(self) -> None:
        from maljan.core.config import Settings

        settings = Settings(_env_file=None, llm={"openai": {"base_url": "http://127.0.0.1:1/v1"}})
        _sent_by(lambda: cw.window_for_settings(settings, ["static"]))
        for key in list(cw._learned):  # noqa: SLF001 - the age is the thing under test
            stale = time.monotonic() - cw.WINDOW_CACHE_SECONDS - 1.0
            cw._learned[key] = (stale, cw._learned[key][1])  # noqa: SLF001
        assert _sent_by(lambda: cw.window_for_settings(settings, ["static"])), "never asked again"


class TestTheOllamaWindowIsBothNumbers:
    def setup_method(self) -> None:
        cw.forget_learned_windows()

    def teardown_method(self) -> None:
        cw.forget_learned_windows()

    def test_the_settings_value_does_not_short_circuit_the_probe(self) -> None:
        """The served window is the smaller of what is sent and what is held."""
        from maljan.core.config import Settings

        settings = Settings(_env_file=None, llm={"provider": "ollama"})
        asked = _sent_by(lambda: cw.window_for_settings(settings, ["static"]))
        assert [request.url.path for request in asked] == ["/api/show"]

    def test_a_model_that_holds_less_than_is_asked_for_wins(self) -> None:
        smaller = cw.WindowFact(8192, cw.PROBED, "the Ollama model description reported 8,192")
        fact = cw._combined(32768, True, smaller)  # noqa: SLF001 - the rule under test
        assert fact.tokens == 8192

    def test_an_untouched_default_does_not_claim_an_operator_set_it(self) -> None:
        from maljan.core.config import Settings

        shipped = Settings(_env_file=None, llm={"provider": "ollama"})
        chosen = Settings(_env_file=None, llm={"provider": "ollama", "ollama": {"num_ctx": 4096}})
        assert cw.declared_window(shipped, "ollama")[1] is True
        assert cw.declared_window(chosen, "ollama")[1] is False
        assert "by default" in cw._declared_fact(32768, True).detail  # noqa: SLF001
        assert "settings name" in cw._declared_fact(4096, False).detail  # noqa: SLF001

    def test_the_table_does_not_override_a_deployments_own_statement(self) -> None:
        """A published figure for a family is not evidence against an operator."""
        table = cw.table_window("gpt-4o")
        assert table is not None and table.tokens == 128000
        assert cw._combined(200000, False, table).tokens == 200000  # noqa: SLF001


class TestTheArithmetic:
    """One function, and the two properties the design rests on."""

    def test_an_unknown_window_is_the_floor(self) -> None:
        assert cw.derive_tool_output_chars(window_tokens=0) == cw.MIN_TOOL_OUTPUT_CHARS

    def test_the_window_this_deployment_serves(self) -> None:
        """32,768 tokens, an empty conversation, the configured reply reserve."""
        assert cw.derive_tool_output_chars(window_tokens=32768, reply_tokens=8192) == 9216

    def test_a_million_token_window_is_not_spent_as_if_it_were_small(self) -> None:
        cap = cw.derive_tool_output_chars(window_tokens=1_000_000, reply_tokens=8192)
        assert cap == 371_928

    def test_a_fuller_conversation_gets_a_smaller_answer(self) -> None:
        empty = cw.derive_tool_output_chars(window_tokens=32768, reply_tokens=8192)
        half = cw.derive_tool_output_chars(
            window_tokens=32768, reply_tokens=8192, held_chars=30_000
        )
        assert half < empty

    def test_a_nearly_full_conversation_gets_what_is_left_and_no_more(self) -> None:
        """The floor applies while the room affords it, and shrinks to it when not."""
        window, reply = 32768, 8192
        free = (window - reply) * cw.CHARS_PER_TOKEN
        # Held so that exactly 1,500 characters of room remain: under the
        # floor, over the point at which an answer stops being one.
        cap = cw.derive_tool_output_chars(
            window_tokens=window, reply_tokens=reply, held_chars=free - 1500
        )
        assert cap == 1500

    def test_a_conversation_with_no_room_left_is_handed_no_answer(self) -> None:
        window, reply = 32768, 8192
        free = (window - reply) * cw.CHARS_PER_TOKEN
        assert (
            cw.derive_tool_output_chars(
                window_tokens=window, reply_tokens=reply, held_chars=free - 100
            )
            == 0
        )
        assert (
            cw.derive_tool_output_chars(
                window_tokens=window, reply_tokens=reply, held_chars=10_000_000
            )
            == 0
        )

    def test_the_no_room_point_is_where_the_notice_leaves_no_payload(self) -> None:
        """989 characters: the widest notice plus the smallest payload."""
        from maljan.agents.output_shortening import (  # noqa: PLC2701
            _MIN_SHORTENABLE_STRING,
            MAX_SENTENCE_ROOM,
        )

        assert cw.NO_ROOM_BELOW_CHARS >= MAX_SENTENCE_ROOM + _MIN_SHORTENABLE_STRING
        assert cw.NO_ROOM_BELOW_CHARS < cw.MIN_TOOL_OUTPUT_CHARS

    def test_the_sentence_says_what_happened_without_naming_an_argument(self) -> None:
        said = cw.no_room_sentence(120_000)
        assert "120,000" in said
        assert "no room left" in said
        assert "`" not in said, "narrowing the call does not make room"

    def test_the_floor_leaves_room_for_the_notice_and_a_document(self) -> None:
        from maljan.agents.output_shortening import MAX_SENTENCE_ROOM, shorten_target

        assert cw.MIN_TOOL_OUTPUT_CHARS > MAX_SENTENCE_ROOM
        assert shorten_target(cw.MIN_TOOL_OUTPUT_CHARS, ("limit", "offset")) > 1000

    def test_the_answers_of_one_conversation_sum_to_less_than_its_room(self) -> None:
        """The property that makes the share a count rather than a safety margin."""
        window, reply = 32768, 8192
        free_chars = (window - reply) * cw.CHARS_PER_TOKEN
        held = 0
        spent = 0
        for _ in range(40):
            cap = cw.derive_tool_output_chars(
                window_tokens=window, reply_tokens=reply, held_chars=held, floor=0
            )
            spent += cap
            held += cap
        assert spent < free_chars

    def test_twelve_answers_clear_the_floor_on_the_smallest_window(self) -> None:
        """The count the share is argued from, computed rather than asserted."""
        window, reply = 32768, 8192
        held = 0
        above = 0
        for _ in range(40):
            cap = cw.derive_tool_output_chars(
                window_tokens=window, reply_tokens=reply, held_chars=held
            )
            if cap > cw.MIN_TOOL_OUTPUT_CHARS:
                above += 1
            held += cap
        assert above == 12

    def test_the_first_answer_beats_the_constant_it_replaces(self) -> None:
        """6,000 characters was tuned against this deployment's own model."""
        assert cw.derive_tool_output_chars(window_tokens=32768, reply_tokens=8192) > 6000

    def test_the_reply_reserve_never_eats_a_small_window_whole(self) -> None:
        assert cw.reply_reserve_tokens(8192, 8192) == 2048
        assert cw.reply_reserve_tokens(32768, 8192) == 8192
        assert cw.reply_reserve_tokens(32768, 0) == cw.DEFAULT_REPLY_TOKENS

    def test_the_characters_per_token_figure_is_the_measured_one(self) -> None:
        """Nineteen answers of 6,000 characters measured at 38,868 tokens."""
        measured = (19 * 6000) / 38_868
        assert round(measured) == cw.CHARS_PER_TOKEN


class TestAWindowThatMovedUnderUs:
    """A server restarted smaller says so, and that sentence is a correction."""

    def setup_method(self) -> None:
        cw.forget_learned_windows()

    def teardown_method(self) -> None:
        cw.forget_learned_windows()

    def _remember(self) -> None:
        cw._remembered(  # noqa: SLF001 - the cache is what is under test
            ("openai", "http://x/v1", "m"), cw.WindowFact(131072, cw.PROBED, "props")
        )

    def test_a_server_naming_its_context_length_retires_what_was_learned(self) -> None:
        for said in (
            "This model's maximum context length is 32768 tokens",
            "the request exceeds the available context size",
            "ValueError: n_ctx is 32768 but the prompt is longer",
            "prompt is too long: 40000 tokens > 32768",
            "max_model_len (32768) exceeded",
        ):
            self._remember()
            assert cw.note_provider_error(said) is True, said
            assert cw._cached(("openai", "http://x/v1", "m")) == (False, None)  # noqa: SLF001

    def test_an_ordinary_failure_retires_nothing(self) -> None:
        self._remember()
        for said in ("Connection refused", "HTTP 503", "", None, "rate limit exceeded"):
            assert cw.note_provider_error(said) is False, said
        assert cw._cached(("openai", "http://x/v1", "m"))[0] is True  # noqa: SLF001

    def test_the_next_question_is_asked_again(self) -> None:
        from maljan.core.config import Settings

        settings = Settings(_env_file=None, llm={"openai": {"base_url": "http://127.0.0.1:1/v1"}})
        _sent_by(lambda: cw.window_for_settings(settings, ["static"]))
        assert _sent_by(lambda: cw.window_for_settings(settings, ["static"])) == []

        cw.note_provider_error("maximum context length is 32768 tokens")

        assert _sent_by(lambda: cw.window_for_settings(settings, ["static"])), "never asked again"


class TestARefusalIsNotASilence:
    def test_the_table_supplies_the_number_and_the_refusal_supplies_the_reason(self) -> None:
        refused = cw.unknown_window(
            "the server description reported 10 tokens; the figure was refused"
        )
        fact = cw._preferred(refused, "gpt-4o")  # noqa: SLF001 - the rule under test

        assert fact is not None
        assert (fact.tokens, fact.source) == (128000, cw.TABLE)
        assert "refused" in fact.detail
        assert "reported no window" not in fact.detail

    def test_a_table_row_with_nothing_to_explain_reads_plainly(self) -> None:
        fact = cw._preferred(None, "gpt-4o")  # noqa: SLF001
        assert fact is not None
        assert "refused" not in fact.detail


class TestTheBudgetOneRunSpends:
    def test_an_empty_budget_reports_the_window_it_was_built_with(self) -> None:
        budget = cw.ContextBudget(cw.WindowFact(32768, cw.PROBED, "props"), reply_tokens=8192)
        assert budget.chars_for_one_answer() == 9216
        snapshot = budget.snapshot()
        assert snapshot["tokens"] == 32768
        assert snapshot["source"] == cw.PROBED
        assert snapshot["chars_per_token"] == cw.CHARS_PER_TOKEN
        assert snapshot["cap_largest"] == 9216

    def test_the_fullest_live_conversation_decides(self) -> None:
        budget = cw.ContextBudget(cw.WindowFact(32768, cw.PROBED, "props"), reply_tokens=8192)
        budget.note_conversation("static", 60_000)
        budget.note_conversation("network", 1_000)
        assert budget.chars_for_one_answer() == cw.MIN_TOOL_OUTPUT_CHARS

    def test_a_finished_loop_stops_binding(self) -> None:
        budget = cw.ContextBudget(cw.WindowFact(32768, cw.PROBED, "props"), reply_tokens=8192)
        budget.note_conversation("static", 60_000)
        budget.forget_conversation("static")
        assert budget.chars_for_one_answer() == 9216

    def test_a_toolkit_without_a_budget_gets_the_documented_constant(self) -> None:
        """Nothing is derived where nothing was measured."""
        assert cw.output_limit(0, None) == cw.UNKNOWN_WINDOW_TOOL_OUTPUT_CHARS

    def test_a_budget_over_an_unknown_window_derives_nothing_either(self) -> None:
        budget = cw.ContextBudget(cw.unknown_window())
        assert budget.derives is False
        assert budget.chars_for_one_answer() == cw.UNKNOWN_WINDOW_TOOL_OUTPUT_CHARS

    def test_the_snapshot_records_the_smallest_and_largest_cap_in_force(self) -> None:
        budget = cw.ContextBudget(cw.WindowFact(32768, cw.PROBED, "props"), reply_tokens=8192)
        budget.chars_for_one_answer()
        budget.note_conversation("static", 60_000)
        budget.chars_for_one_answer()
        snapshot = budget.snapshot()
        assert snapshot["cap_largest"] == 9216
        assert snapshot["cap_smallest"] == cw.MIN_TOOL_OUTPUT_CHARS


class TestTheVendoredTable:
    def test_the_file_says_it_is_a_fallback_and_how_to_correct_it(self) -> None:
        from maljan.core.paths import resolve_data

        raw = json.loads(resolve_data(cw.TABLE_PATH).read_text(encoding="utf-8"))
        note = " ".join(raw["_comment"]).lower()
        assert "fallback" in note
        assert "core.llm.openai.context_size" in note

    def test_every_row_is_a_positive_token_count(self) -> None:
        from maljan.core.paths import resolve_data

        raw = json.loads(resolve_data(cw.TABLE_PATH).read_text(encoding="utf-8"))
        for key, value in raw["windows"].items():
            assert isinstance(value, int) and value > 0, key
            assert key == key.lower(), key


@pytest.mark.parametrize(
    ("provider", "endpoint", "payload", "path", "expected"),
    [
        (
            "openai",
            "http://127.0.0.1:8080/v1",
            {"default_generation_settings": {"n_ctx": 32768}},
            "/props",
            32768,
        ),
        (
            "ollama",
            "http://localhost:11434",
            {"model_info": {"qwen3.context_length": 40960}},
            "/api/show",
            40960,
        ),
    ],
)
def test_a_server_that_answers_is_reported_as_probed(
    provider: str, endpoint: str, payload: dict, path: str, expected: int
) -> None:
    """The transport is a stub; the reading and the wording are the real ones."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path != path:
            return httpx.Response(404, json={})
        return httpx.Response(200, json=payload)

    real_client = httpx.Client

    def stub(**_kwargs: Any) -> httpx.Client:
        return real_client(transport=httpx.MockTransport(handler))

    try:
        httpx.Client = stub  # type: ignore[assignment,misc]
        fact = cw.probe_window(provider, endpoint=endpoint, model="qwen3")
    finally:
        httpx.Client = real_client  # type: ignore[misc]
    assert fact is not None
    assert (fact.tokens, fact.source) == (expected, cw.PROBED)
    assert f"{expected:,}" in fact.detail
