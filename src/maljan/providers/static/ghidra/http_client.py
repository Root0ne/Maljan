"""HTTP client for GhidraMCP Headless Server.

Converts the server's REST API (/mcp/schema) into LangChain StructuredTool
objects so that StaticAnalyst can use Ghidra analysis endpoints without
requiring a local stdio subprocess.

Usage:
    client = GhidraHTTPClient(base_url="http://localhost:8089",
                              auth_token="secret")
    await client.initialize()
    tools = client.get_tools()
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence
from typing import Any

import httpx
from langchain_core.tools import BaseTool, StructuredTool

from maljan.agents.mcp_client import tool_error_marker
from maljan.agents.null_arguments import argument_model, params_rules
from maljan.agents.output_shortening import narrowing_arguments
from maljan.core.logger import logger
from maljan.providers.server_guard import transport_failure
from maljan.tools.errors import SERVER_WORDS_LIMIT

# What a character cut leaves behind, and the room kept back for it.
#
# The marker goes *inside* the limit rather than after it, which is the same
# rule ``output_shortening.shorten_target`` follows for the notice a shortened
# answer carries: the limit is how much may reach the model, and the marker
# reaches the model. Appended after the cut instead, it left twenty characters
# a call unaccounted — self-correcting between model turns, because the next
# measurement sees the true size, and not self-correcting inside one, where
# every answer of a wide fan-out leaked its own.
TRUNCATION_MARKER = "\n\n[OUTPUT TRUNCATED]"


def tool_name_of_path(path: str) -> str:
    """The tool name an endpoint path becomes: the leading slash dropped, ``/`` read as ``_``."""
    return str(path).lstrip("/").replace("/", "_")


def schema_tool_names(schema: Any) -> list[str]:
    """The tool names this client derives from a server's ``/mcp/schema`` answer."""
    entries = schema.get("tools", []) if isinstance(schema, dict) else []
    names: list[str] = []
    for entry in entries:
        path = str(entry.get("path", "")) if isinstance(entry, dict) else ""
        if path:
            names.append(tool_name_of_path(path))
    return names


def truncation_target(limit: int) -> int:
    """How much of an answer a character cut keeps, so the marker fits the limit."""
    return max(0, int(limit) - len(TRUNCATION_MARKER))


# What Ghidra says, in some builds as bare text, when a call needs a program
# and none is current. Matched as the whole answer, case aside.
NO_PROGRAM_LOADED = "no program loaded"


def no_program_as_error(text: str, tool: str) -> str:
    """``text``, or the failure marker for a bare "No program loaded" answer.

    Ghidra answers a call made with no program current with HTTP 200. The
    JSON form, ``{"error": "No program loaded."}``, is already a failed call
    to the ledger (``tools.errors.error_parts``); a build that answers with the
    bare sentence reached the ledger as a successful call whose output was
    that sentence. It is handed on as the MCP client hands on a tool's error
    reply, with the server's words as the detail. Only an answer that is that
    sentence and nothing else, trimmed and with or without its full stop; any
    other answer, one that merely begins with it included, is returned exactly
    as it came.
    """
    stripped = text.strip()
    if stripped.rstrip(".").strip().lower() == NO_PROGRAM_LOADED:
        return tool_error_marker("tool_returned_error", tool, detail=stripped)
    return text


class GhidraHTTPClient:
    """Client that discovers and calls GhidraMCP headless REST endpoints."""

    def __init__(
        self,
        base_url: str,
        auth_token: str = "",
        output_guardrail: Any | None = None,
        max_output_chars: int = 0,
        truncation_ledger: Any | None = None,
        context_budget: Any | None = None,
        long_running_tools: frozenset[str] = frozenset(),
        explicit_call_timeout: float = 0.0,
        categories: Mapping[str, str] | None = None,
        guard: Any | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        # The rule every tool server's guard applies (``ServerGuard.call_timeout``),
        # for this client's own transport: a long-running tool (the open and
        # analysis tools the server's block declares, ``sample_open``) waits as
        # long as Ghidra takes, unless the operator set a per-call budget
        # (``mcp.breaker.call_timeout_seconds``); every other call keeps the
        # client's own request timeout.
        self._long_running = frozenset(t for t in long_running_tools if t)
        self._explicit_call_timeout = max(0.0, float(explicit_call_timeout or 0.0))
        # The job's breaker and call cap for this server, the one every other
        # tool server's calls go through (``maljan.providers.server_guard``).
        # None outside a job's settings, and every call is then sent as it was.
        self._guard = guard
        # The tag each tool's description is shown with, as Ghidra's block
        # declares it (``ToolFacts.category``).
        self._categories = dict(categories or {})
        # Callers pass a plain string (``SecretStr.get_secret_value()`` already
        # unwrapped at the config boundary); stored plain here too, since this
        # client builds the header string itself.
        self.auth_token = auth_token
        self._tools: list[BaseTool] = []
        self._schema: list[dict[str, Any]] = []
        self._output_guardrail = output_guardrail
        # Zero is the ordinary case and means "ask the budget below". A
        # positive number is the operator's own cap and wins over it.
        self._max_output_chars = max_output_chars
        # Optional TruncationLedger (pitfall P6); None disables counting. This is
        # the production Ghidra transport, so this is where the numbers come from.
        self._truncation_ledger = truncation_ledger
        # The job's context budget, which knows the window the served model has
        # and what the conversation currently holds. None outside a job, and the
        # conservative window then answers.
        self._context_budget = context_budget
        # Single long-lived AsyncClient — re-using the connection pool across
        # tool calls cuts TLS/TCP handshake overhead and avoids the previous
        # "new client per tool call" anti-pattern.
        self._http: httpx.AsyncClient | None = None

    def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.auth_token}"} if self.auth_token else {}

    async def _get_http(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(timeout=60.0, headers=self._auth_headers())
        return self._http

    async def aclose(self) -> None:
        """Close the underlying httpx client (idempotent)."""
        if self._http is not None:
            try:
                await self._http.aclose()
            finally:
                self._http = None

    async def initialize(self) -> None:
        """Fetch /mcp/schema and build LangChain tools."""
        client = await self._get_http()
        resp = await client.get(f"{self.base_url}/mcp/schema")
        resp.raise_for_status()
        schema = resp.json()

        self._schema = schema.get("tools", [])
        for tool_def in self._schema:
            lc_tool = self._create_langchain_tool(tool_def)
            self._tools.append(lc_tool)

        logger.info(
            "GhidraHTTPClient loaded %d tools from %s",
            len(self._tools),
            self.base_url,
        )

    def get_tools(self) -> list[BaseTool]:
        """Return the list of LangChain tools."""
        return self._tools

    def _create_langchain_tool(self, tool_def: dict[str, Any]) -> BaseTool:
        """Convert a GhidraMCP schema entry into a LangChain StructuredTool."""
        path: str = tool_def["path"]
        method: str = tool_def.get("method", "GET").upper()
        description: str = tool_def.get("description", f"Call {path}")
        params: list[dict[str, Any]] = tool_def.get("params", [])

        # A category tag in front of the full description lets the model scan
        # tool families quickly.
        description = self._tag_description(path, description)

        # Build Pydantic args schema
        properties: dict[str, tuple[Any, Any]] = {}
        for p in params:
            name: str = p["name"]
            ptype: str = p.get("type", "string")
            required: bool = p.get("required", False)

            type_mapping = {
                "string": str,
                "integer": int,
                "number": float,
                "boolean": bool,
                "json": str,
                "array": list,
                "object": dict,
            }
            py_type = type_mapping.get(ptype, Any)
            default_val = ... if required else None
            properties[name] = (py_type, default_val)

        # An optional parameter given ``null`` is the parameter left out
        # (``agents.null_arguments``): it takes its default, ``None``, which
        # ``_call_endpoint`` does not send, so Ghidra applies its own. A
        # required one given ``null`` is refused as before.
        args_schema = argument_model(
            f"GhidraTool_{path.lstrip('/').replace('/', '_')}Schema",
            properties,
            params_rules(params),
        )

        async def arun_tool(
            _path: str = path,
            _method: str = method,
            _params: list[dict[str, Any]] = params,
            **kwargs: Any,
        ) -> str:
            return await self._call_endpoint(_path, _method, _params, kwargs)

        # Use the last path segment as a concise name
        tool_name = tool_name_of_path(path)

        return StructuredTool.from_function(
            func=None,
            coroutine=arun_tool,
            name=tool_name,
            description=description,
            args_schema=args_schema,
        )

    async def _send(
        self,
        method: str,
        url: str,
        query: dict[str, Any],
        body: dict[str, Any],
        tool: str,
        path: str,
        timeout: Any,
        *,
        on_failure: Any = None,
    ) -> str:
        """One request, as the answer a model reads; ``on_failure`` hears of a transport failure."""
        client = await self._get_http()
        try:
            if method == "POST":
                resp = await client.post(
                    url,
                    params=query,
                    json=body,
                    headers={"Content-Type": "application/json"},
                    timeout=timeout,
                )
            else:
                resp = await client.get(url, params=query, timeout=timeout)
            resp.raise_for_status()
            return no_program_as_error(resp.text, tool)
        except httpx.HTTPStatusError as exc:
            return tool_error_marker(
                "http_status",
                tool,
                status=str(exc.response.status_code),
                path=path,
                detail=" ".join(exc.response.text.split())[:SERVER_WORDS_LIMIT],
            )
        except httpx.RequestError as exc:
            if on_failure is not None:
                on_failure(exc)
            return tool_error_marker("request_failed", tool, type=type(exc).__name__, path=path)

    async def _send_guarded(
        self,
        guard: Any,
        method: str,
        url: str,
        query: dict[str, Any],
        body: dict[str, Any],
        tool: str,
        path: str,
        timeout: Any,
    ) -> str:
        """:meth:`_send` through the server's breaker and call cap.

        A server that answered, even with its own error status, is up; a
        request that never got an answer counts toward the rest, as it does
        for every other tool server. A sent call its caller's budget cut off
        counts as one the server did not answer, unless the tool is
        long-running (it has no clock of its own, so its caller stopping is no
        verdict on the server); one cancelled while it queued for a slot was
        never sent and is nothing.
        """
        refused, trial = guard.admit(tool)
        if refused is not None:
            return str(refused)
        sent = False
        settled = False

        def failed(exc: BaseException) -> None:
            nonlocal settled
            reason = transport_failure(exc)
            if reason is not None:
                guard.failed(reason, trial=trial)
                settled = True

        try:
            async with guard.slot():
                if not trial:
                    refused, trial = guard.admit(tool)
                    if refused is not None:
                        return str(refused)
                sent = True
                output = await self._send(
                    method, url, query, body, tool, path, timeout, on_failure=failed
                )
                if not settled:
                    guard.answered()
                    settled = True
                return output
        except BaseException as exc:
            if not settled:
                if (
                    sent
                    and isinstance(exc, asyncio.CancelledError)
                    and not guard.long_running(tool)
                ):
                    guard.failed("the call did not finish within its caller's budget", trial=trial)
                else:
                    guard.abandoned(trial=trial)
            raise

    async def _call_endpoint(
        self,
        path: str,
        method: str,
        param_defs: list[dict[str, Any]],
        kwargs: dict[str, Any],
    ) -> str:
        """Execute a single HTTP request against a GhidraMCP endpoint."""
        url = f"{self.base_url}{path}"
        query: dict[str, Any] = {}
        body: dict[str, Any] = {}

        for pdef in param_defs:
            pname = pdef["name"]
            psource = pdef.get("source", "query")
            if pname in kwargs and kwargs[pname] is not None:
                if psource == "body":
                    body[pname] = kwargs[pname]
                else:
                    query[pname] = kwargs[pname]

        tool = path.lstrip("/").replace("/", "_")
        timeout: Any = httpx.USE_CLIENT_DEFAULT
        if tool in self._long_running:
            timeout = self._explicit_call_timeout or None
        guard = self._guard
        if guard is None:
            output = await self._send(method, url, query, body, tool, path, timeout)
        else:
            output = await self._send_guarded(guard, method, url, query, body, tool, path, timeout)

        if path == "/load_program":
            await self._activate_loaded_program(output)

        # On a thread: shortening a large answer is CPU-bound and synchronous,
        # and this is a coroutine serving an agent.
        narrowing = narrowing_arguments(pdef["name"] for pdef in param_defs)
        return await asyncio.to_thread(self._apply_output_guardrail, output, narrowing)

    async def _activate_loaded_program(self, load_output: str) -> None:
        """Make a freshly loaded program the *current* one.

        ``load_program`` imports the binary and reports success, but it only
        sets Ghidra's current program when nothing is current yet — the first
        load after a restart. Every later load leaves the server looking at the
        first binary of the container's lifetime, so an agent that loads its
        sample and then decompiles, lists imports or walks the call graph is
        reading a different file entirely, with no error anywhere to say so.

        Measured 2026-08-10: two samples of 241 KB and 139 KB yielded call
        graphs identical to the character until this call was added.

        Best-effort by construction. A stale current program is a wrong answer;
        an exception raised here would be a failed analysis, which is worse.
        """
        from maljan.providers.static.ghidra.program import (
            program_name_from_load,
            switch_is_confirmed,
        )

        name = program_name_from_load(load_output)
        if not name:
            return
        try:
            text = await self._switch_program(name)
            if not switch_is_confirmed(text, name):
                logger.warning(
                    "Ghidra switch_program did not confirm '%s' (%s) — subsequent tool "
                    "calls may read the previously loaded program.",
                    name,
                    text[:160],
                )
        except Exception as exc:  # noqa: BLE001 — never fail an analysis over this
            logger.warning("Ghidra switch_program failed for '%s' (non-fatal): %s", name, exc)

    async def _switch_program(self, name: str) -> str:
        """The answer of ``switch_program`` for ``name``, through the guard when there is one."""
        from maljan.providers.static.ghidra.program import SWITCH_PARAM, SWITCH_PATH

        tool = SWITCH_PATH.lstrip("/").replace("/", "_")
        url = f"{self.base_url}{SWITCH_PATH}"
        query = {SWITCH_PARAM: name}
        if self._guard is None:
            client = await self._get_http()
            resp = await client.post(
                url, params=query, json={}, headers={"Content-Type": "application/json"}
            )
            return resp.text
        return await self._send_guarded(
            self._guard, "POST", url, query, {}, tool, SWITCH_PATH, httpx.USE_CLIENT_DEFAULT
        )

    def _tag_description(self, path: str, description: str) -> str:
        """Prefix the description with its category tag; the text itself is kept whole.

        The tag Ghidra's block declares for the tool, else the one its name's
        first word gives (``core.undeclared_tools.category_tag``).
        """
        from maljan.core.undeclared_tools import category_tag

        name = path.lstrip("/").replace("/", "_")
        clean = " ".join(description.split())
        return f"[{category_tag(name, self._categories.get(name, ''))}] {clean}"

    def _charge_overage(self, kept: int, limit: int) -> str:
        """Charge what a result is longer than the cap it was measured against.

        The budget reserved ``limit`` when it granted the cap, and two branches
        can hand back more than that: the character cut appends its marker
        after cutting, and a summariser may legitimately expand a short input.
        Twenty characters a call sounds like nothing and is not — within one
        model turn, where no measurement intervenes, every granted answer leaks
        its marker, and the run's own account of what the conversation holds
        drifts from what is in it. The ledger already records the real length;
        this makes the budget agree with it.

        Returns nothing useful; it is called for the charge.
        """
        from maljan.llm.context_window import ContextBudget

        budget = getattr(self, "_context_budget", None)
        over = max(0, int(kept) - int(limit))
        if over and isinstance(budget, ContextBudget):
            budget.charge(over)
        return ""

    def _no_room(self, chars_in: int) -> str:
        """The sentence a conversation with no room left gets, said once.

        Charged to the budget, because it is text that enters the conversation
        like any answer, and the agent is marked so its tool phase ends rather
        than paying for this sentence on every remaining round.

        Withheld when it would not fit, on the same rule as the shorter line a
        later call gets: a conversation already at its budget took a constant
        few hundred characters to be told it had none, which is the one claim
        this design makes about its own text and has to hold for the long
        sentence as well as the short one. The agent is marked either way —
        the phase ends whether or not there was room to say so.
        """
        from maljan.llm.context_window import ContextBudget, no_room_sentence

        said = no_room_sentence(chars_in)
        budget = getattr(self, "_context_budget", None)
        if not isinstance(budget, ContextBudget):
            return said
        budget.note_no_room()
        if not budget.room_for(len(said)):
            return ""
        budget.charge(len(said))
        return said

    def _apply_output_guardrail(self, output: str, narrowing: Sequence[str] = ()) -> str:
        """Limit tool output size to prevent LLM context overflow.

        The limit is ``_max_output_chars`` when the operator set one, and
        otherwise what the served model's context window has left for one
        answer at this moment (``maljan.llm.context_window.output_limit``),
        read once so the whole of one call's decision is taken against one
        number.

        A limit of zero is not "cut to nothing": it is the conversation having
        no room left for a tool answer at all. The model is handed one sentence
        saying so — a deterministic fact about this conversation — and the call
        is said to be cut (``note_answer_not_shown``), so its ledger entry is
        recorded as cut rather than as a successful empty answer.

        ``narrowing`` names this tool's own arguments that reach what a
        shortening leaves out. The recorder appends a sentence naming them to a
        shortened answer, and the room that sentence needs is kept back here
        through the same ``shorten_target`` the MCP toolkit uses, so the claim
        that an answer and its notice fit the limit holds on both tool paths.

        Every outcome is recorded on ``_truncation_ledger`` when one is attached,
        including the pass-through: pitfall P6 asks for truncation *frequency*,
        and a frequency needs its denominator.

        A JSON answer over the limit only because of its whitespace is handed
        over whole, written without it, and counted as ``compacted``; only a
        compact form that still does not fit is shortened.

        A JSON object is shortened as a document: elements come off the end of
        its largest lists, then characters off the end of its largest long
        strings, until it fits, and one reserved key says what was left out
        (``maljan.agents.output_shortening``). A cut made in characters ends a
        document mid-array, which reaches the model as a prefix it cannot read
        the metadata of and the ledger as prose with no ``structured`` at all.

        This runs **before** the summariser, and for a JSON object it is the
        better of the two: the summariser answers in English prose, and prose
        is exactly what leaves the record with nothing structured in it. A
        decompilation that arrives as plain text still reaches the summariser
        and then the character cut, which keeps back the room of the
        completeness line the recorder appends to a cut answer
        (``schemas.answer_completeness.cut_line_room``).
        """
        from maljan.agents.output_shortening import shorten_json_document, shorten_target
        from maljan.agents.tool_fence import cut_length, view_room
        from maljan.core.truncation_ledger import record_guardrail_outcome
        from maljan.llm.context_window import (
            note_answer_line_room,
            note_answer_not_shown,
            note_answer_whole,
            output_limit,
        )
        from maljan.schemas.answer_completeness import cut_line_room, shortened_line_room

        chars_in = len(output)
        limit = output_limit(self._max_output_chars, self._context_budget)

        if limit <= 0:
            note_answer_whole(output)
            note_answer_not_shown(chars_in)
            said = self._no_room(chars_in)
            record_guardrail_outcome(
                self._truncation_ledger,
                chars_in=chars_in,
                chars_kept=len(said),
                over_limit=True,
                no_room=True,
                limit=limit,
            )
            return said

        # An answer is shown through one view (``agents.tool_fence``): a text
        # answer fenced, a JSON one with its raw breaks escaped. The answer and
        # what the view adds together are what has to fit.
        fence = view_room(output)
        if chars_in + fence <= limit:
            record_guardrail_outcome(
                self._truncation_ledger,
                chars_in=chars_in,
                chars_kept=chars_in,
                over_limit=False,
                limit=limit,
            )
            return output

        # The answer as the tool gave it, for the call's entry to keep whole
        # when what follows cuts it (``schemas.evidence_spill``).
        note_answer_whole(output)
        logger.warning(
            "Ghidra tool output exceeds limit (%d > %d chars). Applying guardrail.",
            chars_in,
            limit,
        )

        # The completeness line under a shortened document is kept back from
        # the shortening's target as its sentence is, so the answer, the
        # sentence and the line together are inside the limit; the compact
        # form is still measured against the limit itself.
        # Kept back only while the shortening still has a target left;
        # otherwise the line is charged by the recorder.
        target = shorten_target(limit, narrowing) - shortened_line_room(output, narrowing)
        line_kept_back = target >= 1
        if not line_kept_back:
            target = shorten_target(limit, narrowing)
        attempt = shorten_json_document(output, target, cap=limit)
        if attempt.shortened and line_kept_back:
            note_answer_line_room()
        if attempt.compacted:
            record_guardrail_outcome(
                self._truncation_ledger,
                chars_in=chars_in,
                chars_kept=len(attempt.text),
                over_limit=True,
                compacted=True,
                limit=limit,
            )
            return attempt.text
        if attempt.shortened:
            self._charge_overage(len(attempt.text), limit)
            record_guardrail_outcome(
                self._truncation_ledger,
                chars_in=chars_in,
                chars_kept=len(attempt.text),
                over_limit=True,
                shortened=True,
                limit=limit,
            )
            return attempt.text

        if self._output_guardrail is not None:
            try:
                summarised: str = self._output_guardrail(output)
            except Exception as exc:
                logger.warning("Output guardrail failed: %s - falling back to truncation.", exc)
            else:
                # The completeness line the recorder appends to a cut answer
                # (``schemas.answer_completeness``) enters the conversation too.
                self._charge_overage(
                    len(summarised) + view_room(summarised) + cut_line_room(chars_in, narrowing),
                    limit,
                )
                note_answer_line_room()
                record_guardrail_outcome(
                    self._truncation_ledger,
                    chars_in=chars_in,
                    chars_kept=len(summarised),
                    over_limit=True,
                    summarised=True,
                    limit=limit,
                )
                return summarised

        # The kept part is text and fenced: the fence and the escapes inside
        # the kept part, never the whole answer's, are kept back, and so is the
        # completeness line the recorder appends to it, so the answer and the
        # line together are inside the limit.
        # Kept back only while some of the answer still fits beside it; a
        # limit too small for both keeps the answer's place, as it always
        # did, and the recorder charges the line instead.
        room = cut_line_room(chars_in, narrowing)
        kept = cut_length(output, max(0, truncation_target(limit) - room))
        if kept > 0:
            note_answer_line_room()
        else:
            kept = cut_length(output, truncation_target(limit))
        result = output[:kept] + TRUNCATION_MARKER
        self._charge_overage(len(result) + view_room(result), limit)
        record_guardrail_outcome(
            self._truncation_ledger,
            chars_in=chars_in,
            chars_kept=len(result),
            over_limit=True,
            hard_truncated=True,
            shortening_timed_out=attempt.timed_out,
            limit=limit,
        )
        return result
