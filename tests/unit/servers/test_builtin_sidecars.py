"""The two tool sidecars' manifests are the contract an agent calls them by.

``test_builtin_tool_sets`` pins the older sidecars by tool name, because that
is what the move-into-settings claim rested on. These two are pinned by
argument names as well: an argument silently renamed is a tool that stops
working for every agent at once, with nothing anywhere to say why. Regenerate
with ``uv run python scripts/goldens/capture_builtin_tool_sets.py``.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
GOLDEN = ROOT / "tests" / "fixtures" / "golden" / "mcp_tools"

TOOL_SIDECARS = ["analysis", "knowledge"]

_INTERPRETER_MISSING = not sys.executable or not shutil.which(sys.executable)


def _golden(name: str) -> dict:
    return json.loads((GOLDEN / f"{name}.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("name", TOOL_SIDECARS)
def test_the_golden_pins_arguments_and_not_only_names(name: str) -> None:
    payload = _golden(name)
    assert payload["tools"], f"{name} golden is empty"
    assert payload["tools"] == sorted(set(payload["tools"]))
    assert set(payload["arguments"]) == set(payload["tools"]), (
        "every pinned tool must have its argument names pinned too"
    )


def test_the_analysis_golden_carries_the_tools_the_static_analyst_needs() -> None:
    """Named rather than counted: a count moves whenever anything is added,
    and says nothing about whether the capability an analyst depends on is
    still there."""
    tools = set(_golden("analysis")["tools"])
    assert {
        "identify_file",
        "hashes",
        "signing_info",
        "strings",
        "iocs_from_file",
        "pe_info",
        "elf_info",
        "macho_info",
        "apk_info",
        "archive_list",
        "document_info",
        "carve_payloads",
        "yara_scan",
        "sigma_match",
        "capa",
        "floss",
    } <= tools


def test_the_analysis_golden_carries_the_whole_sample_delivery_convention() -> None:
    tools = set(_golden("analysis")["tools"])
    assert {"put_sample", "put_sample_begin", "put_sample_chunk", "put_sample_finish"} <= tools

    arguments = _golden("analysis")["arguments"]
    assert set(arguments["put_sample"]) == {"filename", "content_b64", "sha256"}
    assert set(arguments["put_sample_begin"]) == {"filename", "sha256", "size"}
    assert set(arguments["put_sample_chunk"]) == {"upload_id", "seq", "content_b64"}
    assert set(arguments["put_sample_finish"]) == {"upload_id"}


def test_the_knowledge_golden_carries_the_reference_lookups() -> None:
    tools = set(_golden("knowledge")["tools"])
    assert tools == {
        "capabilities",
        "resolve_technique",
        "attck_lookup",
        "attck_validate",
        "api_capability",
        "lolbin_lookup",
        "family_lookup",
        "similar_cases",
    }


def test_the_network_golden_gained_the_whole_capture_view() -> None:
    """``pcap_summary`` joined the three packet-level tools on the existing
    sidecar rather than moving them somewhere new."""
    tools = set(_golden("network")["tools"])
    assert "pcap_summary" in tools
    assert {"read_pcap_summary", "extract_dns", "extract_http"} <= tools


@pytest.mark.skipif(
    _INTERPRETER_MISSING, reason="no python interpreter available to launch the sidecar"
)
@pytest.mark.parametrize("name", TOOL_SIDECARS)
def test_the_live_sidecar_offers_exactly_the_pinned_manifest(name: str) -> None:
    """A real stdio handshake. Neither sidecar reaches the network to answer
    ``initialize`` or ``tools/list``, so a failure here is a real signal that
    the manifest moved."""
    from scripts.goldens.capture_builtin_tool_sets import SIDECARS, enumerate_stdio_manifest

    from maljan.agents.subprocess_env import child_env

    subdir, allow = SIDECARS[name]
    live = asyncio.run(
        asyncio.wait_for(
            enumerate_stdio_manifest(
                sys.executable,
                [str(ROOT / subdir / "server.py")],
                str(ROOT / subdir),
                child_env(allow=allow),
            ),
            timeout=60.0,
        )
    )

    payload = _golden(name)
    assert sorted(live) == payload["tools"]
    assert {name: sorted(args) for name, args in live.items()} == payload["arguments"]


def test_the_caveats_on_a_measured_number_reach_the_model_that_reads_them() -> None:
    """The sidecar's docstring is the tool description in the default topology.

    ``api_capability`` answers with a measured benign rate and a held-out
    profile count. A model handed those without a glossary can read
    ``held_out_malware_profiles: 6`` as six labelled samples the rule was
    validated against, and no corpus behind this catalogue carries
    technique-level ground truth. The sidecar reuses the in-process docstring
    rather than paraphrasing it, because a paraphrase is one edit from saying
    something the in-process one does not.
    """
    import importlib.util

    from maljan.tools import knowledge as knowledge_tools

    spec = importlib.util.spec_from_file_location(
        "knowledge_sidecar", ROOT / "services" / "knowledge-mcp" / "server.py"
    )
    assert spec is not None and spec.loader is not None
    server = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(server)

    # The *served* description, not ``__doc__``. Flip the two decorators and
    # ``__doc__`` still holds the long text while the registered description is
    # empty, so a test on the attribute protects nothing; this is what a client
    # handshake returns and what the model is handed.
    served = {tool.name: tool.description or "" for tool in asyncio.run(server.mcp.list_tools())}
    # The in-process text whole, then the one sentence every lookup argument
    # carries about quotes.
    in_process = (knowledge_tools.api_capability.__doc__ or "").rstrip()
    assert served["api_capability"].startswith(in_process)
    assert (
        served["api_capability"][len(in_process) :]
        .strip()
        .startswith("Pass ``api_names`` as the raw text or pattern itself, unquoted.")
    )
    # Line wrapping is not the subject; the sentences are.
    described = " ".join(served["api_capability"].split())
    for promise in (
        # What the answer cannot say for itself, so it has to arrive before the
        # call or not at all.
        "asking the wrong one gives a libc symbol a Win32 category",
        "A reference lookup, not an observation",
        "A bare ``suspicious: true`` would be a verdict",
        # What a reader of the numbers has to be told, because the misreading
        # is silent and ends up in a report.
        "in the one direction it was measured in",
        "None of them is a probability that *this* sample is benign",
        "None of the corpora carry technique-level ground truth",
        "carries no ``measured`` key rather than a zero",
    ):
        assert promise in described, promise
    # The field-by-field glossary is gone: every key in the answer names its own
    # direction, `corpora` ships the corpus sentences, and a description paid
    # for in every prompt should not repeat what the payload already says.
    assert "seen_on_benign_percent" not in described
    assert len(described) < 2600


@pytest.mark.parametrize("name", TOOL_SIDECARS)
def test_the_sidecar_is_registered_as_a_built_in_with_the_launch_parameters_it_needs(
    name: str,
) -> None:
    from maljan.core.config import BUILTIN_SERVER_KEYS, RESERVED_SERVER_KEYS, Settings

    assert name in BUILTIN_SERVER_KEYS
    assert name in RESERVED_SERVER_KEYS
    server = Settings(_env_file=None).mcp.servers[name]
    assert server.enabled is True
    assert server.transport == "stdio"
    assert server.command == sys.executable
    assert server.args == [f"services/{name}-mcp/server.py"]
    assert server.cwd == f"services/{name}-mcp"
    assert server.tools is None, "a built-in exposes its whole manifest"
    assert server.agents == [], (
        "a tool sidecar binds through the definitions' tool references only, "
        "so a definition that drops the reference really loses the tools"
    )


def test_only_the_analysis_sidecar_is_allowed_to_see_the_staging_directory() -> None:
    """The staging variables say where uploads land and how long they are
    kept, and no other built-in has any business reading either.

    ``MALJAN_SAMPLE_ROOTS`` is the exception both file-reading sidecars need:
    it is the list of directories they may read a path argument in, and a
    server that cannot see it reads only what it staged itself. The knowledge
    sidecar takes no path at all, so it sees neither, and the one variable it
    does see says nothing about the filesystem.
    """
    from maljan.core.config import Settings

    servers = Settings(_env_file=None).mcp.servers
    assert servers["analysis"].env_allow == [
        "MALJAN_STAGING_DIR",
        "MALJAN_STAGING_TTL_HOURS",
        "MALJAN_SAMPLE_ROOTS",
    ]
    assert servers["network"].env_allow == ["MALJAN_STAGING_DIR", "MALJAN_SAMPLE_ROOTS"]
    assert servers["knowledge"].env_allow == ["MALJAN_INDEX_RETRY_SECONDS"]


@pytest.mark.skipif(
    _INTERPRETER_MISSING, reason="no python interpreter available to launch the sidecar"
)
def test_the_index_retry_interval_reaches_the_knowledge_sidecar() -> None:
    """The sidecar is the process where the ATT&CK index is actually built, so
    an operator who sets the interval to zero has to reach it here. Proved
    through a real stdio handshake against a child started the way the
    registry starts it, reading the value back out of the running process."""
    import json
    import subprocess

    from maljan.agents.subprocess_env import child_env
    from maljan.core.config import REQUIRED_ENV_ALLOW, Settings
    from maljan.tools.knowledge import INDEX_RETRY_ENV

    assert INDEX_RETRY_ENV in REQUIRED_ENV_ALLOW["knowledge"]
    assert INDEX_RETRY_ENV in Settings(_env_file=None).mcp.servers["knowledge"].env_allow

    env = child_env(allow=(INDEX_RETRY_ENV,), source={**os.environ, INDEX_RETRY_ENV: "0"})
    assert env[INDEX_RETRY_ENV] == "0"
    probe = (
        "import json,runpy,sys;"
        "sys.argv=['server.py'];"
        "m=runpy.run_path('server.py');"
        "print(json.dumps({'retry': m['knowledge_tools']._RETRY_AFTER_SECONDS}))"
    )
    done = subprocess.run(
        [sys.executable, "-c", probe],
        cwd=str(ROOT / "services" / "knowledge-mcp"),
        env={**env, "PYTHONPATH": str(ROOT / "src")},
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert done.returncode == 0, done.stderr[-2000:]
    assert json.loads(done.stdout.strip().splitlines()[-1]) == {"retry": 0.0}


@pytest.mark.skipif(
    _INTERPRETER_MISSING, reason="no python interpreter available to launch the sidecar"
)
def test_a_sidecar_that_is_told_nothing_keeps_the_module_default() -> None:
    import json
    import subprocess

    from maljan.agents.subprocess_env import child_env

    env = child_env(source={k: v for k, v in os.environ.items()})
    probe = (
        "import json,runpy,sys;"
        "sys.argv=['server.py'];"
        "m=runpy.run_path('server.py');"
        "print(json.dumps({'retry': m['knowledge_tools']._RETRY_AFTER_SECONDS}))"
    )
    done = subprocess.run(
        [sys.executable, "-c", probe],
        cwd=str(ROOT / "services" / "knowledge-mcp"),
        env={**env, "PYTHONPATH": str(ROOT / "src")},
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert done.returncode == 0, done.stderr[-2000:]
    assert json.loads(done.stdout.strip().splitlines()[-1]) == {"retry": 900.0}


def test_the_container_is_the_one_place_that_announces_the_retry_interval() -> None:
    """A sidecar started from any entry point reads the deployment's number.

    It used to be announced from ``MaljanApp.arun``, which is one entry point
    of several: a container built by a script, a test harness or the API
    started its knowledge sidecar with the module default instead of the
    configured interval. The container builds the sidecar registry, so it is
    where the value is put into the environment ``child_env`` filters.
    """
    import ast
    import os
    import pathlib

    from maljan.core.config import Settings
    from maljan.core.container import ServiceContainer
    from maljan.tools.knowledge import INDEX_RETRY_ENV

    config = Settings(_env_file=None)
    config.validation.index_retry_seconds = 1234
    before = os.environ.get(INDEX_RETRY_ENV)
    try:
        ServiceContainer(config=config, mock=True)
        assert os.environ[INDEX_RETRY_ENV] == "1234"
    finally:
        if before is None:
            os.environ.pop(INDEX_RETRY_ENV, None)
        else:
            os.environ[INDEX_RETRY_ENV] = before

    # And in one place only: nothing else in the tree writes the name.
    writers: list[str] = []
    root = pathlib.Path(__file__).resolve().parents[3] / "src" / "maljan"
    for path in root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            for target in node.targets:
                if (
                    isinstance(target, ast.Subscript)
                    and isinstance(target.value, ast.Attribute)
                    and target.value.attr == "environ"
                    and "INDEX_RETRY_ENV" in ast.unparse(target.slice)
                ):
                    writers.append(str(path.relative_to(root)))

    assert writers == ["core/container.py"], writers
