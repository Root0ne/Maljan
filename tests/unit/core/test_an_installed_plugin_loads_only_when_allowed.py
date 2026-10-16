"""An installed provider plugin is judged from its metadata and loaded only once allowed.

A pip-installed package adds an LLM, static, sandbox or memory provider
through the entry-point group of its kind. Nothing of it runs until the
plugin allow-list names it and a process is told to load by that list:
reading a registry loads nothing, listing and judging a provider id read
package metadata only, every shipped provider registers before any plugin is
imported, and a plugin that fails to load is reported with its reason while
the process goes on without it.

The installed packages are stand-ins: entry points with a counted ``load``,
and real dist-infos on ``sys.path`` for the metadata path. Nothing is
installed into the environment.
"""

from __future__ import annotations

import gc
import json
import logging
import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError
from tests.unit._plugin_doubles import (
    AcmeLLM,
    AcmeSandbox,
    AcmeStatic,
    FakePoint,
    HalfStatic,
    NotAProvider,
    OtherStatic,
    allow,
    installed_plugins,
    llm_with_block,
    memory_plugin,
    withdraw_every_plugin,
)

from maljan.core import plugins
from maljan.core.config import Settings
from maljan.llm import registry as llm_registry
from maljan.llm.provider_base import LLMProvider, facts_of, provider_names
from maljan.memory import store_factory
from maljan.memory.in_memory_store import InMemoryStore
from maljan.providers import registry

ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def installed(monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, list[FakePoint]]]:
    """The installed entry points by kind, with this process's plugin state fresh."""
    yield installed_plugins(monkeypatch)
    withdraw_every_plugin()


def _dist_info(root: Path, package: str, version: str, group: str, name: str, source: str) -> None:
    """A package ``package`` with one entry point ``name`` in ``group``, as pip would leave it."""
    module = root / package
    module.mkdir()
    (module / "__init__.py").write_text(source, encoding="utf-8")
    info = root / f"{package}-{version}.dist-info"
    info.mkdir()
    (info / "METADATA").write_text(
        f"Metadata-Version: 2.1\nName: {package.replace('_', '-')}\nVersion: {version}\n",
        encoding="utf-8",
    )
    (info / "entry_points.txt").write_text(
        f"[{group}]\n{name} = {package}:Provider\n", encoding="utf-8"
    )


class TestNothingRunsUntilItIsAllowed:
    def test_the_empty_default_loads_no_installed_plugin(
        self, installed: dict[str, list[FakePoint]]
    ) -> None:
        point = FakePoint("acme", AcmeStatic)
        installed["static"].append(point)
        assert Settings(_env_file=None).plugins.allowed == []
        plugins.load_allowed(Settings(_env_file=None).plugins.allowed)
        assert "acme" not in registry.static_provider_ids()
        assert point.loads == 0

    def test_reading_a_registry_loads_nothing_whatever_the_list_says(
        self, installed: dict[str, list[FakePoint]]
    ) -> None:
        points = {
            "static": FakePoint("acme", AcmeStatic),
            "llm": FakePoint("acme_llm", AcmeLLM),
            "sandbox": FakePoint("acme_sandbox", AcmeSandbox),
            "memory": FakePoint("acme_memory", memory_plugin("acme_memory")),
        }
        for kind, point in points.items():
            installed[kind].append(point)
        plugins.install_allow_list([f"{kind}:{point.name}" for kind, point in points.items()])
        registry.static_provider_ids()
        registry.sandbox_provider_ids()
        provider_names()
        store_factory.memory_backends()
        Settings(_env_file=None, llm={"provider": "acme_llm"})
        assert [point.loads for point in points.values()] == [0, 0, 0, 0]

    def test_an_allowed_plugin_loads_and_an_unallowed_one_does_not(
        self, installed: dict[str, list[FakePoint]], caplog: pytest.LogCaptureFixture
    ) -> None:
        acme = FakePoint("acme", AcmeStatic)
        other = FakePoint("other", OtherStatic, dist="maljan-other", version="0.1")
        installed["static"] += [acme, other]
        with caplog.at_level(logging.INFO):
            allow("static:acme")
        ids = registry.static_provider_ids()
        assert "acme" in ids and "other" not in ids
        assert registry.static_provider_class("acme") is AcmeStatic
        assert (acme.loads, other.loads) == (1, 0)
        assert "Loaded plugin static:acme from maljan-acme 1.2.3." in caplog.text

    def test_each_kind_loads_from_its_own_group(
        self, installed: dict[str, list[FakePoint]]
    ) -> None:
        installed["llm"].append(FakePoint("acme_llm", AcmeLLM))
        installed["sandbox"].append(FakePoint("acme_sandbox", AcmeSandbox))
        installed["memory"].append(FakePoint("acme_memory", memory_plugin("acme_memory")))
        allow("llm:acme_llm", "sandbox:acme_sandbox", "memory:acme_memory")
        assert "acme_llm" in provider_names()
        assert facts_of("acme_llm") is AcmeLLM and AcmeLLM.name == "acme_llm"
        assert "acme_sandbox" in registry.sandbox_provider_ids()
        assert "acme_memory" in store_factory.memory_backends()
        cfg = Settings(_env_file=None, memory={"backend": "acme_memory"})
        assert isinstance(store_factory.build_memory_store(cfg), InMemoryStore)

    def test_a_name_on_the_list_of_another_kind_loads_nothing(
        self, installed: dict[str, list[FakePoint]]
    ) -> None:
        point = FakePoint("acme", AcmeStatic)
        installed["static"].append(point)
        allow("sandbox:acme")
        assert "acme" not in registry.static_provider_ids()
        assert "acme" not in registry.sandbox_provider_ids()
        assert point.loads == 0

    def test_a_plugin_the_list_drops_is_withdrawn_at_the_next_load(
        self, installed: dict[str, list[FakePoint]], caplog: pytest.LogCaptureFixture
    ) -> None:
        installed["static"].append(FakePoint("acme", AcmeStatic))
        installed["llm"].append(FakePoint("acme_llm", AcmeLLM))
        allow("static:acme", "llm:acme_llm")
        assert "acme" in registry.static_provider_ids() and "acme_llm" in provider_names()
        plugins.install_allow_list([])
        # Reading the store's new list withdraws nothing on its own.
        assert "acme" in registry.static_provider_ids()
        with caplog.at_level(logging.WARNING):
            plugins.load_allowed([])
        assert "acme" not in registry.static_provider_ids()
        assert "acme_llm" not in provider_names()
        assert "no longer on the allow-list" in caplog.text
        assert "stays imported" in caplog.text


class TestDiscoveryReadsMetadataOnly:
    def test_a_real_dist_info_is_listed_and_judged_without_importing_its_module(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(plugins, "_STATE", plugins._ProcessState())
        marker = tmp_path / "imported"
        _dist_info(
            tmp_path,
            "acme_listed_plugin",
            "4.5.6",
            "maljan.static_providers",
            "acme_listed",
            f"from pathlib import Path\nPath({str(marker)!r}).write_text('yes')\n"
            "raise RuntimeError('the plugin module was imported')\n",
        )
        monkeypatch.syspath_prepend(str(tmp_path))

        (found,) = [p for p in plugins.installed("static") if p.name == "acme_listed"]
        assert (found.distribution, found.version, found.entry) == (
            "acme-listed-plugin",
            "4.5.6",
            "static:acme_listed",
        )
        static = next(kind for kind in plugins.listing([]) if kind["kind"] == "static")
        (row,) = [row for row in static["plugins"] if row["name"] == "acme_listed"]
        assert row == {
            "name": "acme_listed",
            "entry": "static:acme_listed",
            "distribution": "acme-listed-plugin",
            "version": "4.5.6",
            "allowed": False,
            "state": "not_allowed",
            "error": "",
            "process_state": "",
            "process_error": "",
        }
        assert plugins.accepted_names("static", ["static:acme_listed"]) == {"acme_listed"}
        assert plugins.id_refusal("static", "acme_listed", ["static:acme_listed"]) == ""
        assert "acme_listed_plugin" not in sys.modules
        assert not marker.exists()

    def test_a_real_dist_info_loads_once_allowed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(plugins, "_STATE", plugins._ProcessState())
        _dist_info(
            tmp_path,
            "acme_loaded_plugin",
            "1.0",
            "maljan.static_providers",
            "acme_loaded",
            "from maljan.providers.base import StaticCapabilities, StaticProvider\n"
            "class Provider(StaticProvider):\n"
            "    @classmethod\n"
            "    def from_settings(cls, cfg):\n"
            "        return cls()\n"
            "    @property\n"
            "    def capabilities(self):\n"
            "        return StaticCapabilities()\n",
        )
        monkeypatch.syspath_prepend(str(tmp_path))
        try:
            allow("static:acme_loaded")
            assert "acme_loaded" in registry.static_provider_ids()
            assert registry.static_provider_class("acme_loaded").__module__ == (
                "acme_loaded_plugin"
            )
            assert plugins.records("static")["acme_loaded"].state == "loaded"
        finally:
            withdraw_every_plugin()
            sys.modules.pop("acme_loaded_plugin", None)
        assert "acme_loaded" not in registry.static_provider_ids()


class TestEveryShippedProviderRegistersFirst:
    def test_a_plugin_importing_another_kinds_shipped_modules_loads_and_sees_them(
        self, tmp_path: Path
    ) -> None:
        """In a fresh interpreter, where none of those shipped modules is imported yet."""
        _dist_info(
            tmp_path,
            "acme_cross_plugin",
            "1.0",
            "maljan.static_providers",
            "acme_cross",
            "from maljan.memory import store_factory\n"
            "from maljan.llm.provider_base import provider_names\n"
            "SEEN = {'memory': list(store_factory.memory_backends()), 'llm': provider_names()}\n"
            "from maljan.providers.base import StaticCapabilities, StaticProvider\n"
            "class Provider(StaticProvider):\n"
            "    @classmethod\n"
            "    def from_settings(cls, cfg):\n"
            "        return cls()\n"
            "    @property\n"
            "    def capabilities(self):\n"
            "        return StaticCapabilities()\n",
        )
        script = (
            "import json, sys\n"
            "from maljan.core import plugins\n"
            "assert 'maljan.memory.store_factory' not in sys.modules\n"
            "plugins.load_allowed(['static:acme_cross'], ('static',))\n"
            "import acme_cross_plugin\n"
            "from maljan.memory import store_factory\n"
            "print(json.dumps({'state': plugins.records('static')['acme_cross'].state,\n"
            "  'error': plugins.records('static')['acme_cross'].error,\n"
            "  'seen': acme_cross_plugin.SEEN,\n"
            "  'memory': list(store_factory.memory_backends())}))\n"
        )
        done = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            cwd=tmp_path,
            env={
                "PATH": "/usr/bin:/bin",
                "PYTHONPATH": f"{tmp_path}:{ROOT / 'src'}:{ROOT / 'apps' / 'api'}",
                "HOME": "/nonexistent",
            },
            timeout=300,
            check=True,
        )
        said = json.loads(done.stdout.strip().splitlines()[-1])
        assert (said["state"], said["error"]) == ("loaded", "")
        assert said["seen"]["memory"] == ["memory", "qdrant"]
        assert {"openai", "anthropic", "ollama", "gemini"} <= set(said["seen"]["llm"])
        assert said["memory"] == ["memory", "qdrant"]

    def test_the_built_in_backend_ids_are_the_ones_the_shipped_backends_register(self) -> None:
        shipped = {
            key
            for key, backend in store_factory.registered_backends().items()
            if backend.build.__module__ == store_factory.__name__
        }
        assert shipped == store_factory.BUILT_IN_BACKENDS


class TestABuiltInIdAlwaysWins:
    def test_a_plugin_named_like_a_built_in_is_refused_and_never_imported(
        self, installed: dict[str, list[FakePoint]]
    ) -> None:
        shipped = registry.static_provider_class("ghidra")
        point = FakePoint("ghidra", AcmeStatic)
        installed["static"].append(point)
        allow("static:ghidra")
        assert registry.static_provider_class("ghidra") is shipped
        assert point.loads == 0
        record = plugins.records("static")["ghidra"]
        assert record.state == "refused" and "built-in static provider" in record.error

    def test_a_plugin_that_registers_a_built_in_while_it_loads_is_refused(
        self, installed: dict[str, list[FakePoint]]
    ) -> None:
        shipped = registry.static_provider_class("r2")
        point = FakePoint(
            "acme",
            AcmeStatic,
            on_import=lambda: registry.register_static_provider("r2")(OtherStatic),
        )
        installed["static"].append(point)
        allow("static:acme")
        assert "acme" not in registry.static_provider_ids()
        assert registry.static_provider_class("r2") is shipped
        record = plugins.records("static")["acme"]
        assert record.state == "failed"
        assert "never registers under a built-in id" in record.error

    def test_a_memory_plugin_cannot_take_a_shipped_backend(
        self, installed: dict[str, list[FakePoint]]
    ) -> None:
        shipped = store_factory.registered_backends()["qdrant"]
        installed["memory"].append(FakePoint("acme_memory", memory_plugin("qdrant")))
        allow("memory:acme_memory")
        assert store_factory.registered_backends()["qdrant"] is shipped
        assert (
            "never registers under a built-in id"
            in (store_factory.unavailable_backends()["acme_memory"])
        )

    def test_a_plugin_registers_only_the_name_its_entry_point_gives(
        self, installed: dict[str, list[FakePoint]]
    ) -> None:
        point = FakePoint(
            "acme",
            AcmeStatic,
            on_import=lambda: registry.register_static_provider("stowaway")(OtherStatic),
        )
        installed["static"].append(point)
        allow("static:acme")
        ids = registry.static_provider_ids()
        assert "stowaway" not in ids and "acme" not in ids
        assert "registers only the provider its entry point names" in (
            plugins.records("static")["acme"].error
        )

    def test_two_packages_declaring_one_name_are_both_refused_with_that_cause(
        self, installed: dict[str, list[FakePoint]]
    ) -> None:
        first = FakePoint("acme", AcmeStatic, dist="maljan-acme", version="1.0")
        second = FakePoint("acme", OtherStatic, dist="acme-fork", version="2.0")
        installed["static"] += [first, second]
        allow("static:acme")
        assert "acme" not in registry.static_provider_ids()
        assert (first.loads, second.loads) == (0, 0)
        assert "two installed packages declare it" in plugins.records("static")["acme"].error
        refused = plugins.id_refusal("static", "acme", ["static:acme"])
        assert "two installed packages declare it (acme-fork 2.0 and maljan-acme 1.0)" in refused
        assert "accepted once" not in refused


class TestABrokenPluginIsReportedAndLeftOut:
    def test_an_import_error_is_reported_and_the_others_still_load(
        self, installed: dict[str, list[FakePoint]], caplog: pytest.LogCaptureFixture
    ) -> None:
        installed["static"] += [
            FakePoint("broken", ImportError("acme_sdk is not installed"), dist="maljan-broken"),
            FakePoint("acme", AcmeStatic),
        ]
        with caplog.at_level(logging.WARNING):
            allow("static:broken", "static:acme")
        ids = registry.static_provider_ids()
        assert "acme" in ids and "broken" not in ids
        assert plugins.failures("static") == {"broken": "ImportError: acme_sdk is not installed"}
        assert "static:broken from maljan-broken 1.2.3 failed to load" in caplog.text
        static = next(kind for kind in plugins.listing() if kind["kind"] == "static")
        rows = {row["name"]: row for row in static["plugins"]}
        assert (rows["broken"]["state"], rows["broken"]["process_state"]) == ("allowed", "failed")
        assert rows["broken"]["process_error"] == "ImportError: acme_sdk is not installed"
        assert rows["acme"]["process_state"] == "loaded"

    def test_a_plugin_that_exits_while_it_loads_never_stops_the_process(
        self, installed: dict[str, list[FakePoint]]
    ) -> None:
        installed["sandbox"].append(FakePoint("quitter", SystemExit(3)))
        allow("sandbox:quitter")
        assert "quitter" not in registry.sandbox_provider_ids()
        assert plugins.failures("sandbox") == {"quitter": "SystemExit: 3"}

    def test_what_a_failed_plugin_registered_of_itself_goes_with_it(
        self, installed: dict[str, list[FakePoint]]
    ) -> None:
        def register_then_fail() -> None:
            registry.register_static_provider("acme")(AcmeStatic)
            raise RuntimeError("half imported")

        installed["static"].append(FakePoint("acme", AcmeStatic, on_import=register_then_fail))
        allow("static:acme")
        assert "acme" not in registry.static_provider_ids()
        assert plugins.failures("static") == {"acme": "RuntimeError: half imported"}

    @pytest.mark.parametrize(
        ("kind", "provides", "said"),
        [
            ("static", NotAProvider, "not a subclass of maljan.providers.base.StaticProvider"),
            ("static", HalfStatic, "leaves abstract methods unwritten (capabilities)"),
            ("sandbox", AcmeStatic, "not a subclass of maljan.providers.base.SandboxProvider"),
            ("llm", NotAProvider, "not a subclass of maljan.llm.provider_base.LLMProvider"),
            ("llm", LLMProvider, "has no build_model method"),
            ("memory", "a string", "which is not callable"),
            ("memory", lambda: None, "registered no memory backend named 'acme'"),
        ],
    )
    def test_an_object_that_is_no_provider_of_its_kind_is_refused_with_why(
        self, installed: dict[str, list[FakePoint]], kind: str, provides: Any, said: str
    ) -> None:
        installed[kind].append(FakePoint("acme", provides))
        allow(f"{kind}:acme")
        record = plugins.records(kind)["acme"]
        assert record.state == "failed" and said in record.error

    def test_an_llm_class_that_names_itself_otherwise_is_refused(
        self, installed: dict[str, list[FakePoint]]
    ) -> None:
        class Misnamed(AcmeLLM):
            name = "someone_else"

        installed["llm"].append(FakePoint("acme_llm", Misnamed))
        allow("llm:acme_llm")
        assert "acme_llm" not in provider_names()
        assert "the two must be the same" in plugins.failures("llm")["acme_llm"]

    def test_a_job_naming_a_failed_plugin_says_why(
        self, installed: dict[str, list[FakePoint]]
    ) -> None:
        from maljan.core.exceptions import LLMError
        from maljan.providers.errors import ProviderConfigurationError

        installed["static"].append(FakePoint("broken", ImportError("no sdk")))
        installed["llm"].append(FakePoint("broken_llm", ImportError("no client")))
        allow("static:broken", "llm:broken_llm")
        with pytest.raises(ProviderConfigurationError, match=r"not loaded \(ImportError: no sdk"):
            registry.static_provider_class("broken")
        built = llm_registry.LLMProviderRegistry(
            Settings(_env_file=None, llm={"provider": "broken_llm"})
        )
        with pytest.raises(LLMError, match=r"not loaded \(ImportError: no client"):
            built.build_model()


class TestAMemoryPluginNotAllowed:
    def test_selecting_it_says_the_allow_list_does_not_name_it(
        self, installed: dict[str, list[FakePoint]]
    ) -> None:
        point = FakePoint("vectorhub", memory_plugin("vectorhub"))
        installed["memory"].append(point)
        cfg = Settings(_env_file=None, memory={"backend": "vectorhub"})
        with pytest.raises(store_factory.MemoryBackendNotConfiguredError) as missing:
            store_factory.build_memory_store(cfg)
        assert missing.value.unavailable is True
        assert missing.value.reason == (
            "memory backend 'vectorhub' is unavailable: it is an installed plugin that the "
            "plugin allow-list (core.plugins.allowed) does not name; allow memory:vectorhub "
            "to load it"
        )
        assert point.loads == 0

    def test_an_allowed_name_nothing_installs_is_said(
        self, installed: dict[str, list[FakePoint]]
    ) -> None:
        allow("memory:vectorhub")
        cfg = Settings(_env_file=None, memory={"backend": "vectorhub"})
        with pytest.raises(store_factory.MemoryBackendNotConfiguredError) as missing:
            store_factory.build_memory_store(cfg)
        assert missing.value.unavailable is False
        assert "no installed package declares it" in missing.value.reason

    def test_a_package_registering_it_under_another_entry_point_name_is_named(
        self, installed: dict[str, list[FakePoint]]
    ) -> None:
        installed["memory"].append(
            FakePoint("VectorHub", memory_plugin("vectorhub"), dist="maljan-vectorhub")
        )
        cfg = Settings(_env_file=None, memory={"backend": "vectorhub"})
        with pytest.raises(store_factory.MemoryBackendNotConfiguredError) as missing:
            store_factory.build_memory_store(cfg)
        assert missing.value.unavailable is True
        assert "the installed memory plugins are VectorHub (maljan-vectorhub 1.2.3)" in (
            missing.value.reason
        )
        assert "must be the backend id it registers" in missing.value.reason


class TestTheAllowListHoldsNamesOnly:
    @pytest.mark.parametrize(
        "entry",
        [
            "acme",
            "static:acme_plugin.provider:Provider",
            "static:/opt/plugins/acme",
            "static:Acme",
            "firmware:acme",
            "static:",
            "llm:acme llm",
            "static:acme\n",
            "\nstatic:acme",
        ],
    )
    def test_anything_but_kind_and_name_is_refused(self, entry: str) -> None:
        with pytest.raises(ValidationError, match="is not a plugin name"):
            Settings(_env_file=None, plugins={"allowed": [entry]})
        assert plugins.parse_entry(entry) is None

    def test_a_name_twice_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="named twice"):
            Settings(_env_file=None, plugins={"allowed": ["llm:acme", "llm:acme"]})

    def test_an_installed_name_with_a_trailing_newline_is_never_loaded(
        self, installed: dict[str, list[FakePoint]]
    ) -> None:
        point = FakePoint("acme\n", AcmeStatic)
        installed["static"].append(point)
        allow("static:acme")
        assert "acme" not in registry.static_provider_ids()
        assert point.loads == 0
        static = next(kind for kind in plugins.listing(["static:acme"]) if kind["kind"] == "static")
        (row,) = static["plugins"]
        assert row["state"] == "refused" and "not a provider id" in row["error"]
        assert row["allowed"] is False
        assert static["allowed_absent"] == ["acme"]

    def test_a_refused_stored_list_loads_nothing(
        self, installed: dict[str, list[FakePoint]], caplog: pytest.LogCaptureFixture
    ) -> None:
        point = FakePoint("acme", AcmeStatic)
        installed["static"].append(point)
        refused = ["static:acme", "static:acme.module:Class"]
        with caplog.at_level(logging.WARNING):
            plugins.install_allow_list(refused)
        plugins.load_allowed(refused)
        assert plugins.allow_list() == frozenset()
        assert "acme" not in registry.static_provider_ids()
        assert point.loads == 0
        assert "no installed plugin is loaded until it is fixed" in caplog.text


class TestAProviderIdIsJudgedByMetadataAndTheListInQuestion:
    def test_a_loaded_plugin_is_no_shipped_id_once_the_list_drops_it(
        self, installed: dict[str, list[FakePoint]]
    ) -> None:
        installed["static"].append(FakePoint("acme", AcmeStatic))
        allow("static:acme")
        assert "acme" in registry.static_provider_ids()
        assert "acme" not in plugins.shipped_ids("static")
        assert plugins.id_refusal("static", "acme", ["static:acme"]) == ""
        refused = plugins.id_refusal("static", "acme", [])
        assert "does not name; allow static:acme to load it" in refused

    def test_an_agent_naming_an_allowed_static_plugin_validates_without_importing_it(
        self, installed: dict[str, list[FakePoint]]
    ) -> None:
        point = FakePoint("acme", AcmeStatic)
        installed["static"].append(point)
        agents = {
            "definitions": {
                "checker": {
                    "role": "generic",
                    "label": "Checker",
                    "prompt": "p",
                    "static_provider": "acme",
                }
            }
        }
        built = Settings(_env_file=None, agents=agents, plugins={"allowed": ["static:acme"]})
        assert built.agents.definitions["checker"].static_provider == "acme"
        assert point.loads == 0
        with pytest.raises(ValidationError, match=r"plugin allow-list \(core.plugins.allowed\)"):
            Settings(_env_file=None, agents=agents)

    def test_the_same_settings_are_judged_alike_with_the_plugin_loaded_or_not(
        self, installed: dict[str, list[FakePoint]]
    ) -> None:
        installed["static"].append(FakePoint("acme", AcmeStatic))
        agents = {
            "definitions": {
                "checker": {
                    "role": "generic",
                    "label": "Checker",
                    "prompt": "p",
                    "static_provider": "acme",
                }
            }
        }

        def verdict() -> bool:
            try:
                Settings(_env_file=None, agents=agents, plugins={"allowed": []})
            except ValidationError:
                return False
            return True

        before = verdict()
        allow("static:acme")
        assert verdict() is before is False


class TestACheckOfAnLLMPluginsOwnFactsWaitsForItsLoad:
    def test_a_per_agent_address_and_effort_are_judged_where_the_plugin_is_loaded(
        self, installed: dict[str, list[FakePoint]]
    ) -> None:
        from maljan.core.config import ModelChoice

        installed["llm"].append(FakePoint("acme_llm", llm_with_block("acme_llm")))
        choice = {
            "provider": "acme_llm",
            "model": "acme-xl",
            "base_url": "http://acme.local:9000",
            "effort": "high",
        }
        # Its facts are in its own code: a process that has not loaded it
        # leaves them to the one that does, and checks what it can itself.
        ModelChoice.model_validate(choice)
        with pytest.raises(ValidationError, match="the record holds at most"):
            ModelChoice.model_validate({**choice, "effort": "e" * 400})
        allow("llm:acme_llm")
        with pytest.raises(ValidationError, match="base_url is only supported"):
            ModelChoice.model_validate(choice)
        with pytest.raises(ValidationError, match="effort is only supported"):
            ModelChoice.model_validate({**choice, "base_url": None})

    def test_an_id_no_package_declares_is_judged_at_once(self) -> None:
        from maljan.core.config import ModelChoice

        with pytest.raises(ValidationError, match="base_url is only supported"):
            ModelChoice.model_validate(
                {"provider": "nothing_here", "model": "m", "base_url": "http://x.local"}
            )


class TestADroppedPluginStillSelectedIsNamed:
    def test_each_key_that_selects_it_is_named(self, installed: dict[str, list[FakePoint]]) -> None:
        installed["static"].append(FakePoint("acme", AcmeStatic))
        installed["llm"].append(FakePoint("acme_llm", AcmeLLM))
        core = {
            "static.provider": "acme",
            "llm.provider": "acme_llm",
            "agents.definitions": {"checker": {"static_provider": "acme"}},
            "llm.agents": {
                "static": {
                    "provider": "openai",
                    "model": "m",
                    "fallbacks": [{"provider": "acme_llm", "model": "m"}],
                }
            },
        }
        errors = plugins.dropped_selections(["static:acme", "llm:acme_llm"], [], core)
        assert set(errors) == {
            "core.static.provider",
            "core.llm.provider",
            "core.agents.definitions.checker.static_provider",
            "core.llm.agents.static.fallbacks.0.provider",
            "core.plugins.allowed",
        }
        assert "drops from the plugin allow-list" in errors["core.static.provider"]

    def test_a_drop_nothing_selects_and_a_shipped_id_pass(self) -> None:
        core = {"static.provider": "ghidra", "memory.backend": "qdrant"}
        assert plugins.dropped_selections(["static:ghidra", "static:acme"], [], core) == {}
        assert plugins.dropped_selections(["static:acme"], ["static:acme"], core) == {}


def _timed(work: Callable[[], None]) -> float:
    """The seconds ``work`` takes, the collector held so no sweep is timed."""
    gc.collect()
    gc.disable()
    try:
        began = time.perf_counter()
        work()
        return time.perf_counter() - began
    finally:
        gc.enable()


class TestALongListStaysLinear:
    """Ten times the input takes about ten times as long; a quadratic step would be a hundred."""

    def test_ten_times_the_plugins_and_names(self, installed: dict[str, list[FakePoint]]) -> None:
        def read(count: int) -> Callable[[], None]:
            installed["static"][:] = [FakePoint(f"p{i}", AcmeStatic) for i in range(count)]
            entries = [f"static:p{i}" for i in range(count)]

            def work() -> None:
                assert plugins.allow_list_problem(entries) == ""
                assert len(plugins.accepted_names("static", entries)) == count
                (static,) = [k for k in plugins.listing(entries) if k["kind"] == "static"]
                assert len(static["plugins"]) == count

            return work

        _timed(read(2_000))
        low = min(_timed(read(2_000)) for _ in range(3))
        high = min(_timed(read(20_000)) for _ in range(3))
        print("plugins and names, 2,000 and 20,000:", round(low, 4), round(high, 4))
        assert high < low * 20
        assert all(point.loads == 0 for point in installed["static"])

    def test_a_hostile_entry_is_refused_by_a_quote_of_bounded_length(self) -> None:
        def refuse(length: int) -> Callable[[], None]:
            entry = "static:" + "a" * length

            def work() -> None:
                problem = plugins.allow_list_problem([entry])
                assert "is not a plugin name" in problem and len(problem) < 400

            return work

        _timed(refuse(1_000_000))
        low = min(_timed(refuse(1_000_000)) for _ in range(3))
        high = min(_timed(refuse(10_000_000)) for _ in range(3))
        print("one hostile entry, one and ten million characters:", round(low, 5), round(high, 5))
        assert high < low * 20
        assert "(2000009 characters)" in plugins.allow_list_problem(["static:" + "a" * 2_000_000])
