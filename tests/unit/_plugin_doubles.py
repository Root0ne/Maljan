"""Stand-ins for installed provider plugins: entry points with a counted ``load``.

Nothing is installed into the environment: ``installed_plugins`` makes the
plugin helper read these entry points as package metadata would list them,
with this process's plugin state fresh, and ``withdraw_every_plugin`` takes
whatever a test loaded out of the registries again.
"""

from __future__ import annotations

from collections.abc import Callable
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import BaseModel

from maljan.core import plugins
from maljan.llm.provider_base import LLMProvider
from maljan.memory import store_factory
from maljan.memory.in_memory_store import InMemoryStore
from maljan.providers.base import (
    SandboxCapabilities,
    SandboxProvider,
    StaticCapabilities,
    StaticProvider,
)


class FakePoint:
    """An installed entry point as ``importlib.metadata`` lists it; every load is counted.

    ``on_import`` stands for what importing the plugin's module does before
    ``provides`` is handed back; ``provides`` an exception is an import that fails.
    """

    def __init__(
        self,
        name: str,
        provides: Any,
        *,
        dist: str = "maljan-acme",
        version: str = "1.2.3",
        on_import: Callable[[], None] | None = None,
    ) -> None:
        self.name = name
        self.value = f"acme_plugin:{name}"
        self.dist = SimpleNamespace(name=dist, version=version)
        self.provides = provides
        self.on_import = on_import
        self.loads = 0

    def load(self) -> Any:
        self.loads += 1
        if self.on_import is not None:
            self.on_import()
        if isinstance(self.provides, BaseException):
            raise self.provides
        return self.provides


class AcmeStatic(StaticProvider):
    title = "Acme static"

    @classmethod
    def from_settings(cls, cfg: Any) -> AcmeStatic:
        return cls()

    @property
    def capabilities(self) -> StaticCapabilities:
        return StaticCapabilities()


class OtherStatic(AcmeStatic):
    title = "Other static"


class HalfStatic(StaticProvider):
    """A static provider that leaves ``capabilities`` unwritten."""

    @classmethod
    def from_settings(cls, cfg: Any) -> HalfStatic:
        return cls()


class AcmeSandbox(SandboxProvider):
    @classmethod
    def from_settings(cls, cfg: Any) -> AcmeSandbox:
        return cls()

    @property
    def capabilities(self) -> SandboxCapabilities:
        return SandboxCapabilities()


class AcmeLLM(LLMProvider):
    label = "Acme models"

    def __init__(self, config: Any) -> None:
        self.config = config

    def build_model(self, model: str, temperature: float, **kwargs: Any) -> Any:
        return SimpleNamespace(model=model)


class AcmeLLMSettings(BaseModel):
    """An LLM plugin's own block, ``llm.<name>``: where its role models are named."""

    expert_model: str = "acme-expert"
    judge_model: str = "acme-judge"


def llm_with_block(name: str) -> type[LLMProvider]:
    """A fresh LLM plugin class named ``name`` that keeps its role models in ``llm.<name>``."""
    made: type[LLMProvider] = type(
        f"AcmeBlockLLM_{name}", (AcmeLLM,), {"name": name, "settings_model": AcmeLLMSettings}
    )
    return made


class NotAProvider:
    pass


def memory_plugin(name: str) -> Callable[[], None]:
    """What a memory plugin's entry point names: a callable that registers ``name``."""

    def register() -> None:
        store_factory.register_memory_backend(name, lambda _memory: InMemoryStore())

    return register


def ends_the_process(kind: str, name: str, imported: list[str]) -> FakePoint:
    """An installed plugin of ``kind`` whose import ends the process it runs in.

    Importing it is recorded in ``imported`` and fails the test that did it,
    so a path that leaves ``imported`` empty imports nothing of it.
    """

    def end() -> None:
        imported.append(f"{kind}:{name}")
        pytest.fail(f"plugin {kind}:{name} was imported, which ends the process")

    provides: Any = {
        "llm": llm_with_block(name),
        "static": AcmeStatic,
        "sandbox": AcmeSandbox,
        "memory": memory_plugin(name),
    }[kind]
    return FakePoint(name, provides, on_import=end)


def installed_plugins(monkeypatch: pytest.MonkeyPatch) -> dict[str, list[FakePoint]]:
    """The installed entry points by kind (lists to fill); this process's plugin state fresh."""
    points: dict[str, list[FakePoint]] = {kind: [] for kind in plugins.PLUGIN_GROUPS}
    by_group = {group: points[kind] for kind, group in plugins.PLUGIN_GROUPS.items()}
    monkeypatch.setattr(plugins, "_entry_points", lambda group: list(by_group.get(group, [])))
    monkeypatch.setattr(plugins, "_STATE", plugins._ProcessState())
    return points


def allow(*entries: str) -> None:
    """A process that read ``entries`` as the stored list and was told to load by it."""
    plugins.install_allow_list(list(entries))
    plugins.load_allowed(list(entries))


def withdraw_every_plugin() -> None:
    """Take whatever a test loaded out of the registries again."""
    plugins.install_allow_list([])
    plugins.load_allowed([])
