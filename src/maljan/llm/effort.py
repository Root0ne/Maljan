"""Which reasoning effort a model is built with, where that value came from, and what may be chosen.

A model of an agent's list may carry its own ``effort``
(``llm.agents.<key>.effort``, or a fallback's); left unset it inherits the
provider's global value, the setting the provider's adapter names
(``LLMProvider.effort_setting``). Nothing here sets a level: an unset effort
everywhere sends none, and the model's own default answers.
"""

from __future__ import annotations

from typing import Any

from maljan.llm.provider_base import facts_of


def global_effort(settings: Any, provider: str) -> str | None:
    """The provider's global effort, or ``None`` when it sets none or has none."""
    path = facts_of(provider).effort_setting
    if path is None:
        return None
    node: Any = settings
    for part in path.split("."):
        node = getattr(node, part, None)
        if node is None:
            return None
    value = str(node or "").strip()
    return value or None


def effort_setting_of(agent: str, position: int = 0) -> str:
    """The field a model of an agent's list reads its own effort from.

    ``position`` 0 is the entry's first model (``llm.agents.<key>.effort``);
    1 and on are its fallbacks, named by their index in ``fallbacks``.
    """
    key = str(agent).lower()
    if position <= 0:
        return f"llm.agents.{key}.effort"
    return f"llm.agents.{key}.fallbacks[{position - 1}].effort"


def effort_in_force(
    settings: Any, provider: str, own: str | None = None, setting: str | None = None
) -> tuple[str | None, str]:
    """The effort a model is built with, and a phrase saying where it came from.

    ``own`` is the model's own value and wins when set; ``setting`` is the
    field it was read from (``effort_setting_of``), named in the phrase.
    """
    path = facts_of(provider).effort_setting
    if path is None:
        return None, "none for this provider"
    if own:
        return own, f"{own} from {setting or 'the agent entry'}"
    value = global_effort(settings, provider)
    if value is None:
        return None, "unset, the provider's default"
    return value, f"{value} from {path}"


def effort_options(settings: Any, provider: str, model: str) -> dict[str, Any]:
    """What an effort field for ``provider``/``model`` may offer.

    ``levels`` is the list to choose from, ``None`` where the endpoint names
    its own levels and the value is written as the endpoint takes it, and
    empty where none may be set; the provider's adapter answers
    (``LLMProvider.effort_levels``). ``levels_source`` is ``models_api`` when
    a models API described the model, ``settings`` when the list is the
    setting's own, and ``none`` otherwise. ``undescribed_levels`` are the offered levels the
    description named nothing about: the build sends them, because only a
    level the Models API refuses is refused, so they are offered and marked.
    """
    provider = str(provider or "")
    facts = facts_of(provider)
    path = facts.effort_setting
    if path is None:
        return {
            "provider": provider,
            "model": model,
            "takes_effort": False,
            "levels": [],
            "undescribed_levels": [],
            "levels_source": "none",
            "global_key": None,
            "global_value": None,
        }
    levels, undescribed, source = facts.effort_levels(model)
    return {
        "provider": provider,
        "model": model,
        "takes_effort": True,
        "levels": levels,
        "undescribed_levels": undescribed,
        "levels_source": source,
        "global_key": f"core.{path}",
        "global_value": global_effort(settings, provider),
    }
