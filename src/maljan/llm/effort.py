"""Which reasoning effort a model is built with, where that value came from, and what may be chosen.

A model of an agent's list may carry its own ``effort``
(``llm.agents.<key>.effort``, or a fallback's); left unset it inherits the
provider's global value, ``llm.anthropic.effort`` or
``llm.openai.reasoning_effort``. Nothing here sets a level: an unset effort
everywhere sends none, and the model's own default answers.
"""

from __future__ import annotations

from typing import Any

from maljan.core.config import ANTHROPIC_EFFORT_LEVELS, EFFORT_SETTING_OF_PROVIDER


def global_effort(settings: Any, provider: str) -> str | None:
    """The provider's global effort, or ``None`` when it sets none or has none."""
    path = EFFORT_SETTING_OF_PROVIDER.get(str(provider))
    if path is None:
        return None
    node: Any = settings
    for part in path.split("."):
        node = getattr(node, part, None)
        if node is None:
            return None
    value = str(node or "").strip()
    return value or None


def effort_in_force(
    settings: Any, provider: str, own: str | None = None, agent: str | None = None
) -> tuple[str | None, str]:
    """The effort a model is built with, and a phrase saying where it came from.

    ``own`` is the model's own entry value and wins when set; ``agent`` names
    the entry for the phrase.
    """
    if str(provider) not in EFFORT_SETTING_OF_PROVIDER:
        return None, "none for this provider"
    if own:
        where = f"llm.agents.{agent}.effort" if agent else "the agent entry"
        return own, f"{own} from {where}"
    value = global_effort(settings, provider)
    if value is None:
        return None, "unset, the provider's default"
    return value, f"{value} from {EFFORT_SETTING_OF_PROVIDER[str(provider)]}"


def effort_options(settings: Any, provider: str, model: str) -> dict[str, Any]:
    """What an effort field for ``provider``/``model`` may offer.

    ``levels`` is the list to choose from, ``None`` where the endpoint names
    its own levels and the value is written as the endpoint takes it (the
    OpenAI-compatible provider), and empty where none may be set.
    ``levels_source`` is ``models_api`` when the Anthropic Models API
    described the model, ``settings`` when the list is the setting's own, and
    ``none`` otherwise.
    """
    provider = str(provider or "")
    path = EFFORT_SETTING_OF_PROVIDER.get(provider)
    if path is None:
        return {
            "provider": provider,
            "model": model,
            "takes_effort": False,
            "levels": [],
            "levels_source": "none",
            "global_key": None,
            "global_value": None,
        }
    levels: list[str] | None
    source = "none"
    if provider == "anthropic":
        levels, source = _anthropic_levels(model)
    else:
        levels = None
    return {
        "provider": provider,
        "model": model,
        "takes_effort": True,
        "levels": levels,
        "levels_source": source,
        "global_key": f"core.{path}",
        "global_value": global_effort(settings, provider),
    }


def _anthropic_levels(model: str) -> tuple[list[str], str]:
    """The levels the Models API said the model takes, or the setting's own list.

    A description that names no level at all says nothing about levels, so
    the setting's list stands; once it names any, only the levels it says the
    model takes are offered.
    """
    from maljan.llm.model_capabilities import takes_effort

    said = {level: takes_effort(model, level) for level in ANTHROPIC_EFFORT_LEVELS}
    if all(answer is None for answer in said.values()):
        return list(ANTHROPIC_EFFORT_LEVELS), "settings"
    return [level for level, answer in said.items() if answer is True], "models_api"
