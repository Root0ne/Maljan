from langchain_core.language_models.chat_models import BaseChatModel
from langchain_openai import ChatOpenAI

from maljan.core.config import settings


def get_expert_llm() -> BaseChatModel:
    """Returns the fast LLM instance for Layer 2 Expert Analysts."""
    if not settings.openai_api_key:
        raise ValueError("OPENAI_API_KEY is not set.")
    return ChatOpenAI(
        model=settings.expert_model_name,
        api_key=settings.openai_api_key,  # type: ignore
        temperature=0.1,
    )


def get_judge_llm() -> BaseChatModel:
    """Returns the more capable and context-heavy LLM for Layer 4 Judge."""
    if not settings.openai_api_key:
        raise ValueError("OPENAI_API_KEY is not set.")
    return ChatOpenAI(
        model=settings.judge_model_name,
        api_key=settings.openai_api_key,  # type: ignore
        temperature=0.0,
    )
