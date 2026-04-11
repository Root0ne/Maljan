from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central configuration for application via environment variables or .env file."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # API Keys
    openai_api_key: str | None = None
    anthropic_api_key: str | None = None

    # LangChain / LangSmith Tracing Tracking
    langchain_tracing_v2: bool = False
    langchain_api_key: str | None = None

    # Model Configurations
    judge_model_name: str = "gpt-4o"
    expert_model_name: str = "gpt-4o-mini"

    # Negotiation parameters
    max_iterations: int = 2


settings = Settings()
