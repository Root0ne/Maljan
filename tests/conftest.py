from unittest.mock import MagicMock

import pytest


@pytest.fixture
def mock_llm() -> MagicMock:
    """Mock LLM instance for testing agents without hitting real APIs."""
    mock = MagicMock()
    # Mocking standard LangChain API call 'invoke'
    mock.invoke.return_value = MagicMock(content="Mocked LLM Response")
    return mock
