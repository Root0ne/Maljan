# Maljan — Code Style and Conventions

## General Rules (from user_global rules)
- NO emojis anywhere in code or docstrings
- All code in English (comments, variable names, docstrings)
- Turkish text uses correct Turkish characters (ş, ğ, ü, etc.)
- Run tests after every change and confirm everything passes

## Python Style
- **Python 3.13** — use modern syntax (match/case, `X | Y` unions, `list[str]` not `List[str]`)
- **Type hints** on every function, return type, and class attribute (mypy strict)
- `from __future__ import annotations` in all files
- `TYPE_CHECKING` guard for circular import prevention

## Imports
- stdlib → third-party → internal (ruff `I` rule enforces this)
- Use `from maljan.x.y import Z` (absolute internal imports)
- No wildcard imports

## Naming
- Classes: `PascalCase`
- Functions/methods/variables: `snake_case`
- Constants: `UPPER_SNAKE_CASE`
- Private helpers: `_leading_underscore`
- File names: `snake_case.py`

## Docstrings
- Every public class and method has a docstring
- Format: Google style or plain text with Attributes section
- First line: short description (imperative mood)
- Attributes section for dataclasses and Pydantic models

## Pydantic
- All schemas use `pydantic.BaseModel` (v2 syntax)
- `model_config = ConfigDict(...)` for class-level config
- Use `Field(...)` with description for all public fields
- Enums for constrained string fields (not `Literal` alone)

## Error Handling
- Domain errors: raise `maljan.core.exceptions.AnalystError`
- Log with `maljan.core.logger.logger` (not `print`)
- Use `logger.getChild(self.name.lower())` in agents

## Line Length
- Max 100 characters (ruff `line-length = 100`)
- Exception: `src/maljan/agents/*.py` — E501 ignored (LLM prompts can be long)

## Dataclasses vs Pydantic
- Pydantic: API schemas, config, STIX output (needs validation)
- `@dataclass`: internal analysis results (CascadeResult, TextChunk, etc.)

## Testing Conventions
- Unit tests: `tests/unit/test_<module_name>.py`
- Integration tests: `tests/integration/test_<feature>.py`
- Use `pytest-mock` (`mocker` fixture) not `unittest.mock`
- Tests should be runnable without any external services (mock everything)
- Integration tests that need Qdrant: mark with `@pytest.mark.skipif`

## Commit Convention
```
type(scope): short description

Types: feat, fix, refactor, docs, test, ci, chore, security
```
