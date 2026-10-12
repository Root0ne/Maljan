"""What a report read by a reader that keeps its source's arrangement lays out as."""

from __future__ import annotations

import json
from typing import Any

from maljan.schemas.sandbox_document import renamed
from maljan.schemas.sandbox_report import CAPE_RENAMES


def as_published(document: Any, source: dict[str, Any]) -> bool:
    """Whether ``document`` is ``source`` as published: every key, value and order.

    The source's renamed blocks (``CAPE_RENAMES``) sit under the document's
    words, in the place the source listed them; nothing else differs.
    """
    expected = renamed(source, CAPE_RENAMES)
    return json.dumps(document, default=str) == json.dumps(expected, default=str)
