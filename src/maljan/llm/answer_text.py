"""The text a model's answer says, whatever shape its client keeps the answer in.

Most clients hand back an answer's ``content`` as a string. ``ChatAnthropic``
keeps it as the list of blocks the API returned whenever the answer is more
than one text block — and an answer from a model that thinks by default is a
``thinking`` block (an empty text and a signature, on Claude Haiku 5.5) before
its ``text`` block. Read with ``str()``, such an answer is the repr of a list,
signature and all, and nothing downstream can read a claim out of it.

The list is kept as it came on the message, because the thinking block has to
go back to the API unchanged; only the reading is changed here: the text
blocks, joined in order, and nothing else. A string is returned as it is.
"""

from __future__ import annotations

from typing import Any


def answer_text(content: Any) -> str:
    """The text ``content`` says: a string as it is, a block list's text parts joined."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(
            part
            if isinstance(part, str)
            else str(part.get("text") or "")
            if isinstance(part, dict) and part.get("type") == "text"
            else ""
            for part in content
        )
    return "" if content is None else str(content)
