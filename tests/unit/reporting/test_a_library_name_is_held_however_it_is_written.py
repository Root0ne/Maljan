"""A library or API name a report writes is held by an entry that writes it another way.

A report wrote "WinINet" under the entry of resolved hashes and was told the
value is not in it: the entry holds the library as ``wininet.dll``, lower-case
and with its extension, and only a rule table spelled the bare name. A DLL and
an API are named without regard to case, and a library is the same library
with or without its ``.dll``.
"""

from __future__ import annotations

import json

from maljan.pipeline.validation import EntryTexts, wrong_entry_citations
from maljan.schemas.evidence import LedgerEntry


def _texts() -> EntryTexts:
    resolved = json.dumps(
        {"hits": [{"name": "InternetOpenW", "dlls": ["exampleio.dll"]}, {"name": "LoadThing"}]}
    )
    rules = json.dumps({"capabilities": [{"library": "ExampleIO", "api": "InternetOpenW"}]})
    return EntryTexts.from_ledger(
        [
            LedgerEntry(
                id="ev_0020", agent="p", server="p", tool="resolve_api_hashes", output=resolved
            ),
            LedgerEntry(id="ev_0022", agent="p", server="p", tool="api_capability", output=rules),
        ]
    )


def test_a_library_written_without_its_extension_is_held_by_the_entry_naming_the_dll() -> None:
    body = "It resolves functions from `ExampleIO` at run time [ev_0020]."

    assert wrong_entry_citations({"body": body}, _texts(), prose=("body",)) == []


def test_an_api_name_in_another_case_is_held() -> None:
    body = "It calls `INTERNETOPENW` and `loadthing` [ev_0020]."

    assert wrong_entry_citations({"body": body}, _texts(), prose=("body",)) == []


def test_a_dll_written_in_another_case_is_held() -> None:
    body = "It loads `ExampleIO.DLL` [ev_0020]."

    assert wrong_entry_citations({"body": body}, _texts(), prose=("body",)) == []


def test_a_name_neither_entry_holds_is_still_asked_about_where_another_holds_it() -> None:
    body = "It reads the `library` field [ev_0020]."

    (found,) = wrong_entry_citations({"body": body}, _texts(), prose=("body",))

    assert "ev_0022 (api_capability)" in found.message
