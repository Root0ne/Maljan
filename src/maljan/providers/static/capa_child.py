"""The capa child: one capa pass over one file, its answer written to a file.

``capa_yara.run_capa_document`` starts this file as a process of its own::

    python -I capa_child.py <sample> <rules dir> <signatures dir> <backend> <answer file>

in isolated mode (no ``PYTHON*`` variable, no user site, no working directory
on the path), with an environment it builds rather than its own, in a run
directory of its own. It is run by its path and imports nothing of ``maljan``:
only the standard library and capa, so the child runs this tree's own code and
never loads the platform, its settings or its credentials. The answer is the
document, or capa's error, as JSON, written beside the answer path and renamed
onto it, so a child that dies mid-write leaves no answer rather than half of
one.

capa API surface pinned against flare-capa 9.4.0 (the version ``uv sync
--extra capa`` installs); a few names moved since the 7.x line this was first
written against:

- ``capa.rules.get_rules`` (not ``capa.loader.get_rules``). It writes a ruleset
  cache under ``$XDG_CACHE_HOME`` or ``$HOME/.cache/capa`` even with the cache
  off, which is why the child's ``HOME`` is its run directory.
- ``capa.rules.cache`` must be imported explicitly: ``get_rules`` references
  ``capa.rules.cache.get_default_cache_directory()`` at call time without
  importing the submodule, so a bare ``import capa.rules`` leaves it missing.
- ``capa.loader.get_extractor`` takes an explicit ``input_format``; the format
  is detected up front with ``capa.helpers.get_auto_format``.
- ``capa.loader`` has no ``BACKEND_MAP``; the per-backend constants
  (``BACKEND_VIV`` / ``BACKEND_PEFILE`` / ``BACKEND_BINJA``) are looked up by
  name.
- ``auto`` is not a ``capa.loader`` constant. capa's command line picks the
  backend for the format it detected (``capa.main.get_backend_from_cli``), and
  so does a pass here, so a managed assembly reaches capa's .NET backend
  rather than vivisect, which refuses the ``dotnet`` format.
- ``capa.render.result_document.ResultDocument.from_capa`` takes the
  ``Capabilities.matches`` mapping, not the ``Capabilities`` object itself
  (``collect_metadata`` takes the whole object).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

# The backend name that asks capa to pick one for the detected format.
AUTO_BACKEND = "auto"

# What the capa answer says in place of its library functions when none were
# looked for, and the key the child hands that reason to the parent under
# (``None`` when the signatures were loaded and library functions identified).
LIBRARY_FUNCTIONS_NO_DIRECTORY = "no: there is no signature directory"
LIBRARY_FUNCTIONS_NOT_FOR_FORMAT = "no: capa loads no signatures for this format and backend"
LIBRARY_FUNCTIONS_NO_FILES = "no: the signature directory holds no signatures"
LIBRARY_FUNCTIONS_UNSTATED = "no: the capa run did not say whether it looked for them"
NOT_IDENTIFIED_KEY = "maljan_library_functions_not_identified"


def _capa_backend(backend_name: str, input_format: str) -> str:
    """The capa backend one run uses, for the format capa's own detection returned.

    A named backend is the ``capa.loader`` constant of that name, exactly as
    configured. ``auto`` is the backend capa itself picks for the format when
    no backend is forced (``capa.main.get_backend_from_cli``): its .NET backend
    for a managed assembly, and vivisect for native code.
    """
    if backend_name != AUTO_BACKEND:
        import capa.loader as capa_loader

        return str(getattr(capa_loader, backend_name))
    import argparse

    import capa.main as capa_main

    no_override = argparse.Namespace(backend=capa_main.BACKEND_AUTO)
    return str(capa_main.get_backend_from_cli(no_override, input_format))


def _capa_signatures(
    signatures_dir: str, input_format: str, backend: str
) -> tuple[list[Path], str | None]:
    """The library signature files capa itself loads for this format and backend, or why none.

    capa's command line passes signatures to vivisect for a PE only
    (``capa.main.get_signatures_from_cli``). Asked the same way, a shellcode,
    ELF or .NET run loads none, so it never pays for the PE signature set and
    never marks its code as a PE library's. An empty setting or a path with
    no directory means no signatures, which is the way to run without library
    identification. The reason is ``None`` when signatures were chosen.
    """
    if not signatures_dir.strip() or not Path(signatures_dir).is_dir():
        return [], LIBRARY_FUNCTIONS_NO_DIRECTORY
    import argparse

    import capa.loader as capa_loader
    import capa.main as capa_main

    sig_dir = Path(signatures_dir)
    given = argparse.Namespace(signatures=sig_dir, is_default_signatures=False)
    chosen = list(capa_main.get_signatures_from_cli(given, input_format, backend))
    if chosen:
        return chosen, None
    if capa_loader.get_signatures(sig_dir):
        return [], LIBRARY_FUNCTIONS_NOT_FOR_FORMAT
    return [], LIBRARY_FUNCTIONS_NO_FILES


def capa_pass(
    sample_path: str, rules_dir: str, signatures_dir: str, backend_name: str
) -> dict[str, Any]:
    """capa's result document for one file, saying whether library functions were identified.

    capa lists the library functions it identified, and an empty list when it
    looked for none: ``NOT_IDENTIFIED_KEY`` holds the reason, ``None`` when it
    looked. Raises whatever capa raises.
    """
    import capa.capabilities.common as capa_capabilities
    import capa.helpers as capa_helpers
    import capa.loader as capa_loader
    import capa.render.result_document as capa_rd
    import capa.rules as capa_rules
    import capa.rules.cache  # noqa: F401 - get_rules() references this submodule

    path = Path(sample_path)
    rules_path = Path(rules_dir)
    rules = capa_rules.get_rules([rules_path], enable_cache=False)
    input_format = capa_helpers.get_auto_format(path)
    backend = _capa_backend(backend_name, input_format)
    sigpaths, not_identified = _capa_signatures(signatures_dir, input_format, backend)
    extractor = capa_loader.get_extractor(
        path,
        input_format,
        capa_loader.OS_AUTO,
        backend,
        sigpaths,
        should_save_workspace=False,
        disable_progress=True,
    )
    capabilities = capa_capabilities.find_capabilities(rules, extractor, disable_progress=True)
    meta = capa_loader.collect_metadata(
        [], path, input_format, capa_loader.OS_AUTO, [rules_path], extractor, capabilities
    )
    document = capa_rd.ResultDocument.from_capa(meta, rules, capabilities.matches)
    result: dict[str, Any] = document.model_dump(mode="json")
    result[NOT_IDENTIFIED_KEY] = not_identified
    return result


def main(argv: list[str]) -> int:
    """One pass, its answer in the file named last: ``{"ok": document}`` or ``{"error": why}``."""
    sample_path, rules_dir, signatures_dir, backend_name, answer_path = argv
    try:
        answer: dict[str, Any] = {
            "ok": capa_pass(sample_path, rules_dir, signatures_dir, backend_name)
        }
    except Exception as exc:  # noqa: BLE001 - written for the parent, never raised here
        answer = {"error": f"{type(exc).__name__}: {exc}"}
    written = Path(f"{answer_path}.part")
    written.write_text(json.dumps(answer), encoding="utf-8")
    os.replace(written, answer_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
