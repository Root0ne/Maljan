"""oletools over one document, as one JSON document on standard output.

Run by ``server.py`` as a program of its own (``python3 -I ole_report.py
<report> [options] -- <path>``), in a process group of its own with the shared
plumbing's time bound, so a document that sends a parser into a loop is
killed with its run and never stalls the server. It imports oletools and the
standard library, nothing else, and reads the document only:

* ``vba``: olevba's macro source and its keyword analysis. olevba parses the
  VBA project and scans the source text; no macro runs. The XLM emulator
  olevba would call where it is installed is switched off here, so Excel 4
  macro sheets are read by olevba's own BIFF parser alone.
* ``macro_risk``: MacroRaptor's auto-run, write and execute flags over the
  same source.
* ``indicators``: oleid's indicators (format, encryption, macros, external
  relationships, Flash, ...).
* ``rtf_objects``: rtfobj's embedded objects of an RTF document, with their
  class names and a digest of each payload; nothing is written out.
* ``dde``: msodde's DDE links and fields.

A document encrypted with one of Office's default passwords is decrypted in
memory for ``vba`` and ``macro_risk``; nothing is written to disk. A document
of a format the report does not read is ``{"error": {"code":
"unsupported_format", ...}}``; any other failure is a traceback on standard
error and a non-zero exit, which the server answers as ``tool_failed``.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import logging
import sys
from collections.abc import Callable
from typing import Any

UNSUPPORTED_FORMAT = "unsupported_format"
# msodde's field filters, by the names the server's tool takes.
FIELD_FILTERS = {
    "only_dde": "only dde",
    "exclude_blacklisted": "exclude blacklisted",
    "keep_all": "keep all",
}


class Unsupported(Exception):
    """The document is of a format this report does not read."""


def _text(value: Any) -> Any:
    """``value`` with bytes decoded, so the answer is JSON whatever oletools handed back."""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace").rstrip("\0")
    return value


def _sha256(data: Any) -> str:
    return hashlib.sha256(data).hexdigest() if isinstance(data, bytes | bytearray) else ""


def _read(path: str) -> bytes:
    with open(path, "rb") as handle:
        return handle.read()


def _decrypted(data: bytes) -> bytes | None:
    """``data`` decrypted in memory with Office's default passwords; ``None`` when none opens it."""
    import msoffcrypto
    from oletools import crypto

    for password in crypto.DEFAULT_PASSWORDS:
        try:
            office = msoffcrypto.OfficeFile(io.BytesIO(data))
            office.load_key(password=password)
            out = io.BytesIO()
            office.decrypt(out)
        except Exception:  # noqa: BLE001 — the next password, then none
            continue
        return out.getvalue()
    return None


def _vba_parser(path: str) -> tuple[Any, bool]:
    """olevba's parser over the document, decrypted in memory where it must be; and whether."""
    from oletools import olevba

    # Never the XLM emulator: XLM macro sheets are read by olevba's own parser.
    olevba.XLMDEOBFUSCATOR = False
    try:
        parser = olevba.VBA_Parser(path, relaxed=True)
    except olevba.FileOpenError as exc:
        said = str(exc).removeprefix("Failed to open file ")
        raise Unsupported(said.replace(path, "the document")) from exc
    if not parser.detect_is_encrypted():
        return parser, False
    plain = _decrypted(_read(path))
    if plain is None:
        return parser, True
    parser.close()
    return olevba.VBA_Parser(path, data=plain, relaxed=True), True


def vba(path: str, options: argparse.Namespace) -> dict[str, Any]:
    parser, encrypted = _vba_parser(path)
    try:
        has_vba = bool(parser.detect_vba_macros())
        has_xlm = bool(parser.detect_xlm_macros())
        # The document's own path, where olevba names it, is the call's
        # argument: left out, so a row names only what is inside the document.
        macros = [
            {
                "container": "" if container == path else _text(container),
                "stream": _text(stream),
                "module": "" if module == path else _text(module),
                "source": _text(code),
            }
            for container, stream, module, code in parser.extract_all_macros()
        ]
        indicators = [
            {"type": _text(kind), "keyword": _text(keyword), "description": _text(description)}
            for kind, keyword, description in parser.analyze_macros(
                show_decoded_strings=True, deobfuscate=options.deobfuscate
            )
            or ()
        ]
        stomping = bool(parser.detect_vba_stomping()) if has_vba else False
        return {
            "container_type": _text(parser.type),
            "encrypted": encrypted,
            "has_vba": has_vba,
            "has_xlm": has_xlm,
            "vba_stomping": stomping,
            "macros": macros,
            "xlm_macros": [_text(line) for line in parser.xlm_macros or ()],
            "indicators": indicators,
        }
    finally:
        parser.close()


def macro_risk(path: str, options: argparse.Namespace) -> dict[str, Any]:
    from oletools.mraptor import MacroRaptor

    parser, encrypted = _vba_parser(path)
    try:
        has_vba = bool(parser.detect_vba_macros())
        sources = parser.extract_all_macros() if has_vba else ()
        code = "".join(f"{_text(source)}\n" for _c, _s, _m, source in sources)
    finally:
        parser.close()
    raptor = MacroRaptor(code)
    if has_vba:
        raptor.scan()
    return {
        "encrypted": encrypted,
        "has_vba": has_vba,
        "suspicious": bool(raptor.suspicious),
        "flags": raptor.get_flags(),
        "autoexec": bool(raptor.autoexec),
        "write": bool(raptor.write),
        "execute": bool(raptor.execute),
        "matches": [
            {"flag": flag, "keyword": _text(found)}
            for flag, found in (
                ("autoexec", raptor.autoexec_match),
                ("write", raptor.write_match),
                ("execute", raptor.execute_match),
            )
            if found
        ],
    }


def indicators(path: str, options: argparse.Namespace) -> dict[str, Any]:
    from oletools.oleid import OleID

    found = OleID(path).check()
    return {
        "indicators": [
            {
                "id": _text(item.id),
                "name": _text(item.name),
                "value": _text(item.value)
                if isinstance(item.value, str | bytes | bool | int | float) or item.value is None
                else str(item.value),
                "risk": _text(item.risk),
                "description": _text(item.description),
            }
            for item in found
        ]
    }


def rtf_objects(path: str, options: argparse.Namespace) -> dict[str, Any]:
    from oletools import rtfobj

    data = _read(path)
    if not rtfobj.is_rtf(data, treat_str_as_data=True):
        raise Unsupported("the document is not RTF")
    parser = rtfobj.RtfObjParser(data)
    parser.parse()
    objects = []
    for index, obj in enumerate(parser.objects):
        payload = obj.olepkgdata if obj.is_package else obj.oledata if obj.is_ole else obj.rawdata
        objects.append(
            {
                "index": index,
                "start": obj.start,
                "end": obj.end,
                "is_ole": bool(obj.is_ole),
                "format_id": obj.format_id,
                "class_name": _text(obj.class_name),
                "data_size": obj.oledata_size if obj.is_ole else len(obj.rawdata or b""),
                "is_package": bool(obj.is_package),
                "filename": _text(obj.filename),
                "source_path": _text(obj.src_path),
                "temp_path": _text(obj.temp_path),
                "clsid": _text(obj.clsid),
                "clsid_description": _text(obj.clsid_desc),
                "payload_sha256": _sha256(payload),
            }
        )
    return {"objects": objects}


def dde(path: str, options: argparse.Namespace) -> dict[str, Any]:
    from oletools import crypto, msodde

    if crypto.is_encrypted(path):
        return {"encrypted": True, "links": []}
    said = msodde.process_file(path, FIELD_FILTERS[options.field_filter]) or ""
    links = [{"text": line.strip()} for line in str(said).splitlines() if line.strip()]
    return {"encrypted": False, "links": links}


REPORTS: dict[str, Callable[[str, argparse.Namespace], dict[str, Any]]] = {
    "vba": vba,
    "macro_risk": macro_risk,
    "indicators": indicators,
    "rtf_objects": rtf_objects,
    "dde": dde,
}


def main(argv: list[str] | None = None) -> int:
    arguments = argparse.ArgumentParser(prog="ole_report")
    arguments.add_argument("report", choices=sorted(REPORTS))
    arguments.add_argument("--deobfuscate", action="store_true")
    arguments.add_argument(
        "--field-filter", choices=sorted(FIELD_FILTERS), default="exclude_blacklisted"
    )
    arguments.add_argument("path")
    options = arguments.parse_args(argv)
    # oletools logs and, here and there, prints: neither reaches the document.
    logging.basicConfig(stream=sys.stderr, level=logging.CRITICAL)
    out = sys.stdout
    try:
        with contextlib.redirect_stdout(sys.stderr):
            answer: dict[str, Any] = REPORTS[options.report](options.path, options)
    except Unsupported as exc:
        answer = {"error": {"code": UNSUPPORTED_FORMAT, "message": str(exc)}}
    out.write(json.dumps(answer, default=str))
    out.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
