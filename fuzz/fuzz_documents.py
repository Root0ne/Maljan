"""Fuzz the archive lister and the document reader on a sample's bytes.

``archive_list`` and ``document_info`` read a zip, 7z, tar, gzip, OLE2, OOXML
or PDF without extracting it; a damaged or hostile file is stated in the
answer, never raised. Raw bytes reach the format sniffing, and an OOXML package
built around fuzzed relationship parts reaches the XML reader behind it.
"""

import io
import os
import sys
import tempfile
import zipfile

import atheris

with atheris.instrument_imports():
    from maljan.tools import binary

RELATIONSHIPS = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1" Type="{kind}" Target="{target}" TargetMode="External"/>'
    "{tail}</Relationships>"
)

# One file, rewritten for each input: the readers take a path.
handle, PATH = tempfile.mkstemp(prefix="fuzz-document-")
os.close(handle)


def _package(fdp: atheris.FuzzedDataProvider) -> bytes:
    """An OOXML package whose two relationship parts are fuzzed, one inside a template."""
    templated = RELATIONSHIPS.format(
        kind=fdp.ConsumeUnicodeNoSurrogates(64),
        target=fdp.ConsumeUnicodeNoSurrogates(256),
        tail=fdp.ConsumeUnicodeNoSurrogates(256),
    )
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as package:
        package.writestr("[Content_Types].xml", "<Types/>")
        package.writestr("_rels/.rels", templated.encode("utf-8", "surrogatepass"))
        package.writestr("word/_rels/document.xml.rels", fdp.ConsumeBytes(fdp.remaining_bytes()))
    return buffer.getvalue()


def TestOneInput(data: bytes) -> None:  # noqa: N802 - the name libFuzzer looks for
    fdp = atheris.FuzzedDataProvider(data)
    blob = _package(fdp) if fdp.ConsumeBool() else fdp.ConsumeBytes(fdp.remaining_bytes())
    with open(PATH, "wb") as out:
        out.write(blob)
    binary.document_info(PATH)
    binary.archive_list(PATH, limit=64)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
