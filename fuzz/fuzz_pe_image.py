"""Fuzz the PE reader the address-answering tools share.

A sample's headers are the author's choice. ``pe_image.parse`` maps any bytes
to an image or raises ``NotAPortableExecutable``, the one exception its callers
catch, and the image it answers is read without raising.
"""

import sys

import atheris

with atheris.instrument_imports():
    from maljan.tools import pe_image


def TestOneInput(data: bytes) -> None:  # noqa: N802 - the name libFuzzer looks for
    try:
        image = pe_image.parse(data)
    except pe_image.NotAPortableExecutable:
        return
    image.code_sections()
    image.data_sections()
    image.imports_by_slot()
    image.function_table()
    for offset in (0, len(data) // 2, len(data) - 1):
        image.where(offset)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
