"""Fuzz the structured channel an analyst may append to its answer.

The fenced findings block is JSON a model wrote. Whatever the answer holds, a
closed block, one cut before its closing fence, or none, the parser splits it
into prose and validated rows and drops what does not validate; it never raises.
"""

import logging
import re
import sys

import atheris

with atheris.instrument_imports():
    from malspark.agents import findings_block

# The fence's language tag, read from the parser's own pattern so the harness
# opens the block exactly as the parser looks for it.
FENCE = re.search(r"[\w-]+-findings", findings_block._OPEN_RE.pattern).group(0)

# The parser counts dropped rows in a warning on nearly every input.
logging.disable(logging.CRITICAL)


def TestOneInput(data: bytes) -> None:  # noqa: N802 - the name libFuzzer looks for
    fdp = atheris.FuzzedDataProvider(data)
    shape = fdp.ConsumeIntInRange(0, 2)
    rest = fdp.ConsumeUnicodeNoSurrogates(fdp.remaining_bytes())
    if shape == 0:
        text = rest
    elif shape == 1:
        text = f"CLAIM: one\n```{FENCE}\n{rest}\n```\n"
    else:
        text = f"CLAIM: one\n```{FENCE}\n{rest}"
    findings_block.has_findings_block(text)
    findings_block.parse_findings_block(text)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
