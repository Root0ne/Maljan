"""The register as the docs page ``validation-codes.mdx``: the same tree gives the same bytes."""

from __future__ import annotations

from scripts.validation_codes.register import KEPT_PREFIX, Code, Register, Unresolved

COMMAND = "uv run python scripts/validation_codes/run.py"

TITLE = "Validation codes"
DESCRIPTION = (
    "Every code the platform's validators file a finding under: where it is raised, what it "
    "means, and the pages that name it."
)

HEADER = f"""This page is generated from the source by
`{COMMAND}` and is not edited by hand. A test
regenerates it and fails when this file is not what the source gives, when a
code has no place that raises it, and when no test names a code.

A validation code is the `family.name` string a finding is filed under: the code
a retry turn shows the producer, the key of `run_summary.validation.by_code`, and
the `code` of every unresolved row. The register reads the source with Python's
`ast` module and never imports it. A string counts as a code only in a code
position (the value of a `code=` keyword, the value assigned to a name ending in
`_CODE`, a member of a set or tuple bound to a name ending in `_CODES`, or the
code slot of a finding the platform builds) and only in the form `family.name`.
The families are the ones the source uses.

A code is raised only where the platform puts it into a finding it emits: a call
building an object of a class whose instances carry a `code` (with `code=` or in
its positional place), a dict with a `"code"` key, a copy made with its `code`
changed, a tuple shaped like such a class, a call to a factory whose parameter
reaches one of those, or a callback the function was handed; and only in code
something calls. Sites that store or forward an existing code are listed as
passing it on. Comparing a code, looking up or counting by it, testing a string
against it, logging it, filtering by it, a default that reaches no finding and
formatted text read it, and are not listed. A name, a loop over constants, a
conditional, a constant mapping and a parameter fed by constants at every call
site are followed. Places are named `module:function`, without line numbers, so
an edit elsewhere in a file leaves this page as it is. A class or factory whose
code slots only ever receive strings of another shape files another kind of code
(a team rule, a tool error); its slots the register cannot follow are left out
of the unresolved list. A code-shaped string in a pair is listed only when its
family is already a code family, so a code first written only as a pair literal
in a new family is not seen; bind it to a `_CODE` name.

A code's meaning is the comment or docstring on its own constant; where there is
none, the message a raise site passes, with each value it fills in written
`<name>` (a site that passes several messages for a code is pointed at
instead); where there is neither, the comment written over the group of
constants it belongs to, marked as such. A code counts as tested when a Python
test names it, in a string other than a docstring or by its constant; that does
not prove the test makes the platform raise it. The tests are not listed here:
`{COMMAND} --tests` prints them. A code bound under a `{KEPT_PREFIX}` name is
one nothing raises any more and stored runs still carry; the comment on that
name says what reads it."""


def render(register: Register) -> str:
    lines = [
        "---",
        f'title: "{TITLE}"',
        f'description: "{DESCRIPTION}"',
        "---",
        "",
        HEADER,
        "",
        _summary(register),
        "",
    ]
    for family in register.families():
        lines += [f"## {family}", ""]
        for code in register.codes:
            if code.family == family:
                lines += _entry(code)
    lines += _unresolved(register.unresolved)
    return "\n".join(lines).rstrip("\n") + "\n"


def _summary(register: Register) -> str:
    families = register.families()
    counts = " · ".join(
        f"[{family}](#{family}) {sum(1 for code in register.codes if code.family == family)}"
        for family in families
    )
    unresolved = len(register.unresolved)
    if not unresolved:
        tail = "Every code position resolved."
    elif unresolved == 1:
        tail = "One code position the register could not resolve is [listed at the end]"
        tail += "(#unresolved-code-positions)."
    else:
        tail = f"{unresolved} code positions the register could not resolve are [listed at the end]"
        tail += "(#unresolved-code-positions)."
    codes = _counted(len(register.codes), "code", "codes")
    return f"**{codes} in {_counted(len(families), 'family', 'families')}:** {counts}. {tail}"


def _counted(count: int, one: str, many: str) -> str:
    return f"{count} {one if count == 1 else many}"


def _entry(code: Code) -> list[str]:
    lines = [f"### `{code.code}`", ""]
    paragraphs = [" ".join(part.split()) for part in code.meaning.split("\n\n") if part.strip()]
    quoted = _inline(" ".join(paragraphs))
    if code.meaning_kind == "message":
        lines += [
            f'No comment names its meaning; the message at `{code.meaning_from}` reads: "{quoted}"',
            "",
        ]
    elif code.meaning_kind == "group":
        lines += [
            "No comment of its own names its meaning; the comment over the group of constants "
            f'it belongs to, on `{code.meaning_from}`, reads: "{quoted}"',
            "",
        ]
    elif code.meaning_kind == "messages":
        lines += [
            f"No comment names its meaning, and `{code.meaning_from}` passes more than one "
            "message for it: see the messages there.",
            "",
        ]
    elif code.meaning_kind == "pointer":
        lines += [
            "No comment names its meaning, and the message at "
            f"`{code.meaning_from}` is made only of values it fills in: see the message there.",
            "",
        ]
    elif paragraphs:
        for paragraph in paragraphs:
            lines += [_block(_inline(paragraph)), ""]
    else:
        lines += ["No comment or message in the source says what it means.", ""]
    if code.raised_at:
        lines.append(f"- **Raised at** {_spans(code.raised_at)}")
    elif code.kept_by:
        lines.append(
            f"- **Raised at** nothing: kept for stored runs, as {_spans(code.kept_by)} says"
        )
    else:
        lines.append("- **Raised at** nothing")
    if code.passes_on:
        lines.append(f"- **Passes on** {_spans(code.passes_on)}")
    if code.uncalled:
        lines.append(f"- **Raised where nothing calls it** {_spans(code.uncalled)}")
    if code.constants:
        lines.append(f"- **Constant** {_spans(code.constants)}")
    elif code.collections:
        lines.append(f"- **Listed in** {_spans(code.collections)}")
    else:
        lines.append("- **Constant** none: the code is written as a literal")
    if code.docs:
        pages = ", ".join(f"[{_inline(title)}]({route})" for route, title in code.docs)
        lines.append(f"- **Docs** {pages}")
    else:
        lines.append("- **Docs** none")
    lines.append("")
    return lines


def _unresolved(items: tuple[Unresolved, ...]) -> list[str]:
    lines = ["## Unresolved code positions", ""]
    if not items:
        return [
            *lines,
            "Every code position resolved to a literal or a constant, so the codes above are "
            "every code the source can raise.",
            "",
        ]
    lines += [
        "Each of these is a code position whose value the register could not follow to a "
        "literal or a constant: mostly a finding built from a code it was handed, out of a "
        "row or another finding. It may carry a code this page does not list.",
        "",
    ]
    for item in items:
        lines.append(f"- `{item.site}`: `{item.expression}`, {_inline(item.why)}.")
    lines.append("")
    return lines


def _spans(items: tuple[str, ...]) -> str:
    return ", ".join(f"`{item}`" for item in items)


# Characters that mean something to MDX or Markdown in running text.
_ESCAPED = {"{": "\\{", "}": "\\}", "<": "\\<", "\\": "\\\\", "[": "\\[", "]": "\\]"}


def _block(text: str) -> str:
    """A paragraph that cannot be read as a heading, a quote or a list item."""
    if text[:1] in ("#", ">", "-", "+", "*", "="):
        return "\\" + text
    digits = len(text) - len(text.lstrip("0123456789"))
    if digits and text[digits : digits + 1] in (".", ")"):
        return f"{text[:digits]}\\{text[digits:]}"
    return text


def _inline(text: str) -> str:
    """Source prose as MDX: code spans kept whole (reST's double ones too), the rest escaped."""
    text = _without_roles(text)
    out: list[str] = []
    index, size = 0, len(text)
    while index < size:
        char = text[index]
        if char != "`":
            out.append(_ESCAPED.get(char, char))
            index += 1
            continue
        run = 1
        while index + run < size and text[index + run] == "`":
            run += 1
        end = _closing(text, index + run, run)
        if end < 0:
            out.append("\\`" * run)
            index += run
            continue
        content = text[index + run : end]
        out.append(f"`{content}`" if "`" not in content else f"`` {content} ``")
        index = end + run
    return "".join(out)


def _closing(text: str, start: int, run: int) -> int:
    """Where a run of exactly ``run`` backticks closes the span opened before ``start``."""
    fence = "`" * run
    end = text.find(fence, start)
    while end >= 0:
        after = end + run
        if (after >= len(text) or text[after] != "`") and (end == start or text[end - 1] != "`"):
            return end
        end = text.find(fence, after)
    return -1


def _without_roles(text: str) -> str:
    """``:func:`name``` as ``name``: a docstring's role prefix means nothing on a page."""
    parts = text.split("`")
    for index, before in enumerate(parts[:-1]):
        if not before.endswith(":"):
            continue
        colon = before.rfind(":", 0, len(before) - 1)
        role = before[colon + 1 : -1]
        if colon >= 0 and role.isalpha() and (colon == 0 or not before[colon - 1].isalnum()):
            parts[index] = before[:colon]
    return "`".join(parts)
