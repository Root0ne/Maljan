"""Compose paste-ready research briefs from literature-review-brief.md.

One source of truth: edit Part C / the preamble / Part D there and re-run this.
Each output file is a single self-contained prompt — preamble, one brief, format.
"""

import re
from pathlib import Path

SRC = Path("other/docs/academic-article/literature-review-brief.md")
OUT = Path("other/docs/academic-article/research-briefs")
text = SRC.read_text(encoding="utf-8")

# Preamble: the blockquote right after "**Preamble to paste before every brief:**".
# ``>``-only lines are blank paragraph separators inside the quote and must be matched too —
# a ``> .*`` pattern stops dead at the first one, which silently truncated the preamble to its
# first paragraph and dropped the standing instructions.
pre = re.search(r"\*\*Preamble to paste before every brief:\*\*\n\n((?:>.*\n)+)", text)
assert pre is not None, "preamble block not found"
preamble = "\n".join(
    line[2:] if line.startswith("> ") else line[1:].strip()
    for line in pre.group(1).rstrip().split("\n")
)
# Cheap guard against the same class of silent truncation returning.
assert "standing instructions" in preamble, "preamble truncated — check the blockquote regex"

# Output format: the fenced block under Part D
fmt = re.search(r"## Part D — Required output format.*?\n```markdown\n(.*?)\n```", text, re.S)
out_format = fmt.group(1)

# Each brief: "### R<n> — <title>" up to the next "### R" or "---\n\n## Part D"
briefs = re.findall(
    r"### (R\d) — (.+?)\n\n(.*?)(?=\n---\n\n### R\d — |\n---\n\n## Part D)", text, re.S
)
assert len(briefs) == 8, f"expected 8 briefs, parsed {len(briefs)}"

for tag, title, body in briefs:
    doc = f"""# {tag} — {title}

<!-- Paste this ENTIRE file into one research-LLM conversation. One brief per
     conversation: mixing themes blurs the gap analysis. Generated from
     ../literature-review-brief.md — edit there, not here. -->

{preamble.strip()}

---

## Research brief: {title}

{body.strip()}

---

## Required output format

Answer in exactly this structure:

```markdown
{out_format}
```
"""
    (OUT / f"{tag}.md").write_text(doc, encoding="utf-8")
    print(f"{tag}.md  ({len(doc.splitlines())} lines)  {title}")
