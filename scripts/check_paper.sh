#!/usr/bin/env bash
# Every checklist item that can be checked by a machine, checked by one.
#
# The paper's own thesis is that a measurement can be wrong and look right, and
# the same is true of a conformance checklist: a tick in a document is a claim
# someone made once, and it goes stale exactly the way a hand-typed number does.
# So the checklist is this script. It exits non-zero on the first failure, names
# what failed, and says what fixes it.
#
# Run:  make paper-check
set -uo pipefail

cd "$(dirname "$0")/.." || exit 2

PAPER_DIR="docs/academic-article/paper"
BUILD="$PAPER_DIR/tex"
PDF="$BUILD/main.pdf"
LOG="$BUILD/main.log"
PY=".venv/bin/python"

fails=0
pass() { printf '  \033[32mok\033[0m    %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; fails=$((fails + 1)); }
note() { printf '        %s\n' "$1"; }

echo "paper conformance"
echo

# --------------------------------------------------------------------------
# 1. The document exists and is current
# --------------------------------------------------------------------------
if [[ ! -f "$PDF" ]]; then
    fail "no built PDF"
    note "run: make paper"
    exit 1
fi
pages=$(pdfinfo "$PDF" 2>/dev/null | awk '/^Pages:/{print $2}')

# The PDF has to be newer than everything it is built from, or this whole script
# is reporting on a document that no longer exists in the sources. It was not
# checked, and on 2026-08-16 that cost an hour: three fixes in a row looked like
# they had failed, because `make paper-check` does not build and `paper-check`
# does not depend on `paper`. A conformance report against a stale artefact is
# worse than no report, for the same reason a green test on unbuilt code is.
newer=$(find "$BUILD" "$PAPER_DIR" -maxdepth 1 \
        \( -name '*.tex' -o -name '*.bib' -o -name '*.sty' -o -name '*.json' \) \
        -newer "$PDF" -print 2>/dev/null | head -5)
if [[ -n "$newer" ]]; then
    fail "the PDF is older than its sources"
    printf '%s\n' "$newer" | sed 's|.*/|        |'
    note "run: make paper"
    exit 1
fi
pass "built: $pages pages, newer than every source"

# --------------------------------------------------------------------------
# 2. Typography
# --------------------------------------------------------------------------
type3=$(pdffonts "$PDF" 2>/dev/null | awk 'NR>2 && /Type 3/' | wc -l)
if [[ "$type3" -eq 0 ]]; then
    pass "zero Type 3 fonts"
else
    fail "$type3 Type 3 fonts embedded"
    note "matplotlib defaults pdf.fonttype to 3; set it to 42 in make_paper_figures.py"
fi

# A maths companion (TeXGyreTermesMath) is the same family as its text face, so
# it normalises to it. What this catches is Computer Modern arriving alongside
# Termes the moment maths appears without \setmathfont — which is exactly what
# happened when the symbol translator emitted its first minus sign.
# Counting is done in Python. Two attempts at doing it in shell were wrong in
# two different machine-specific ways: [A-Z] is a collation range that excludes I
# under this box's Turkish locale, and the `grep` on PATH is ugrep, which reads
# the braces in `label{tab:x}` as an interval quantifier. A check whose answer
# depends on the locale or on which grep is installed is not a check.
family_report=$("$PY" - <<'FONTS'
import re
import subprocess

out = subprocess.run(
    ["pdffonts", "docs/academic-article/paper/tex/main.pdf"],
    capture_output=True, text=True,
).stdout
names = [ln.split()[0] for ln in out.splitlines()[2:] if ln.strip()]
# Strip the six-letter subset prefix, the weight suffix, and the maths companion:
# TeXGyreTermesMath is the same family as its text face, and the failure this
# catches is Computer Modern arriving beside Termes when maths has no font set.
families = sorted({re.sub(r"^[A-Z]+\+|[-,].*$|Math$", "", n) for n in names})
families = sorted({re.sub(r"Math$", "", f) for f in families if f})
print(len(families), ",".join(families))
FONTS
)
families=${family_report%% *}
if [[ "$families" -le 2 ]]; then
    pass "one serif family plus one monospace (${family_report#* })"
else
    fail "$families font families — body, figures and maths should share one serif"
    note "${family_report#* }"
fi

boxes=$(grep -c 'Overfull\|Underfull' "$LOG" 2>/dev/null)
boxes=${boxes:-0}
if [[ "$boxes" -eq 0 ]]; then
    if grep -q '^\\hfuzz=0pt' "$BUILD/main.tex" 2>/dev/null; then
        pass "zero overfull/underfull boxes, at hfuzz=0"
    else
        fail "zero boxes, but hfuzz is not 0 — the zero is suppressed, not earned"
    fi
else
    fail "$boxes overfull/underfull boxes"
    grep -m3 'Overfull\|Underfull' "$LOG" | sed 's/^/        /'
fi

# --------------------------------------------------------------------------
# 3. Text extraction — a reviewer copying a paragraph must get readable text
# --------------------------------------------------------------------------
extracted=$(pdftotext "$PDF" - 2>/dev/null | grep -cE 'Tra c|e ect|di erent|con dence|speci c|classi cation' || true)
if [[ "$extracted" -eq 0 ]]; then
    pass "text extracts without ligature damage"
else
    fail "$extracted broken ligatures in extracted text"
    note "the font has no ToUnicode map; check the fontspec setup"
fi

# --------------------------------------------------------------------------
# 4. Numbers
# --------------------------------------------------------------------------
if "$PY" -m pytest tests/evaluation/test_paper_numerals.py -q >/tmp/numerals.$$ 2>&1; then
    pass "no hand-typed measurement in the prose"
else
    fail "hand-typed numerals remain"
    grep -oE '[0-9]+ hand-typed numerals in [A-Za-z0-9.-]+' /tmp/numerals.$$ | sed 's/^/        /'
    note "derive each into paper_facts.py, or register it in narrative_provenance.json"
fi
rm -f /tmp/numerals.$$

if "$PY" -m pytest tests/evaluation/test_reanalysis_determinism.py -q >/tmp/determinism.$$ 2>&1; then
    pass "the re-analysis is deterministic and its artifact is current"
else
    fail "the committed cluster analysis is not what the code produces"
    note "run: make reanalyse"
fi
rm -f /tmp/determinism.$$

# --------------------------------------------------------------------------
# 5. Every interval knows the unit it resampled
# --------------------------------------------------------------------------
"$PY" - <<'CHECK'
import json
import sys
from pathlib import Path

blob = json.loads(Path("tests/evaluation/cluster_analysis.json").read_text())
bad = []
for cid, comp in blob["comparisons"].items():
    iv = comp.get("interval") or {}
    if not iv.get("n_clusters") or not iv.get("seed"):
        bad.append(cid)
sys.exit(1 if bad else 0)
CHECK
if [[ $? -eq 0 ]]; then
    pass "every interval records its cluster count and seed"
else
    fail "an interval was written without the provenance needed to reproduce it"
fi

# --------------------------------------------------------------------------
# 6. Structure the rubric requires
# --------------------------------------------------------------------------
# Checked in the rendered PDF, not in the sources. The sources were the wrong
# place: the bibliography is generated by BibTeX under the Elsevier template, so
# there is no \section{References} to grep for and this check failed on a paper
# whose references were present and correct. Reading the artefact also asks the
# stronger question — whether the section is *there*, rather than whether
# somebody typed a heading that might sit inside a commented-out block.
# Searched with a here-string, never through a pipe.
#
# `grep -q` exits at its first match. Whatever is writing into it then takes
# SIGPIPE, and `set -o pipefail` turns that into exit 141 — so the check
# reports a missing section because the *reader* stopped reading. It is
# position-dependent, which is what made it look like nonsense: Discussion
# matches at line 1963 of 2609 and failed, Declarations at 2522 and References
# at 2609 passed, because by then the writer had nothing left to write. A
# here-string is a temporary file rather than a pipe, so there is no writer to
# signal and no race to lose.
#
# The leading character class allows whitespace, and that is load-bearing:
# pdftotext emits a form feed (\f) at the start of the first line of every page,
# so a heading that happens to fall at a page top reads as "\fDeclarations" and
# a pattern anchored on `^[0-9. ]*` cannot match it. This check was written
# without that and passed anyway, because on a 54-page draft all three headings
# landed mid-page. Adding two pages moved Declarations and References to page
# tops and both went red at once, with the sections present and correct.
#
# So this is the second time these three checks have failed for a reason that
# had nothing to do with the sections: first SIGPIPE, now pagination. The lesson
# is the same one the paper argues about instruments — a check that passes can
# be passing by luck, and only a deliberate attempt to break it tells them
# apart. POSIX [[:space:]] includes \f, which is why it is used here rather than
# a literal space.
pdf_text=$(pdftotext "$BUILD/main.pdf" - 2>/dev/null)
for section in Discussion Declarations References; do
    if grep -qE "^[[:space:]0-9.]*$section[[:space:]]*$" <<<"$pdf_text"; then
        pass "has a $section section"
    else
        fail "no $section section"
    fi
done

abstract_words=$("$PY" - <<'WORDS'
import json
import re
from pathlib import Path

tex = Path("docs/academic-article/paper/tex/abstract.tex").read_text()
facts = json.loads(Path("tests/evaluation/paper_facts.json").read_text())
tex = re.sub(r"\\fact\{([a-z0-9-]+)\}", lambda m: facts.get(m.group(1).replace("-", "_"), "0"), tex)
tex = re.sub(r"\\[a-zA-Z]+\*?", " ", tex)          # strip control sequences
tex = re.sub(r"[{}$~\\]", " ", tex)
print(len(re.findall(r"[A-Za-z0-9][\w.,%\[\]+-]*", tex)))
WORDS
)
if [[ "$abstract_words" -ge 150 && "$abstract_words" -le 250 ]]; then
    pass "abstract is $abstract_words words"
else
    fail "abstract is $abstract_words words, outside 150-250"
fi

# --------------------------------------------------------------------------
# 6b. Every table is numbered, captioned and referenceable
# --------------------------------------------------------------------------
table_report=$("$PY" - <<'TABLES'
import re
from pathlib import Path

tex = "".join(p.read_text() for p in sorted(Path("docs/academic-article/paper/tex").glob("*.tex")))
tables = len(re.findall(r"\\begin\{longtable\}", tex))
labels = set(re.findall(r"\\label\{(tab:[a-z0-9-]+)\}", tex))
captions = len(re.findall(r"\\caption\{", tex))
print(tables, len(labels), captions)
TABLES
)
read -r n_tables n_labels n_captions <<<"$table_report"
if [[ "$n_tables" -eq "$n_labels" ]]; then
    pass "all $n_tables tables numbered, captioned and referenceable"
else
    fail "$n_tables tables but $n_labels distinct table labels — every table needs one"
fi

# --------------------------------------------------------------------------
# 7. Anonymity, over the whole assembled document rather than section by section
# --------------------------------------------------------------------------
if grep -qir 'maljan' "$BUILD"/*.tex; then
    fail "the system name reached a LaTeX source"
    grep -oihrm3 'maljan' "$BUILD"/*.tex | sed 's/^/        /'
else
    pass "anonymity clean across the whole document, title and preamble included"
fi

# --------------------------------------------------------------------------
# 8. The unreviewed sources declare themselves in the document a reader gets
# --------------------------------------------------------------------------
# The tests check that every citation to an unreviewed source carries the
# marker in the *sources*. They cannot see what BibTeX did with it. On
# 2026-08-16 the answer was: elsarticle-num lowercases the first letter of a
# note field, so all eight declarations rendered as "pREPRINT — not peer
# reviewed" — the one word carrying the disclosure, visibly broken, in the
# reference list of a paper whose subject is citation discipline. Nothing
# caught it because nothing read the artefact.
#
# So this reads the artefact. Both halves of the disclosure must survive: the
# in-body [preprint] marker at every use site, and one intact PREPRINT note per
# declared entry.
expected=$("$PY" - <<'DECL'
import json
import re
from pathlib import Path

paper = Path("docs/academic-article/paper")
status = json.loads((paper / "preprint-status.json").read_text())
unreviewed = set(status["entries"]) | set(status["not_papers"])
# One marker per macro *invocation*, not per key: \preprintcite{a,b} cites two
# unreviewed sources and prints one [preprint] covering both. Counting keys
# here reported a missing marker for a paper that had them all.
markers = 0
for path in sorted((paper / "tex").glob("*.tex")):
    text = path.read_text()
    markers += len(re.findall(r"\\preprintcite\{[^}]*\}", text))
    # Plus any typed straight into the prose — the citation audit quotes the
    # marker when it explains what the marker means.
    markers += len(re.findall(r"\[preprint\]", text))
print(len(unreviewed), markers)
DECL
)
read -r n_entries n_markers <<<"$expected"
notes=$(grep -oE '\bPREPRINT\b' <<<"$pdf_text" | wc -l)
mangled=$(grep -oE '\bpREPRINT\b' <<<"$pdf_text" | wc -l)
markers=$(grep -oF '[preprint]' <<<"$pdf_text" | wc -l)

if [[ "$mangled" -gt 0 ]]; then
    fail "$mangled reference note(s) render as 'pREPRINT' — the bst case-folded the disclosure"
    note "brace-protect it in refs.bib: note = {{PREPRINT} --- ...}"
elif [[ "$notes" -ne "$n_entries" ]]; then
    fail "$n_entries sources are declared unreviewed but $notes say so in the reference list"
    note "every entry in preprint-status.json needs a PREPRINT note in refs.bib"
elif [[ "$markers" -ne "$n_markers" ]]; then
    fail "$n_markers [preprint] marker(s) are written in the sources but $markers reached the page"
else
    pass "all $n_entries unreviewed sources declared, at $markers marked use sites and in the reference list"
fi

echo
if [[ "$fails" -eq 0 ]]; then
    printf '\033[32mall checks passed\033[0m\n'
    exit 0
fi
printf '\033[31m%d check(s) failed\033[0m\n' "$fails"
exit 1
