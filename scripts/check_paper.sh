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
BUILD="$PAPER_DIR/build"
PDF="$BUILD/paper.pdf"
LOG="$BUILD/paper.log"
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
pass "built: $pages pages"

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
# LC_ALL=C because this box runs a Turkish locale, where [A-Z] is a collation
# range that does not contain I — so a subset prefix like VPIHHP+ survived the
# strip and one font counted twice. A range expression is only a byte range in
# the C locale, and a check that behaves differently per machine is not a check.
family_list=$(pdffonts "$PDF" 2>/dev/null | awk 'NR>2{print $1}' \
    | LC_ALL=C sed -E 's/^[A-Z]+\+//; s/[-,].*//; s/Math$//' | LC_ALL=C sort -u | grep -v '^$')
families=$(echo "$family_list" | grep -c .)
if [[ "$families" -le 2 ]]; then
    pass "one serif family plus one monospace ($(echo "$family_list" | paste -sd', '))"
else
    fail "$families font families — body, figures and maths should share one serif"
    echo "$family_list" | sed 's/^/        /'
fi

boxes=$(grep -c 'Overfull\|Underfull' "$LOG" 2>/dev/null)
boxes=${boxes:-0}
if [[ "$boxes" -eq 0 ]]; then
    if grep -q '^\\hfuzz=0pt' "$BUILD/paper.tex" 2>/dev/null; then
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
for section in Discussion Declarations References; do
    if grep -q "\\\\section\*\?{$section}" "$BUILD/paper.tex"; then
        pass "has a $section section"
    else
        fail "no $section section"
    fi
done

abstract_words=$("$PY" - <<'WORDS'
import re
import sys
from pathlib import Path

sys.path.insert(0, "docs/academic-article/paper")
import build_paper as B  # noqa: E402

md = Path("docs/academic-article/paper/E4-outline.md").read_text()
facts = __import__("json").loads(Path("tests/evaluation/paper_facts.json").read_text())
text, _ = B.substitute_facts(B.extract_abstract(md), facts, "abstract")
print(len(re.findall(r"[A-Za-z0-9][\w.,%\[\]+×−-]*", text)))
WORDS
)
if [[ "$abstract_words" -ge 150 && "$abstract_words" -le 250 ]]; then
    pass "abstract is $abstract_words words"
else
    fail "abstract is $abstract_words words, outside 150-250"
fi

# --------------------------------------------------------------------------
# 7. Anonymity, over the whole assembled document rather than section by section
# --------------------------------------------------------------------------
if grep -qi 'maljan' "$BUILD/paper.tex"; then
    fail "the system name reached the assembled .tex"
    grep -oim3 'maljan' "$BUILD/paper.tex" | sed 's/^/        /'
else
    pass "anonymity clean across the whole document, title and preamble included"
fi

echo
if [[ "$fails" -eq 0 ]]; then
    printf '\033[32mall checks passed\033[0m\n'
    exit 0
fi
printf '\033[31m%d check(s) failed\033[0m\n' "$fails"
exit 1
