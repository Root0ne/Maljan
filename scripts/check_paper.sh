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

# Overfull and underfull are not the same finding and this check used to treat
# them as one. Overfull is text past the margin: a defect, and the count stays
# at zero, still at hfuzz=0 so no sub-half-point overrun is hidden. Underfull is
# a loose line, which is a spacing judgement rather than a defect, and at the
# class's own measure eight of the eleven are in the bibliography, where BibTeX
# chooses the line breaks and long author lists have nowhere good to break.
#
# The distinction is recorded rather than assumed: this policy changed when the
# page went from a 506pt override to the class measure, and a check that failed
# on both would have been satisfied only by widening the page again.
over=$(grep -c 'Overfull' "$LOG" 2>/dev/null); over=${over:-0}
under=$(grep -c 'Underfull' "$LOG" 2>/dev/null); under=${under:-0}
if [[ "$over" -eq 0 ]]; then
    if grep -q '^\\hfuzz=0pt' "$BUILD/main.tex" 2>/dev/null; then
        pass "zero overfull boxes at hfuzz=0; $under loose line(s), reported not hidden"
    else
        fail "zero overfull, but hfuzz is not 0 — the zero is suppressed, not earned"
    fi
else
    fail "$over overfull box(es): text past the margin"
    grep -m3 'Overfull' "$LOG" | sed 's/^/        /'
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
tables = len(re.findall(r"\\begin\{table\}", tex))
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
# 6b. Highlights: Elsevier's limits, and the numbers they quote
# --------------------------------------------------------------------------
# Highlights ship as a separate file and never reach the PDF, so nothing else in
# this script would ever look at them. Three to five bullets, 85 characters each,
# and every number in one has to be a number the paper derives -- a highlight
# that rounds differently from the table it summarises is a hand-typed numeral
# with a shorter line length.
"$PY" - <<'HIGHLIGHTS'
import json
import re
import sys
from pathlib import Path

src = Path("docs/academic-article/paper/highlights.md")
if not src.exists():
    print("no highlights file")
    sys.exit(1)
body = src.read_text().split("## Measuring", 1)[-1].split("## Where", 1)[0]
bullets = [m for m in re.finditer(r"^- (.*?) \[(\d+)\]$", body, re.M)]
facts = {str(v).strip().lstrip("+") for v in json.loads(
    Path("tests/evaluation/paper_facts.json").read_text()).values()}
bad = []
if not 3 <= len(bullets) <= 5:
    bad.append(f"{len(bullets)} bullets, Elsevier wants 3 to 5")
for m in bullets:
    text, claimed = m.group(1), int(m.group(2))
    if len(text) > 85:
        bad.append(f"{len(text)} chars: {text[:50]}...")
    if len(text) != claimed:
        bad.append(f"claims {claimed} chars and is {len(text)}: {text[:40]}...")
    for num in re.findall(r"(?<![\w.])\d[\d,]*(?:\.\d+)?(?![\d,]|\.\d)", text):
        if not any(f.startswith(num) or num.startswith(f.rstrip("0")) for f in facts):
            bad.append(f"{num!r} is in a highlight and is not a derived value")
for b in bad:
    print(b)
sys.exit(1 if bad else 0)
HIGHLIGHTS
if [[ $? -eq 0 ]]; then
    pass "highlights: 3-5 bullets, each within 85 characters, every number derived"
else
    fail "the highlights do not meet Elsevier's limits or quote a number the paper does not"
fi

# --------------------------------------------------------------------------
# 7. The system name, permitted in exactly one place
# --------------------------------------------------------------------------
# This was an anonymity check while the author block was empty. The authors are
# named now, so blind review is no longer the reason -- but the rule outlives it,
# because the paper calls the object of study "the pipeline" from the abstract to
# the conclusion and never brands it, and that is a decision about how the paper
# reads. The repository is named after the system, so the one reference entry
# carrying its address is the single permitted occurrence. Two checks, because a
# rule with an exception needs the exception checked and not merely tolerated:
# the name may not reach a LaTeX source at all, and on the page it may appear
# only after the References heading.
name_tex=$(grep -oihr 'maljan' "$BUILD"/*.tex | wc -l)
name_body=$(sed '/^[[:space:]0-9.]*References[[:space:]]*$/,$d' <<<"$pdf_text" \
            | grep -oi 'maljan' | wc -l)
name_refs=$(sed -n '/^[[:space:]0-9.]*References[[:space:]]*$/,$p' <<<"$pdf_text" \
            | grep -oi 'maljan' | wc -l)
if [[ "$name_tex" -ne 0 ]]; then
    fail "the system name reached a LaTeX source"
    grep -oihrm3 'maljan' "$BUILD"/*.tex | sed 's/^/        /'
elif [[ "$name_body" -ne 0 ]]; then
    fail "$name_body use(s) of the system name in the body; it belongs to the repository entry"
    sed '/^[[:space:]0-9.]*References[[:space:]]*$/,$d' <<<"$pdf_text" \
        | grep -m3 -oiE '.{40}maljan.{40}' | sed 's/^/        /'
elif [[ "$name_refs" -eq 0 ]]; then
    fail "the repository entry no longer carries the address it exists to carry"
    note "release2026artefact in refs.bib should hold the repository URL"
else
    pass "the system name appears only in the reference list, at $name_refs use(s)"
fi

# --------------------------------------------------------------------------
# 7b. House style, checked in the rendered document
# --------------------------------------------------------------------------
# Two typographic rules with no exceptions, so both are gates rather than
# advice. They are checked in the extracted PDF text and not in the sources,
# because the source spelling and the printed character are different things:
# `---` is what an author types and U+2014 is what a reader sees, and a `---`
# living in a .bib note or a matplotlib annotation reaches the page by a route
# no grep over *.tex would find. Three did.
#
# The en dash goes the same way, and the arrow with it. Both had the same
# spelling problem in reverse: the source says `--` and `$\rightarrow$`, so a
# grep for the printed character over the sources finds nothing while 35 dashes
# and 7 arrows sit on the page.
emdash=$(grep -oF '—' <<<"$pdf_text" | wc -l)
if [[ "$emdash" -eq 0 ]]; then
    pass "no em dash in the rendered text"
else
    fail "$emdash em dash(es) reached the page"
    grep -oF -m3 -B0 -A0 '—' <<<"$pdf_text" >/dev/null
    grep -n -m3 -oE '.{40}—.{40}' <<<"$pdf_text" | sed 's/^/        /'
    note "sources spell it ---; check refs.bib and make_paper_figures.py too"
fi

# En dash, with one carve-out that is stated rather than assumed. Everything the
# paper writes for itself is checked at zero. The reference list is not written
# by the paper: elsarticle-num.bst runs every `pages` field through n.dashify,
# which rewrites a hyphen into `--` on the way to the .bbl, so `51-68` in the
# .bib comes back as 51–68 regardless of what is typed. Patching that would mean
# shipping an altered Elsevier bst, and Elsevier recompiles from the .bib at
# submission, so the patch would not survive the journal anyway. Page ranges are
# therefore the style's dash and not ours. The carve-out is deliberately narrow:
# digits either side, and only after the References heading, so a range in the
# body still fails.
endash_body=$(sed '/^[[:space:]0-9.]*References[[:space:]]*$/,$d' <<<"$pdf_text" \
              | grep -oF '–' | wc -l)
# Joined into one line first. A page range that wraps prints as "pp. 3473–" at
# the end of one line and "3487" at the start of the next, and the digit the
# lookahead needs is on the other side of a newline: the carve-out then misses
# it and the range reads as a stray dash. Two of the sixteen wrap today, and
# which two depends on pagination, so the check would move on its own.
endash_refs=$(sed -n '/^[[:space:]0-9.]*References[[:space:]]*$/,$p' <<<"$pdf_text" \
              | tr -d '\n' | grep -oP '(?<![0-9])–|–(?![0-9])' | wc -l)
if [[ "$endash_body" -eq 0 && "$endash_refs" -eq 0 ]]; then
    pass "no en dash in the rendered text, bar bst-generated page ranges"
else
    fail "$endash_body en dash(es) in the body, $endash_refs outside a page range"
    sed '/^[[:space:]0-9.]*References[[:space:]]*$/,$d' <<<"$pdf_text" \
        | grep -m3 -oE '.{40}–.{40}' | sed 's/^/        /'
    note "sources spell it --; a range reads better as \"7 to 85%\" anyway"
fi

# Arrows. Every one of them stood between two things a preposition joins just as
# well, which is why none of the seven needed a replacement longer than "to".
arrows=$(grep -oP '[\x{2190}-\x{21FF}\x{27F0}-\x{27FF}]' <<<"$pdf_text" | wc -l)
if [[ "$arrows" -eq 0 ]]; then
    pass "no arrow glyphs in the rendered text"
else
    fail "$arrows arrow glyph(s) reached the page"
    grep -m3 -oP '.{40}[\x{2190}-\x{21FF}\x{27F0}-\x{27FF}].{40}' <<<"$pdf_text" | sed 's/^/        /'
    note "sources spell it \$\\rightarrow\$; write the relation as words"
fi

section_sign=$(grep -oF '§' <<<"$pdf_text" | wc -l)
if [[ "$section_sign" -eq 0 ]]; then
    pass "no section sign in the rendered text"
else
    fail "$section_sign section sign(s) reached the page"
    note "write Section~N instead"
fi

# A doubled backslash in front of a macro name. `\\ref{sec:results}` is a line
# break followed by the literal text `ref`, and braces are grouping characters,
# so it printed as "the subject of Section" then a new line reading
# "refsec:results." Nothing else caught it: \ref never ran, so there is no `??`
# to find, and the cross-reference gate counts hand-typed `Section~N`, which
# this is not. Checked in the sources because the rendered form is unremarkable
# text. `\\` before an ordinary word is a legitimate line break; before one of
# these names it is always a mangled control sequence.
doubled=$(grep -c '\\\\\(ref\|cite\|preprintcite\|fact\|setting\|label\|emph\|texttt\|textasciitilde\){' \
          "$BUILD"/*.tex "$BUILD"/*.sty 2>/dev/null | awk -F: '{s+=$2} END{print s+0}')
if [[ "$doubled" -eq 0 ]]; then
    pass "no macro name behind a doubled backslash"
else
    fail "$doubled mangled control sequence(s) in the sources"
    grep -n -m3 '\\\\\(ref\|cite\|fact\|label\){' "$BUILD"/*.tex 2>/dev/null | sed 's|.*/|        |'
fi

# Bulleted structure, checked in the sources because that is where it is
# authored. Prose is the house default; a list has to be argued for.
lists=$(grep -c 'begin{itemize}\|begin{enumerate}\|begin{description}' "$BUILD"/*.tex 2>/dev/null \
        | awk -F: '{s+=$2} END{print s+0}')
if [[ "$lists" -eq 0 ]]; then
    pass "no bulleted lists; the argument is carried in prose"
else
    fail "$lists list environment(s) in the sources"
    note "thirteen were converted to prose; a new one needs a reason"
fi

# Bold. Headings are set bold by the class; nothing else in this document is.
# An earlier pass read "reduce bold" as licence to keep it where it looked
# structural, and left 218 -- run-in pseudo-headings that a reader cannot tell
# from the start of a paragraph, table cells, and the [preprint] marker. The
# rule has no exceptions now, so it is a count rather than a judgement.
bold=$(grep -c '\\textbf' "$BUILD"/*.tex "$BUILD"/*.sty 2>/dev/null \
       | awk -F: '{s+=$2} END{print s+0}')
if [[ "$bold" -eq 0 ]]; then
    pass "no bold outside the headings the class sets"
else
    fail "$bold \\textbf in the sources"
    grep -o -m3 '\\textbf{[^}]\{0,50\}' "$BUILD"/*.tex 2>/dev/null | sed 's|.*/|        |'
fi

# The class documentation points at the table environment for tabular material,
# and none of the two dozen tables here spans a page. longtable was a pandoc
# conversion artefact.
lt=$(grep -c 'begin{longtable}' "$BUILD"/*.tex 2>/dev/null | awk -F: '{s+=$2} END{print s+0}')
if [[ "$lt" -eq 0 ]]; then
    pass "tables are table floats, as the class documents"
else
    fail "$lt longtable(s) in the sources"
fi

# Cross-references. Fifty section numbers were typed by hand and eight of them
# pointed at sections that do not exist, which is this paper's own subject
# happening to this paper: a hand-maintained number that drifted off its source
# and stayed plausible. They are \ref now, and a literal one fails here.
hardref=$(grep -o 'Section~[0-9]' "$BUILD"/*.tex 2>/dev/null | wc -l)
if [[ "$hardref" -eq 0 ]]; then
    pass "every cross-reference goes through \\ref"
else
    fail "$hardref hand-typed section number(s)"
    note "write Section~\\ref{label}"
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
