"""What the run saw, as opposed to what the ledger kept.

A grounding check asks one question: did any tool in this run actually produce
this value. It used to ask that of the *stored* ledger, and the stored ledger is
not the run. ``schemas.evidence.apply_budget`` blanks an entry's ``output`` and
``structured`` once an agent's answers pass ``reporting.evidence_budget_bytes``
— **after** the model has read them — so a value a tool really returned, and a
model really saw, is absent from the corpus the judge is grounded against. The
judge was then told the value *"appears nowhere in the evidence this run
collected"*, spent its one retry on it, and had the object dropped from the
exported bundle. A deterministic statement the platform makes is right or
absent, and that one was wrong.

This is the other half of the record: the searchable text of every tool answer
**as the model received it** — after the output shortener, which is the document
the model read, and before the byte budget trims what is stored. It exists for
the length of one job and no longer:

* in memory only, on the container, never in the graph state and never
  persisted, so it cannot grow a database row or travel between processes;
* dropped when the job's container is released;
* bounded by ``reporting.evidence_corpus_bytes``, and when that ceiling is
  reached the corpus says it is **incomplete** rather than quietly holding
  less than it claims.

Incomplete is the word the rest of the system acts on. The platform does not
assert an absence over evidence it knows is partial: a grounding check that
searched an incomplete corpus writes an advisory finding — the value was not
found in the evidence that was *kept*, and here is how much was not — and
nothing drops an object on that ground. The sentence itself is written in
``pipeline.validation`` beside the other grounding sentences, so the guard that
holds every finding row to one wrapping helper walks it with the rest.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass


@dataclass(frozen=True)
class CorpusState:
    """What a check that searched the corpus may say about what it searched.

    Carried rather than recomputed, because the check runs long after the
    corpus stopped growing and a sentence about the evidence must describe the
    evidence the check actually had.
    """

    # False when the corpus could not hold everything the run produced, or when
    # there is no corpus at all — a run resumed in another process, a report
    # rebuilt from stored entries. Either way an absence is advisory.
    complete: bool = True
    # How many answers are missing from it, and whose. Counts and tool names
    # only: a sentence naming a value would put a tool's output back into the
    # very row the value was withheld from.
    missing_answers: int = 0
    missing_tools: tuple[str, ...] = ()
    # Why it is partial, in one word an operator can act on: the ceiling was
    # reached, the ceiling is zero, or the run has no corpus at all. Carried
    # rather than inferred, because the three are one setting apart and the
    # remedy differs.
    why: str = ""

    @property
    def partial(self) -> bool:
        return not self.complete


# Why a corpus is partial. One of these reaches the run summary and the
# degradation reason, so an operator reads a remedy rather than a symptom.
CEILING_REACHED = "ceiling reached"
CEILING_ZERO = "ceiling zero"
CORPUS_ABSENT = "run resumed without its corpus"


def both_searched(first: CorpusState, second: CorpusState) -> CorpusState:
    """What a check may say when what it searched came from two sources.

    Completeness is a **conjunction**. A search that read one whole source and
    one partial one searched something partial, and a fallback that reports
    itself whole must never launder the state of the source it fell back from:
    a run with no corpus whose stored entries all survived the byte budget is
    still a run nobody can say "this value is in no tool output" about.
    """
    return CorpusState(
        complete=first.complete and second.complete,
        missing_answers=first.missing_answers + second.missing_answers,
        missing_tools=tuple(sorted(set(first.missing_tools) | set(second.missing_tools))),
        why=first.why or second.why,
    )


# What a corpus that does not exist says about itself. A report rebuilt from
# stored entries, a run resumed in another process: the checks still run, and
# what they may conclude is bounded by this.
NO_CORPUS = CorpusState(complete=False, why=CORPUS_ABSENT)


class RunEvidenceCorpus:
    """Every tool answer of one run, as the model received it. In memory only."""

    def __init__(self, ceiling_bytes: int) -> None:
        self._lock = threading.Lock()
        self._ceiling = max(0, int(ceiling_bytes))
        self._texts: dict[str, str] = {}
        self._tools: dict[str, str] = {}
        self._spent = 0
        self._missing_answers = 0
        self._missing_tools: list[str] = []

    def remember(self, entry_id: str, tool: str, text: str) -> None:
        """Keep one answer's text. Never raises.

        Called from the recorder with the string the model was handed, so what
        is kept and what was read are the same characters. An answer that does
        not fit the ceiling is not kept and is counted instead, which is what
        makes the corpus able to say it is incomplete.

        Kept **lower-cased**, once, here. Every reader of it compares
        lower-cased — that is the corpus's own rule — and folding the case at
        each read copied the whole record again per check.
        """
        key = str(entry_id or "").strip()
        body = str(text or "")
        if not key or not body:
            return
        name = str(tool or "").strip() or "a tool"
        body = body.lower()
        size = len(body.encode("utf-8", errors="ignore"))
        with self._lock:
            if key in self._texts:
                return
            # A ceiling of zero keeps nothing, and a corpus that keeps nothing
            # is incomplete — which makes every absence a note, deliberately.
            if self._spent + size > self._ceiling:
                self._missing_answers += 1
                if name not in self._missing_tools:
                    self._missing_tools.append(name)
                return
            self._texts[key] = body
            self._tools[key] = name
            self._spent += size

    def text_for(self, entry_id: str) -> str:
        """One answer's text, lower-cased, or ``""`` when the corpus never held it."""
        with self._lock:
            return self._texts.get(str(entry_id or "").strip(), "")

    def tool_of(self, entry_id: str) -> str:
        """Which tool answered this entry, or ``""``.

        Kept beside the text because a caller that narrows by producer — the
        export's second-source test excludes the string sweep's own entries —
        has to be able to narrow the corpus the same way it narrows the report.
        """
        with self._lock:
            return self._tools.get(str(entry_id or "").strip(), "")

    def parts(self) -> tuple[str, ...]:
        """Every answer, lower-cased, as the answers they are.

        Not one joined string. A value never spans two answers — the join put a
        space between them, and a space bounds a value — so searching each
        answer is exactly the search a joined one performed, and joining copied
        the whole record on the way in, again into the token set, and a third
        time into the string that was finally searched. Measured on 400 answers
        of 6 000 characters, those three copies cost 8 MB of the check's 42.
        """
        with self._lock:
            return tuple(self._texts.values())

    def state(self) -> CorpusState:
        """What a check that searched this corpus may say about what it searched."""
        with self._lock:
            if not self._missing_answers:
                return CorpusState()
            return CorpusState(
                complete=False,
                missing_answers=self._missing_answers,
                missing_tools=tuple(sorted(self._missing_tools)),
                why=CEILING_ZERO if self._ceiling <= 0 else CEILING_REACHED,
            )

    def __len__(self) -> int:
        with self._lock:
            return len(self._texts)


def state_of(corpus: object | None) -> CorpusState:
    """``corpus.state()``, or :data:`NO_CORPUS`. Never raises.

    A caller that has no corpus is in exactly the position a caller with an
    overflowing one is: it cannot say a value is absent from this run, only
    that it is absent from what it searched.
    """
    if corpus is None:
        return NO_CORPUS
    try:
        state = corpus.state()  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 — a missing corpus is a weaker claim, not a failure
        return NO_CORPUS
    return state if isinstance(state, CorpusState) else NO_CORPUS


def parts_of(corpus: object | None) -> tuple[str, ...]:
    """``corpus.parts()``, or ``()``. Never raises."""
    if corpus is None:
        return ()
    try:
        found = corpus.parts()  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        return ()
    return tuple(found) if isinstance(found, tuple | list) else ()
