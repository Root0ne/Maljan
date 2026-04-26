"""FunctionSummarizer — iki asarali token maliyet optimizasyonu.

Problem:
    Buyuk binary analiz raporlari (decompile ciktisi, 1000+ fonksiyon)
    dogrudan expert LLM'e gonderildiginde:
      - Context penceresi asiyor (gpt-4o: 128k token = ~$0.60/analiz)
      - Model performansi duser (needle in a haystack sorunu)

Cozum — iki asarali pipeline:
    Asama 1 (Summarize): Kucuk/ucuz LLM (orn. llama3.2:3b, gpt-4o-mini)
                         her chunk'i MAX_SUMMARY_WORDS kelimeye indirir.
    Asama 2 (Analyze):   Expert LLM sadece ozet metni gorur.

Token maliyet karsilastirmasi (varsayimsal):
    Dogrudan gonderim : ~20,000 token / analiz (@gpt-4o: ~$0.15)
    Iki asarali       : ~3,000 token / analiz (@gpt-4o: ~$0.02)
    Tasarruf          : ~%85 azalma

Sinifin tasarimi:
    - Bagimsiz: sadece LangChain BaseChatModel gerekir.
    - ServiceContainer.get_function_summarizer() ile erisim.
    - Settings.preprocessing.use_function_summarizer=True ile devreye girer.
    - None donduruldugunde pipeline'da seffaf sekilde atlanir.

Kullanim:
    summarizer = container.get_function_summarizer()
    if summarizer is not None:
        condensed = summarizer.summarize_chunks(function_chunks)
    else:
        condensed = "\n".join(function_chunks)
    # condensed artik expert LLM'e gidebilir
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from maljan.core.logger import logger

if TYPE_CHECKING:
    from langchain_core.language_models.chat_models import BaseChatModel

# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

_SUMMARIZE_SYSTEM = (
    "You are a malware analysis assistant. "
    "Your task is to summarize a decompiled code fragment or function list "
    "in plain English, focusing ONLY on security-relevant behaviors. "
    "Be concise. Never hallucinate."
)

_SUMMARIZE_HUMAN_TMPL = (
    "Summarize the following decompiled code fragment in at most {max_words} words. "
    "Focus on: API calls, suspicious operations, network activity, persistence, "
    "process manipulation, encryption, and evasion techniques. "
    "Omit boilerplate code, standard library internals, and benign operations.\n\n"
    "--- BEGIN CODE ---\n"
    "{code_chunk}\n"
    "--- END CODE ---\n\n"
    "Summary:"
)

_MERGE_SYSTEM = (
    "You are a malware analysis assistant. "
    "Merge the following chunk summaries into a single coherent analysis summary."
)

_MERGE_HUMAN_TMPL = (
    "Merge these chunk summaries into one coherent analysis summary "
    "in at most {max_words} words:\n\n"
    "{summaries}\n\n"
    "Merged summary:"
)


# ---------------------------------------------------------------------------
# FunctionSummarizer
# ---------------------------------------------------------------------------


class FunctionSummarizer:
    """Iki asarali LLM tabanlı token maliyet optimizasyonu.

    Args:
        llm:              Summarizer LLM (kucuk/ucuz model onerilir).
        max_summary_words: Her chunk ozeti icin maksimum kelime sayisi.
    """

    def __init__(
        self,
        llm: BaseChatModel,
        max_summary_words: int = 150,
    ) -> None:
        self._llm = llm
        self._max_words = max_summary_words

    def summarize_chunk(self, code_chunk: str) -> str:
        """Tek bir kod veya fonksiyon blogu ozetler.

        Args:
            code_chunk: Decompile edilmis kod, fonksiyon listesi veya
                        analiz raporu parcasi.

        Returns:
            Guvenligi ilgili davranislari iceren kisaltilmis metin.
        """
        from langchain_core.messages import HumanMessage, SystemMessage

        prompt = _SUMMARIZE_HUMAN_TMPL.format(
            max_words=self._max_words,
            code_chunk=code_chunk[:8000],  # Hard limit — token tasarrufu
        )

        messages = [
            SystemMessage(content=_SUMMARIZE_SYSTEM),
            HumanMessage(content=prompt),
        ]

        try:
            response = self._llm.invoke(messages)
            summary: str = response.content  # type: ignore[union-attr]
            word_count = len(summary.split())
            logger.debug(
                "FunctionSummarizer: chunk summarized — %d chars -> %d words.",
                len(code_chunk),
                word_count,
            )
            return summary.strip()
        except Exception as exc:
            logger.warning(
                "FunctionSummarizer.summarize_chunk failed: %s — returning raw chunk.", exc
            )
            # Graceful degradation: hata durumunda ham chunk doner
            return code_chunk[: self._max_words * 6]  # Yaklasik karakter limiti

    def summarize_chunks(self, chunks: list[str]) -> str:
        """Birden fazla chunk'i ozetler ve birlestir.

        Her chunk ayrı ayrı ozetlenir, ardından tum ozetler tek bir
        birlesmis ozete indirgenebilir (birlesim opsiyonel).

        Args:
            chunks: Ozetlenecek kod/rapor bloklari listesi.

        Returns:
            Tum chunk'lerin birlesmis ozeti (tek metin).
        """
        if not chunks:
            return ""

        if len(chunks) == 1:
            return self.summarize_chunk(chunks[0])

        summaries: list[str] = []
        for i, chunk in enumerate(chunks, start=1):
            logger.info(
                "FunctionSummarizer: summarizing chunk %d/%d (%d chars).",
                i,
                len(chunks),
                len(chunk),
            )
            summary = self.summarize_chunk(chunk)
            summaries.append(f"[Chunk {i}] {summary}")

        # Tek ozet varsa birlestirme yapmaya gerek yok
        if len(summaries) <= 3:
            merged = "\n\n".join(summaries)
        else:
            merged = self._merge_summaries(summaries)

        logger.info(
            "FunctionSummarizer: %d chunks -> merged summary (%d chars).",
            len(chunks),
            len(merged),
        )
        return merged

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _merge_summaries(self, summaries: list[str]) -> str:
        """Cok sayida chunk ozetini tek bir ozette birlestir.

        Args:
            summaries: Her chunk icin ozet metinleri listesi.

        Returns:
            Birlesmis ozet metni.
        """
        from langchain_core.messages import HumanMessage, SystemMessage

        combined = "\n\n".join(summaries)
        prompt = _MERGE_HUMAN_TMPL.format(
            max_words=self._max_words * 2,
            summaries=combined[:12000],  # Token korumasi
        )

        messages = [
            SystemMessage(content=_MERGE_SYSTEM),
            HumanMessage(content=prompt),
        ]

        try:
            response = self._llm.invoke(messages)
            result: str = response.content  # type: ignore[union-attr]
            return result.strip()
        except Exception as exc:
            logger.warning(
                "FunctionSummarizer._merge_summaries failed: %s — returning concatenated.", exc
            )
            return combined
