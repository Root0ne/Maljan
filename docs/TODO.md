# Maljan — TODO

Bu belge, `maljan_master_plan.md` ile projenin mevcut implementasyonu karşılaştırılarak hazırlanmıştır.
Geliştirme süreci, ajanların gerçek dünya araçlarını (MCP, Ghidra, CAPE) kullanma yeteneklerini öne çekecek şekilde revize edilmiş,
ardından ajanların karar mekanizmalarını (Anti-Echo-Chamber) güçlendirecek adımlar sıraya konmuştur.

---

## Öncelik Sırası

| # | Görev | Durum | Etki / Öncelik |
|---|---|---|---|
| **A** | YARA kural seti genişletmesi (MITRE verisi uyarlaması) | `[x] TAMAMLANDI` | Kritik |
| **B** | Sigma Layer 0 (pySigma + SigmaHQ entegrasyonu) | `[x] TAMAMLANDI` | Yüksek |
| **C** | Hatching Triage sandbox client | `[x] TAMAMLANDI` | Orta |
| **D** | FunctionSummarizer (iki aşamalı chunk pipeline) | `[x] TAMAMLANDI` | Düşük |
| **E** | **CAPEv2 MCP Araç Genişletmesi & Optimizasyonu** | `[x] TAMAMLANDI` | Yüksek |
| **F** | **Ghidra MCP Prompt Tuning (Agent Eğitimi)** | `[x] TAMAMLANDI` | Yüksek |
| **G** | **Uçtan Uca (E2E) ReAct Pipeline & Orkestrasyon** | `[x] TAMAMLANDI` | Kritik |
| **H** | **Phase 1: Anti-Echo-Chamber Engine (Sycophancy Detector)** | `[x] TAMAMLANDI` | Kritik |
| **I** | **Phase 2: Adaptive Termination (Rolling Std Convergence)** | `[x] TAMAMLANDI` | Yüksek |
| **J** | **Phase 5: Long-Term Memory / RAG (Qdrant & STIX Store)** | `[x] TAMAMLANDI` | Yüksek |

---

## Yakın Vadeli Görevler (MCP ve Canlı Entegrasyon)

### [x] TODO-E: CAPEv2 MCP Araç Genişletmesi & Optimizasyonu

**Durum:** TAMAMLANDI
**Etki:** Yüksek

- [x] **Tool Discovery Çözümü:** `mcp_client.py` içerisindeki `_create_langchain_tool()` metodunda `getattr()` ile dict erişimi yapılıyordu; `dict.get()` ile değiştirildi. MCP SDK'daki `Tool.inputSchema` tipi `dict[str, Any]` olduğundan `getattr` her zaman boş default döndürüyordu — bu da tüm araçların parametresiz oluşturulmasına neden oluyordu.
- [x] **Prompt Güncellemesi:** `dynamic_analyst.py` içerisindeki `_ISR_SYSTEM` promptunda 7 adımlı araç kullanım iş akışı (`get_cuckoo_status` -> `search_task` -> `submit_file` -> `get_task_status` -> `get_task_report` -> `get_task_iocs` -> `get_task_config`) zaten mevcuttu ve yeterliydi.

---

### [x] TODO-F: Ghidra MCP Prompt Tuning (Agent Eğitimi)

**Durum:** TAMAMLANDI
**Etki:** Yüksek

- [x] **Few-Shot Örneklerinin Eklenmesi:** `static_analyst.py` içerisindeki `_ISR_SYSTEM` promptuna 0-8 adımlı standart tersine mühendislik iş akışı (`list_instances` -> `connect_instance` -> `load_tool_group` -> `import_file` -> ... -> `decompile_function`) eklendi.
- [x] **Veri Optimizasyonu:** `MCPLangChainToolkit`'e `output_guardrail` callback mekanizması eklendi. Araç çıktısı `max_tool_output_chars` (varsayılan 8000) eşiğini aştığında `FunctionSummarizer.summarize_chunk()` ile akıllı sıkıştırma yapılıyor; summarizer devre dışıysa basit karakter kesme uygulanıyor. Guardrail hata durumunda graceful degradation ile truncation'a düşüyor.

---

### [x] TODO-G: Uçtan Uca (E2E) ReAct Pipeline & Orkestrasyon

**Durum:** TAMAMLANDI
**Etki:** Kritik

- [x] **`scripts/run_analysis.py` Oluşturulması:** Dosya yolu (`.exe`, `.dll`) veya hash kabul eden bağımsız pipeline script'i yazıldı. `argparse` ile `--provider`, `--max-iterations`, `--mock`, `--output`, `--report` parametreleri destekleniyor. SHA-256 otomatik hesaplanıp `data/samples/` altına import ediliyor.
- [x] **Araç Kullanım Döngüsü Testi:** `tests/integration/test_react_tool_routing.py` — 8 mock-only test (tool binding, routing mechanism, message extraction) + 3 opsiyonel live Gemini API testi. Mock Ghidra (`decompile_function`, `list_functions`) ve CAPEv2 (`get_task_report`) araç simülasyonları ile `create_react_agent` dispatch mekanizması doğrulandı.
- [x] **Rapor Çıktısı:** `cli.py` üzerinden STIX 2.1 JSON (`--output`) ve Markdown raporu (`--report`) disk üzerine yazılıyor.
- [x] **Bug Fix:** `base_agent.py` içerisindeki kırık `from langchain.agents import create_react_agent` importu `from langgraph.prebuilt import create_react_agent` olarak düzeltildi.

---

## Orta/Uzun Vadeli Görevler (Master Plan'a Dönüş)

Araç kullanımı TODO-G ile kanıtlandıktan sonra ajanların karar alma süreçlerinin doğruluğunu artırmak için aşağıdaki maddeler ele alınacaktır.

### [x] TODO-H: Phase 1 — Anti-Echo-Chamber Engine (Sycophancy Detector)

**Durum:** TAMAMLANDI
**Etki:** Kritik

- [x] **Structured ISR:** Ajanlar ham metin yerine `ClaimEvidence` ve `dissent_items` içeren `AgentISR` JSON şemasıyla haberleşiyor (`isr_models.py`).
- [x] **Forced Dissent Protocol:** Her revizyon turunda `DEVIL_ADVOCATE_DIRECTIVE` ile ajanlar en az 1 `dissent_item` belirtmeye zorlanıyor (`sycophancy_detector.py`).
- [x] **Cosine Similarity Denetleyicisi:** Raporlar bag-of-words cosine similarity ile karşılaştırılıyor; eşik (%90) aşılırsa devil's advocate promptu inject ediliyor (`sycophancy_detector.py::detect_sycophancy`).

---

### [x] TODO-I: Phase 2 — Adaptive Termination (Rolling Std Convergence)

**Durum:** TAMAMLANDI
**Not:** Orijinal planda K-S testi öngörülmüştü; SELENE (arXiv) tabanlı rolling std yaklaşımı ile implement edildi — bağımlılıksız ve 3–5 turda %50 token tasarrufu sağlıyor.
**Etki:** Yüksek

- [x] **Rolling Std Convergence:** `routing.py::ConsensusRouter` — son 3 turun confidence std'si `< 0.04` VE mean `>= 0.70` ise müzakere erken sonlandırılıyor (`is_confidence_stable()`).

---

### [x] TODO-J: Phase 5 — Long-Term Memory / RAG (Qdrant & STIX Store)

**Durum:** TAMAMLANDI
**Etki:** Yüksek

- [x] **Qdrant Entegrasyonu:** `memory/qdrant_store.py` implement edildi; her STIX bundle `build_stored_case()` ile vektör veritabanına kaydediliyor (`nodes.py`).
- [x] **Retrieve & Augment:** `judge_agent.py::_build_memory_context()` — yeni analiz için benzer geçmiş STIX case'leri çekilerek judge promptuna few-shot context olarak ekleniyor.

---

## Genel Geliştirme Standartları

Her görev tesliminde sağlanması zorunlu kontroller:

```
Kod kalitesi:
  [ ] mypy --strict src/ → sıfır hata
  [ ] ruff check src/ tests/ → sıfır uyarı
  [ ] ruff format src/ tests/ → temiz format

Testler:
  [ ] Yeni modül için min. 10 unit test yazıldı
  [ ] Mevcut testlerin hiçbiri kırılmadı
  [ ] make check → tamamen yeşil

Dokümantasyon:
  [ ] Yeni modülün docstring'i: amaç, tasarım kararları, kullanım örneği
  [ ] docs/ARCHITECTURE.md güncellendi (yeni katman/bileşen varsa)
  [ ] README.md Key Capabilities tablosu güncellendi
  [ ] .env.example güncellendi (yeni config varsa)
  [ ] docs/TODO.md bu madde tamamlandı olarak işaretlendi

Mimari bütünlük:
  [ ] Yeni sınıf mevcut Protocol'lere uyuyor
  [ ] ServiceContainer üzerinden erişiliyor
  [ ] Settings üzerinden konfigüre ediliyor (.env uyumlu)
  [ ] Graceful degradation: devre dışıysa pipeline kesintisiz çalışıyor
```

---

## Tamamlanmış Görev Arşivi

*(Referans amaçlı — teknik tasarım detayları korunmuştur)*

---

### [x] TODO-A: YARA Kural Seti Genişletmesi

**Sonuç:** MITRE ATT&CK verileri parse edilerek 300+ yeni YARA kuralı otomatik oluşturuldu. 200+ teknik kapsandı.

---

### [x] TODO-B: Sigma Layer 0 (pySigma + SigmaHQ Entegrasyonu)

**Sonuç:** 2,946 SigmaHQ kuralı entegre edildi. TTP Cascade mimarisine `sigma` domain'i eklendi.

---

### [x] TODO-C: Hatching Triage Sandbox Client

**Sonuç:** Triage API'sine uygun `TriageClient` yazıldı; CAPEv2 uyumlu veri normalizasyonu sağlandı.

#### Teknik Tasarım

**`TriageClient` (`src/maljan/loaders/triage_client.py`)**

```python
class TriageClient:
    def __init__(
        self,
        api_token: str,
        base_url: str = "https://api.tria.ge",
        timeout: int = 30,
    ) -> None: ...

    def submit(self, sample_path: str | Path) -> str:
        """POST /v0/samples — multipart/form-data. Returns sample_id."""

    def wait_for_completion(
        self,
        task_id: str,
        timeout_seconds: int = 300,
        poll_interval_seconds: int = 15,
    ) -> str:
        """GET /v0/samples/{id}/summary — polls until status in terminal set."""

    def fetch_report(self, task_id: str) -> SubmissionResult:
        """GET /v0/samples/{id}/reports/triage — full JSON.
        Normalizes Triage schema to CAPEv2-compatible SubmissionResult.report.
        """

    def _normalize_report(self, triage_json: dict) -> dict:
        """Internal: maps Triage response fields to fixture-compatible schema."""

    def close(self) -> None: ...
    def __enter__(self) -> TriageClient: ...
    def __exit__(self, *args: object) -> None: ...
```

**`Settings` güncellemesi**

```python
class SandboxSettings(BaseModel):
    backend: Literal["mock", "cape2", "triage"] = "mock"
    # Mevcut CAPEv2 ayarları korunur
    # Yeni Triage ayarları:
    triage_api_token: str = ""
    triage_base_url: str = "https://api.tria.ge"
    triage_timeout_seconds: int = 300
    triage_poll_interval_seconds: int = 15
```

**`ServiceContainer` güncellemesi**

```python
def get_sandbox_client(self) -> SandboxClient:
    backend = self._settings.sandbox.backend
    if backend == "mock":
        return MockSandboxClient(...)
    elif backend == "cape2":
        return CAPEv2Client(...)
    elif backend == "triage":
        return TriageClient(
            api_token=self._settings.sandbox.triage_api_token,
            base_url=self._settings.sandbox.triage_base_url,
            timeout=self._settings.sandbox.triage_timeout_seconds,
        )
    raise ValueError(f"Unknown sandbox backend: {backend!r}")
```

**`.env.example` güncellemesi**

```ini
# Hatching Triage sandbox (free tier — no self-hosting required)
# SANDBOX__BACKEND=triage
# SANDBOX__TRIAGE_API_TOKEN=your_triage_api_token
# SANDBOX__TRIAGE_BASE_URL=https://api.tria.ge
# SANDBOX__TRIAGE_TIMEOUT_SECONDS=300
# SANDBOX__TRIAGE_POLL_INTERVAL_SECONDS=15
```

**Test gereksinimleri (minimum 15)**

- `submit()`: POST /v0/samples → sample_id dönüyor
- `wait_for_completion()`: polling döngüsü doğru çalışıyor
- `wait_for_completion()`: timeout → `SandboxTimeoutError`
- `fetch_report()`: tam response → normalize edilmiş `SubmissionResult`
- `_normalize_report()`: Triage alanları CAPEv2 uyumlu şemaya dönüşüyor
- `SandboxClient` Protocol uyumu: `isinstance(client, SandboxClient)` → True
- `ServiceContainer.get_sandbox_client()`: `backend="triage"` → `TriageClient`
- Koşullu live test (`SANDBOX__TRIAGE_API_TOKEN` ortam değişkeni yoksa atlanır)

---

### [x] TODO-D: FunctionSummarizer

**Sonuç:** `FunctionSummarizer` opsiyonel pre-summarizer olarak implement edildi. `Settings.preprocessing.use_function_summarizer` ile etkinleştirilir. Varsayılan: devre dışı.

#### Teknik Tasarım

**`FunctionSummarizer` (`src/maljan/analysis/function_summarizer.py`)**

```python
class FunctionSummarizer:
    """Lightweight pre-summarizer for binary analysis chunks.

    Opsiyonel — varsayılan olarak devre dışı. Etkinleştirildiğinde her chunk,
    ana analyst LLM'e geçirilmeden önce küçük bir model tarafından özetlenir.
    BinaryChunker çıktısı ile BaseAnalyst.analyze_isr() arasına yerleştirilir.
    """

    def __init__(self, llm: BaseChatModel, max_summary_words: int = 150) -> None: ...

    def summarize(self, chunk: TextChunk) -> str:
        """Tek bir chunk'ı özetler. Prompt: key API calls, suspicious strings,
        imports, behavioral indicators. Yalnızca olgular — yorum yok.
        """

    def summarize_batch(self, chunks: list[TextChunk]) -> list[str]:
        """Birden fazla chunk'ı özetler. Giriş sırasıyla döner."""
```

**`Settings` güncellemesi**

```python
class PreprocessingSettings(BaseModel):
    use_function_summarizer: bool = False
    summarizer_provider: str = "ollama"
    summarizer_model: str = "llama3.2:3b"
    summarizer_max_words: int = 150
```

**`ServiceContainer` güncellemesi**

```python
def get_function_summarizer(self) -> FunctionSummarizer | None:
    if not self._settings.preprocessing.use_function_summarizer:
        return None
    llm = self._build_llm(
        provider=self._settings.preprocessing.summarizer_provider,
        model=self._settings.preprocessing.summarizer_model,
    )
    return FunctionSummarizer(
        llm=llm,
        max_summary_words=self._settings.preprocessing.summarizer_max_words,
    )
```

**Pipeline entegrasyonu (`pipeline/nodes.py`)**

`BaseAnalyst` değiştirilmez. Node factory'de opsiyonel olarak devreye girer:

```python
summarizer = container.get_function_summarizer()
if summarizer and len(chunks) > 1:
    chunk_summaries = summarizer.summarize_batch(chunks)
    # chunk_summaries → TextChunk listesi yerine geçer
```

**Test gereksinimleri (minimum 8)**

- `summarize()` doğru prompt üretiyor
- `summarize_batch()` boş liste ve tek elemanlı liste
- `get_function_summarizer()`: `use_function_summarizer=False` → None
- `get_function_summarizer()`: `use_function_summarizer=True` → FunctionSummarizer
- `.env.example` yeni config değişkenlerini içeriyor
