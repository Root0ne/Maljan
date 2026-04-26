# Maljan — TODO (Revize Edilmiş)

Bu belge, master plan ile gerçek implementasyon karşılaştırılarak hazırlanmıştır.
Her madde tam teknik tasarım, mimari kararlar ve test gereksinimleriyle birlikte tanımlanmıştır.

---

## Öncelik Sırası

| # | Görev | Öncelik | Tahmini Efor |
|---|---|---|---|
| TODO-A | YARA kural seti genişletmesi (MITRE verisi uyarlaması) | **Kritik** | 1 gün |
| TODO-B | Sigma Layer 0 (log tabanlı deterministik TTP tespiti) | **Yüksek** | 2-3 gün |
| TODO-C | Hatching Triage sandbox client | **Orta** | 1-2 gün |
| TODO-D | FunctionSummarizer (iki aşamalı chunk pipeline) | **Düşük** | 1 gün |

---

## TODO-A: YARA Kural Seti Genişletmesi

**Durum:** YAPILACAK
**Etki:** Kritik — mevcut 40 kural, 691 aktif ATT&CK tekniğinin yalnızca ~%4'ünü kapsıyor.

### Sorun

`data/yara_ttp_rules.yaml` elle yazılmış 40 kuralla geldi. Bu, Layer 0'ın deterministik
gücünü büyük ölçüde kısıtlıyor. Depoda zaten mevcut olan MITRE verisi (`data/attck_labeled_sentences.jsonl`,
6MB, `data/attck_valid_ids.json`) doğrudan bu kural setine uyarlanabilir.

### Yapılacaklar

#### A.1 — Script: `scripts/expand_yara_rules.py`

Mevcut MITRE verilerini okuyarak `data/yara_ttp_rules.yaml` dosyasını otomatik genişletir.
Elle yazılmış kurallar **korunur**; script yalnızca eksik teknikler için yeni kurallar ekler.

**Veri kaynakları (öncelik sırasıyla):**

1. `data/attck_labeled_sentences.jsonl` — `layer: "relationship_description"` satırları:
   MITRE'nin "bu malware bu tekniği ŞU ŞEKİLDE kullanır" cümleleri. En sık geçen token'lar
   pattern olarak çıkartılır.

2. `x_mitre_detection` alanları (cached STIX bundle'dan): Her tekniğin tespit ipuçları;
   API adları, araç isimleri, event ID'leri içerir.

3. `x_mitre_platforms` filtresi: Yalnızca `"Windows"` veya `"Linux"` platformlu teknikler.
   Cloud/SaaS odaklı teknikler (T1578, T1530 vb.) hariç tutulur.

**Pattern çıkartma kuralları:**

- Minimum 2, maksimum 8 pattern/teknik.
- Windows API adı (büyük harf başlangıcı, parantez içermeyen) → confidence 0.88
- Bilinen araç adı (mimikatz, certutil, mshta vb.) → confidence 0.85
- Genel terim → confidence 0.75
- 3 karakterden kısa token → atlanır.
- Jenerik çok-teknikli pattern'lar yalnızca en spesifik tekniğe eklenir.

**Kural ID formatı:** `{tactic_slug}_{technique_normalized}_{seq}`
Örnek: `defense_evasion_t1055_001_0`

**Kapsam hedefi:**

| Metrik | Mevcut | Hedef |
|---|---|---|
| Toplam kural sayısı | 40 | 300+ |
| Kapsanan ATT&CK teknik ID | ~25 | 200+ |
| Kapsanan taktik | 8 | Tüm Enterprise taktikler |

#### A.2 — Kural dosyası formatı güncellemesi

```yaml
version: "2.0"
description: "Maljan YARA-TTP rule set — hand-crafted + MITRE ATT&CK derived."
generated_at: "2026-04-26"
sources:
  - "hand-crafted (baseline)"
  - "mitre-attack/attack-stix-data (ATT&CK Enterprise)"
rules:
  # hand-crafted rules (preserved verbatim)
  ...
  # MITRE-derived rules (auto-generated, do not edit manually)
  ...
```

`YaraLayer` hiç değiştirilmez — format uyumlu.

#### A.3 — Makefile

```makefile
expand-yara:  ## Expand YARA rule set from local MITRE ATT&CK data
    uv run python scripts/expand_yara_rules.py \
        --attck-cache ~/.cache/maljan/attck/ \
        --sentences data/attck_labeled_sentences.jsonl \
        --output data/yara_ttp_rules.yaml \
        --preserve-handcrafted
```

#### A.4 — Testler

- `tests/unit/analysis/test_yara_layer.py`: genişletilmiş kural setiyle
  `from_default_rules()` başarılı, ≥200 teknik kapsamı doğrulanır.
- `tests/unit/scripts/test_expand_yara_rules.py`: script deterministik çıktı üretiyor,
  elle yazılmış kurallar korunuyor.
- Mevcut 27 test değiştirilmez.

---

## TODO-B: Sigma Layer 0

**Durum:** YAPILACAK
**Etki:** Yüksek — log tabanlı saldırı kalıpları şu anda LLM'e havale ediliyor.

### Sorun

YARA binary içeriğine ve analiz metnine bakar. Sigma **log satırlarına** bakar —
Windows Event Log, Sysmon, Zeek. İki kaynak birbirini tamamlar; biri olmadan
diğeri kör kalan bir alan bırakır.

### Teknik Tasarım

Bağımlılık: `uv add pySigma` (Python 3.11+ uyumlu, aktif bakımlı, programatik API).

#### B.1 — Veri modelleri (`src/maljan/analysis/sigma_layer.py`)

```python
@dataclass(frozen=True)
class SigmaMatch:
    rule_id: str
    rule_title: str
    technique_id: str
    confidence: float          # [0.70, 1.0]
    log_source: str            # "windows_security" | "sysmon" | "zeek" | "generic"
    matched_log_indices: list[int]
    matched_fields: dict[str, str]

    @property
    def evidence_ref(self) -> str: ...
    @property
    def claim_text(self) -> str: ...
```

#### B.2 — `SigmaLayer` sınıfı

```python
class SigmaLayer:
    @classmethod
    def from_rules_dir(cls, rules_dir: Path) -> SigmaLayer: ...
    @classmethod
    def from_default_rules(cls) -> SigmaLayer: ...

    def scan_log_lines(
        self,
        log_lines: list[str],
        log_source: str = "generic",
    ) -> list[SigmaMatch]: ...

    def scan_report_text(self, report_text: str) -> list[SigmaMatch]: ...
    def to_isr(self, matches: list[SigmaMatch]) -> AgentISR: ...

    @property
    def rule_count(self) -> int: ...
    def techniques_covered(self) -> set[str]: ...
```

#### B.3 — Kural seti yapısı: `data/sigma_rules/`

```
data/sigma_rules/
├── windows/
│   ├── process_creation/    # Sysmon Event ID 1 / Security 4688
│   ├── registry/            # Sysmon Event ID 12/13/14
│   ├── network/             # Sysmon Event ID 3
│   └── file_event/          # Sysmon Event ID 11
├── network/
│   ├── zeek/
│   └── suricata/
└── generic/
```

Kaynak: SigmaHQ/sigma reposundan yalnızca `tags: attack.tXXXX` alanı olan kurallar.
Minimum 50 kural teslim edilir.

#### B.4 — `TTPCascadeEngine` güncellemesi

```python
LAYER_WEIGHTS: dict[str, float] = {
    "yara":    0.90,
    "sigma":   0.55,   # yeni — deterministik ama log kalitesine bağlı
    "dynamic": 0.45,
    "static":  0.35,
    "network": 0.20,
}

CROSS_LAYER_MULTIPLIERS: dict[int, float] = {
    1: 1.00,
    2: 1.25,
    3: 1.50,
    4: 1.75,
    5: 1.90,   # YARA + Sigma + tüm LLM domainleri
}
```

`AgentISR.domain` Literal'ine `"sigma"` eklenir (`isr_models.py`).

#### B.5 — `ServiceContainer` ve `Settings`

```python
class AnalysisSettings(BaseModel):
    sigma_rules_dir: Path = Path("data/sigma_rules")

# container.py
def get_sigma_layer(self) -> SigmaLayer:
    """SigmaLayer singleton — graceful degradation if rules dir absent."""
```

#### B.6 — Pipeline entegrasyonu (`pipeline/nodes.py`)

YARA çalıştıktan hemen sonra, cascade başlamadan önce:

```python
sigma_layer = container.get_sigma_layer()
if sigma_layer.rule_count > 0:
    log_lines = _extract_log_lines(state)
    sigma_matches = sigma_layer.scan_log_lines(log_lines)
    sigma_matches += sigma_layer.scan_report_text(combined_report_text)
    if sigma_matches:
        isr_reports["sigma_layer"] = sigma_layer.to_isr(sigma_matches)
```

#### B.7 — Testler (minimum 20)

- `from_default_rules()` başarılı yükleme ve boş yükleme (kural dizini yoksa)
- `scan_log_lines()`: sahte LSASS erişim logu → T1003.001
- `scan_log_lines()`: sahte Mimikatz process creation → T1003
- `scan_report_text()`: Sysmon kayıtlı metni parse edip eşleşiyor
- `to_isr()`: domain="sigma", doğru confidence, doğru technique_id
- Eşleşme yoksa boş liste döner, pipeline devam eder
- `TTPCascadeEngine`: sigma domain'li ISR doğru ağırlık alıyor
- `ServiceContainer.get_sigma_layer()`: singleton semantiği

#### B.8 — Makefile

```makefile
download-sigma-rules:  ## Download baseline Sigma rules from SigmaHQ (ATT&CK tagged only)
    uv run python scripts/download_sigma_rules.py \
        --output data/sigma_rules/ \
        --filter-tagged
```

---

## TODO-C: Hatching Triage Sandbox Client

**Durum:** YAPILACAK
**Etki:** Orta — CAPEv2 self-hosted infrastructure gerektiriyor; Triage free tier API ile herhangi
bir makineden kullanılabilir.

### Teknik Tasarım

`httpx` zaten mevcut. Ek bağımlılık yok.
API: https://tria.ge/docs/ — base URL: `https://api.tria.ge/v0/`
Rate limit: free tier 50 istek/gün.

#### C.1 — `TriageClient` (`src/maljan/loaders/triage_client.py`)

`SandboxClient` Protocol'ünü tam uygular — `CAPEv2Client` ile değiştirilebilir.

```python
class TriageClient:
    """Hatching Triage REST API sandbox client.

    Implements SandboxClient Protocol. Identical SubmissionResult shape
    as CAPEv2Client — parsers require zero changes.
    """

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

`_normalize_report()` kritik: Triage şeması CAPEv2'den farklıdır.
Bu metod Triage JSON'unu `DynamicParser`/`NetworkParser`'ın beklediği şemaya dönüştürür.

#### C.2 — `Settings` güncellemesi

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

#### C.3 — `ServiceContainer` güncellemesi

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

#### C.4 — `.env.example` güncellemesi

```ini
# Hatching Triage sandbox (free tier — no self-hosting required)
# SANDBOX__BACKEND=triage
# SANDBOX__TRIAGE_API_TOKEN=your_triage_api_token
# SANDBOX__TRIAGE_BASE_URL=https://api.tria.ge
# SANDBOX__TRIAGE_TIMEOUT_SECONDS=300
# SANDBOX__TRIAGE_POLL_INTERVAL_SECONDS=15
```

#### C.5 — Testler (minimum 15)

`pytest-httpx` veya `respx` ile Triage API mock'ları:

- `submit()`: POST /v0/samples → sample_id dönüyor
- `wait_for_completion()`: polling döngüsü doğru çalışıyor
- `wait_for_completion()`: timeout → `SandboxTimeoutError`
- `fetch_report()`: tam response → normalize edilmiş `SubmissionResult`
- `_normalize_report()`: Triage alanları CAPEv2 uyumlu şemaya dönüşüyor
- `SandboxClient` Protocol uyumu: `isinstance(client, SandboxClient)` → True
- `ServiceContainer.get_sandbox_client()`: `backend="triage"` → `TriageClient`
- Koşullu live test:
  ```python
  @pytest.mark.skipif(
      not os.environ.get("SANDBOX__TRIAGE_API_TOKEN"),
      reason="Triage API token not configured",
  )
  def test_triage_live_submit_and_report(): ...
  ```

---

## TODO-D: FunctionSummarizer

**Durum:** YAPILACAK
**Etki:** Düşük (işlevsel doğruluk değil, token maliyet optimizasyonu).

### Sorun

`safe_analyze_isr_chunked()` her chunk için doğrudan ana LLM'i çağırıyor.
Master plan "önce küçük model özetle → büyük model analiz et" iki aşamalı pipeline
tarif ediyordu. Büyük binary'lerde gereksiz token maliyeti oluşuyor.

### Teknik Tasarım

#### D.1 — `FunctionSummarizer` (`src/maljan/analysis/function_summarizer.py`)

```python
class FunctionSummarizer:
    """Lightweight pre-summarizer for binary analysis chunks.

    Optional — disabled by default. When enabled, each chunk is summarized
    by a small model before being passed to the main analyst LLM.
    Inserted between BinaryChunker output and BaseAnalyst.analyze_isr().
    """

    def __init__(self, llm: BaseChatModel, max_summary_words: int = 150) -> None: ...

    def summarize(self, chunk: TextChunk) -> str:
        """Summarize a single chunk. Max max_summary_words words.
        Prompt: extract key API calls, suspicious strings, imports, behavioral
        indicators. Facts only — no interpretation.
        """

    def summarize_batch(self, chunks: list[TextChunk]) -> list[str]:
        """Summarize multiple chunks. Returns summaries in input order."""
```

#### D.2 — `Settings` güncellemesi

```python
class PreprocessingSettings(BaseModel):
    use_function_summarizer: bool = False
    summarizer_provider: str = "ollama"
    summarizer_model: str = "llama3.2:3b"
    summarizer_max_words: int = 150
```

#### D.3 — `ServiceContainer` güncellemesi

```python
def get_function_summarizer(self) -> FunctionSummarizer | None:
    if not self._settings.preprocessing.use_function_summarizer:
        return None
    llm = self._build_llm(
        provider=self._settings.preprocessing.summarizer_provider,
        model=self._settings.preprocessing.summarizer_model,
    )
    return FunctionSummarizer(llm=llm, max_summary_words=self._settings.preprocessing.summarizer_max_words)
```

#### D.4 — Pipeline entegrasyonu (`pipeline/nodes.py`)

`BaseAnalyst` değiştirilmez. Node factory'de opsiyonel olarak devreye girer:

```python
summarizer = container.get_function_summarizer()
if summarizer and len(chunks) > 1:
    chunk_summaries = summarizer.summarize_batch(chunks)
    # chunk_summaries -> TextChunk listesi yerine geçer
```

#### D.5 — Testler (minimum 8)

- `summarize()` doğru prompt üretiyor
- `summarize_batch()` boş liste ve tek elemanlı liste
- `get_function_summarizer()`: `use_function_summarizer=False` → None
- `get_function_summarizer()`: `use_function_summarizer=True` → FunctionSummarizer
- `.env.example` yeni config değişkenlerini içeriyor

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
