# Maljan — TODO

Aşağıdaki liste, master plan ile gerçek implementasyon karşılaştırılarak
hazırlanmıştır. Her madde için "neden eksik mi, yoksa bilinçli mi sapıldı"
sorusu cevaplanmıştır.

---

## Sonuç: 5 Gerçek Eksik, 3 Bilinçli Sapma

### Bilinçli Sapmalar (TODO değil, bunlar kasıtlı tasarım kararları)

Bu maddeler master plan'da farklı bir implementasyon tarif ediyordu,
ancak gerçek implementasyon daha iyidir. Yapılması gereken bir şey yoktur.

| Plan | Uygulanan | Neden Daha İyi |
|---|---|---|
| `scipy` K-S test ile adaptive termination | Pure-Python rolling std (`routing.py:36-43`) | Bağımlılık yok; 3-5 round pencere için yeterli |
| `sentence-transformers` cosine similarity | Pure BoW cosine (`sycophancy_detector.py:38-51`) | Import-time bağımlılık sıfır; 150ms → <1ms |
| `stix2` kütüphanesi ile STIX üretimi | Pydantic v2 custom models (`schemas/stix_models.py`) | mypy strict uyumlu; stix2'nin validation kısıtlamalarından bağımsız |

### Gerçek Eksikler (UYGULANMADI)

Bu maddeler master plan'da açıkça tanımlanmış, kod tabanında hiç yoktur
ve işlevsel olarak başka bir şey tarafından karşılanmamaktadır.

---

## TODO-1: Phase 4 — TTP Cascade'e Deterministik Layer 1 (YARA/Sigma) Eklenmesi

### Sorun

Master plan Phase 4'te şu üç katmanlı yapıyı tarif eder:

```
Layer 1: CAPE YARA signatures + Sigma rules  (deterministic, zero hallucination)
Layer 2: TIEF/DistilBERT classifier          (high-precision NLP, F1=0.933)
Layer 3: Judge agent LLM                     (contextual reasoning, STIX)
```

Mevcut `TTPCascadeEngine` (`src/maljan/analysis/ttp_cascade.py`) sadece
**Layer 3**'e karşılık gelen çapraz-domain corroboration yapıyor. Layer 1
ve Layer 2 tamamen yoktur.

**Gerçek etki:** YARA/Sigma olmadan pipeline, bilinen imza-eşleme
tekniklerini de LLM'e havale ediyor. Bu hem daha yavaş hem de halüsinasyon
riski taşıyor. Deterministik Layer 1, `technique_id` için sıfır
halüsinasyon garantisi verebilir.

### Yapılacaklar

#### 1.1 — YARA Katmanı (`src/maljan/analysis/yara_layer.py`)

```
Bağımlılık: uv add yara-python
```

- `YARALayer` sınıfı: `run(sample_bytes: bytes) -> list[YARAMatch]` metodu
- `YARAMatch(rule_name, technique_id, confidence, meta)` dataclass
- Kural seti: `data/yara_rules/` dizinine koyulacak
  - Her `.yar` dosyasının `meta` bloğu `mitre_attack_id = "T1055"` içermelidir
  - Başlangıç için YARA-Forge veya community kuralları kullanılabilir:
    https://github.com/YARAHQ/yara-forge
- `attck_id` eksik kural varsa uyarı log'u verilmeli; atlanmalı
- `TTPCascadeEngine.compute()` imzasına `yara_matches: list[YARAMatch] | None = None`
  parametresi eklenmeli
- YARA eşleşmesi olan teknikler için `domain="yara"`, `cross_layer_multiplier`
  hesabında diğer domainlerle aynı formül uygulanmalı
- Güven skoru: YARA eşleşmeleri için sabit `0.95` kullanılmalı

#### 1.2 — Sigma Katmanı (`src/maljan/analysis/sigma_layer.py`)

```
Bağımlılık: uv add sigma-cli (veya pySigma)
```

- `SigmaLayer` sınıfı: `run(log_lines: list[str]) -> list[SigmaMatch]` metodu
- `SigmaMatch(rule_id, rule_title, technique_id, log_index)` dataclass
- Kural seti: `data/sigma_rules/`
  - Varsayılan kural dizini config'den okunmalı (`Settings.sigma_rules_dir`)
- Sigma kuralları Evtx/syslog satırlarına uygulanacak; network logları için
  ayrı bir filtre kümesi olmalı
- `TTPCascadeEngine.compute()` imzasına `sigma_matches: list[SigmaMatch] | None = None`
  parametresi eklenmeli

#### 1.3 — TTPCascadeEngine refactor

- `compute()` metodu hem YARA hem Sigma hem de ISR kaynaklı `technique_id`'leri
  aynı `LayerContribution` mantığı altında birleştirmeli:
  - `domain="yara"`, `domain="sigma"` olarak listeye girmelidir
  - YARA/Sigma'dan gelen teknikler `LAYER_WEIGHTS` sözlüğüne dahil edilmelidir
    (önerilen: `yara=0.55`, `sigma=0.50` — LLM'den daha güvenilir)
- `ServiceContainer.get_yara_layer()` ve `get_sigma_layer()` fabrika metodları eklenmelidir
- Sandbox client'tan alınan ham byte'lar (CAPEv2 `sample_bytes`) YARA katmanına iletilmelidir

#### 1.4 — Test

- `tests/unit/test_yara_layer.py`: sahte kural + sahte byte eşleşmesi
- `tests/unit/test_sigma_layer.py`: sahte log satırları + kural eşleşmesi
- `tests/unit/test_ttp_cascade.py`'ye YARA/Sigma girdili cascade testi eklenmeli
- `tests/evaluation/fixtures/` içindeki fixture'lara `yara_rule_ids` alanı eklenebilir

---

## TODO-2: Phase 3 — Chunk Başına Lightweight Özetleyici (`function_summarizer.py`)

### Sorun

Master plan Phase 3'te şunu tarif eder:

```
src/maljan/preprocessors/
├── binary_chunker.py     # Ghidra output'unu fonksiyon bazında böl
├── function_summarizer.py # Her chunk için lightweight model (CodeLLaMA 13B)
└── cfg_orderer.py         # CFG pozisyonuna göre sırala
```

Gerçek implementasyon:
- `BinaryChunker` var (loaders'da, preprocessors'da değil) ✅
- `merge_summaries()` metodu var ✅
- `safe_analyze_isr_chunked()` her chunk'ı doğrudan ana LLM ile analiz ediyor ✅
- **Eksik:** Her chunk için önce lightweight model (CodeLLaMA/small Ollama)
  özetleyip sonra ana LLM'e özet vermek

### Gerçekten Eksik Mi?

**Kısmen eksik.** `safe_analyze_isr_chunked()`, her chunk için ana LLM (GPT-4o
vb.) çağırıyor. Bu token maliyetli. Master plan'ın önerdiği "önce küçük model,
sonra büyük model" iki aşamalı pipeline implementasyonda yok.

Ancak mevcut yöntem işlevsel olarak doğru sonuç üretiyor — sadece daha pahalı.

### Yapılacaklar

#### 2.1 — `src/maljan/analysis/function_summarizer.py`

- `FunctionSummarizer` sınıfı:
  - `summarize(chunk: TextChunk, llm: BaseChatModel) -> str` metodu
  - Prompt: "Summarize the following decompiled function/API sequence for
    malware analysis. Extract: key API calls, suspicious strings, imports.
    Be concise (max 150 words)."
  - Her chunk için ayrı LLM çağrısı (küçük model — Ollama llama3.2:3b önerilir)
- `FunctionSummarizer` opsiyonel: `Settings` altına `preprocessing.use_summarizer: bool`
  ve `preprocessing.summarizer_model: str` eklenmelidir
- Mevcut `safe_analyze_isr_chunked()` değiştirilmemelidir — `FunctionSummarizer`
  agent katmanında devreye girecektir

#### 2.2 — `src/maljan/analysis/cfg_orderer.py`

**Bu gerçekten eksik mi?**

Hayır. `BinaryChunker._split_by_boundary()` zaten Ghidra fonksiyon başlıklarına
göre (`_STATIC_BOUNDARY_RE`) böldüğü için CFG sıralaması zaten korunuyor.
Ek bir `cfg_orderer.py` gereksiz. **Bu madde yapılmayacak.**

#### 2.3 — `src/maljan/preprocessors/` dizini (yeniden yapılandırma)

Master plan'da `preprocessors/` dizininden bahsediliyorsa da implementasyon
doğrudan `loaders/` altına yerleştirildi. `BinaryChunker`'ı taşımak
breaking change olurdu. Yapılacak:
- `src/maljan/preprocessors/__init__.py` oluşturulacak
- `FunctionSummarizer` buraya taşınacak (chunker taşınmayacak)

---

## TODO-3: Phase 6 — Hatching Triage Sandbox Entegrasyonu (`triage_client.py`)

### Sorun

Master plan Phase 6'da şunu yazar:

> "Hatching Triage önce (free tier, hızlı, 5 dk analiz), CAPEv2 production'da"

Gerçek implementasyon:
- `CAPEv2Client` var ✅
- `MockSandboxClient` var ✅
- `SandboxClientProtocol` var ✅
- **Eksik:** `TriageClient` (Hatching Triage REST API)

### Gerçekten Eksik Mi?

**Evet, eksik.** CAPEv2 self-hosted infrastructure gerektiriyor (Docker, 16GB+ RAM).
Hatching Triage'ın free tier'ı public sample analizi için API anahtarıyla
kullanılabiliyor. Farklı bir kullanım senaryosunu kapsıyor.

### Yapılacaklar

#### 3.1 — `src/maljan/loaders/triage_client.py`

```
Bağımlılık: httpx zaten var
API dokümantasyonu: https://tria.ge/docs/
```

- `TriageClient(SandboxClientProtocol)` sınıfı:
  - `submit_sample(sample_bytes, filename) -> str` (task_id döner)
  - `get_report(task_id) -> SandboxReport` (polling ile)
  - `is_available() -> bool` (API key var mı kontrol)
- Endpoint: `https://api.tria.ge/v0/`
- Auth header: `Authorization: Bearer {TRIAGE_API_TOKEN}`
- Rate limit: Free tier 50 req/day — `httpx.AsyncClient` yerine sync kullanılacak
- `SandboxReport` modeli her iki client için de aynı olacak (zaten öyle)
- `Settings.sandbox.backend` listesine `"triage"` eklenmeli
- `ServiceContainer.get_sandbox_client()` factory metoduna `triage` dalı eklenecek

#### 3.2 — `.env.example`

```ini
# SANDBOX__BACKEND=triage
# SANDBOX__TRIAGE_API_TOKEN=your_triage_api_token
# SANDBOX__TRIAGE_BASE_URL=https://api.tria.ge  # veya on-prem için custom URL
```

#### 3.3 — Test

- `tests/unit/test_triage_client.py`: `httpx_mock` ile sahte Triage API yanıtları
- `tests/integration/test_triage_live.py`: `@pytest.mark.skipif` ile koşullu
  (sadece `SANDBOX__TRIAGE_API_TOKEN` set edilmişse çalışır)

---

## TODO-4: Phase 8.2 — aCTIon Dataset Entegrasyonu (Gerçek Benchmark)

### Sorun

Master plan Phase 8.2'de şunu tarif eder:

> "aCTIon dataset (204 STIX bundle, 36k entity, %93.1 F1 baseline)"
>
> `tests/evaluation/ground_truth/action_dataset/`

Gerçek implementasyon:
- 5 adet el yazımı sentetik fixture var
- 204 gerçek STIX bundle'ı yok
- Benchmark, sentetik "perfect precision" baseline üzerinde çalışıyor
  (TTP F1 = 1.0 — gerçek bir ölçüm değil)

### Gerçekten Eksik Mi?

**Evet, en kritik eksik bu.** Mevcut benchmark, pipeline'ın gerçek dünya
performansını ölçmüyor. aCTIon dataset olmadan "F1=1.0" rakamı anlamsız.

Dataset adresi: `https://github.com/aiforsec/action-dataset`
Paper: "CTI-BERT: A Cyber Threat Intelligence Extraction Model" (2024)

### Yapılacaklar

#### 4.1 — Dataset İndir ve Normalize Et

```bash
git clone https://github.com/aiforsec/action-dataset data/action_dataset/
```

- Her STIX bundle için `tests/evaluation/ground_truth/action/` altına
  `{bundle_id}.json` formatında ground truth fixture yaz
- Ground truth fixture şeması (mevcut `ransomware_sample_1.json` ile uyumlu):
  ```json
  {
    "sample_id": "action_bundle_001",
    "notes": "...",
    "technique_ids": ["T1055", ...],
    "attck_valid_ids": [...],
    "expected_stix_types": ["malware", "attack-pattern", "relationship"],
    "expected_rel_types": ["uses"]
  }
  ```
- Script: `scripts/prepare_action_dataset.py`
  - 204 STIX bundle parse eder
  - `attack-pattern` nesnelerden `technique_id` çıkarır
  - Ground truth fixture'ları üretir

#### 4.2 — `load_fixture_suite()` Güncelleme

`benchmark_suite.py:load_fixture_suite()` zaten glob ile çalışıyor.
`ground_truth/action/` dizini varsa otomatik yüklenecek:

```python
run_fixture_benchmark(fixtures_dir="tests/evaluation/ground_truth/action/")
```

#### 4.3 — Gerçek Pipeline Çıktıları ile Karşılaştırma

- Şu anki benchmark, sentetik "perfect TTP" output üretiyor
- aCTIon için: gerçek pipeline çalıştırılacak, `AnalysisState["run_summary"]`
  ve `AnalysisState["stix_output"]` kaydedilecek
- `from_run_summary()` bu gerçek çıktıları `BenchmarkRunner`'a besleyecek
- Hedef metrik: **TTP F1 >= 0.80** (aCTIon baseline F1=0.931)

#### 4.4 — CI Entegrasyonu

`ci.yml`'e yeni job eklenecek:
```yaml
action-benchmark:
  if: github.event_name == 'schedule'   # sadece gece çalışır
  steps:
    - run: uv run python scripts/run_action_benchmark.py
    - run: uv run python -m tests.evaluation.benchmark_suite
            --fixtures-dir tests/evaluation/ground_truth/action/
            --output benchmark_action_report.md
```

---

## TODO-5: Phase 4 — TIEF/DistilBERT Layer 2 (Opsiyonel, Araştırma)

### Sorun

Master plan Phase 4 Layer 2 için şunu tarif eder:

> "TIEF/DistilBERT classifier (high-precision NLP, F1=0.933)"

Bu, her bir metin parçasından deterministik olarak TTP sınıflandırması yapan
fine-tuned bir transformer modeli olacaktı.

### Gerçekten Eksik Mi?

**Evet ama opsiyonel.** `TTPCascadeEngine` olmadan da pipeline doğru çalışıyor.
TIEF/DistilBERT, LLM çağrısı yapılmadan NLP tabanlı TTP tespiti yapacaktı.
Bu katman, LLM'siz (air-gapped) deployment için kritik.

### Yapılacaklar

#### 5.1 — `src/maljan/analysis/ttp_classifier.py`

```
Bağımlılık: uv add transformers torch (veya onnxruntime için hafif versiyon)
Model: "CTI-BERT" (arXiv:2312.00957) veya "SecureBERT-NER" (HuggingFace)
```

- `TTPClassifier` sınıfı:
  - `classify(text: str) -> list[TTPPrediction]` metodu
  - `TTPPrediction(technique_id, score, evidence_span)` dataclass
  - Model `~/.cache/maljan/models/` altına indirilmeli (ilk çalıştırmada)
- Opsiyonellik: `Settings.ttp_classifier.enabled: bool = False`
  - `enabled=False` ise `TTPClassifier` yüklenmez (import yok)
  - `ServiceContainer.get_ttp_classifier()` `None` döner
- `TTPCascadeEngine.compute()` imzasına
  `classifier_predictions: list[TTPPrediction] | None = None` eklenmeli
  - `domain="distilbert"`, `weight=0.40`

#### 5.2 — ONNX Export (Production için)

- `scripts/export_ttp_classifier_onnx.py`
- PyTorch modeli ONNX'e çevrilir → `onnxruntime` ile çalışır (GPU gerekmez)
- Bu, malware analiz ortamlarında (internet erişimi olmayan) çalışabilir

#### 5.3 — Test

- `tests/unit/test_ttp_classifier.py`: mock transformer ile unit test
- `tests/integration/test_ttp_classifier_live.py`: gerçek model yüklü ise çalışır

---

## Öncelik Sırası

| # | Madde | Öncelik | Tahmini Efor |
|---|---|---|---|
| TODO-4 | aCTIon dataset entegrasyonu | **Kritik** | 1-2 gün |
| TODO-1 | YARA/Sigma Layer 1 | **Yüksek** | 3-5 gün |
| TODO-3 | Hatching Triage client | **Orta** | 1 gün |
| TODO-2 | FunctionSummarizer | **Düşük** | 1 gün |
| TODO-5 | DistilBERT Layer 2 | **Araştırma** | 1-2 hafta |

---

## Tamamlanan Maddeler (Referans)

- [x] Phase 0 — Stabilizasyon (paralel fan-out, registry, mypy/ruff)
- [x] Phase 1.1 — AgentISR / ClaimEvidence structured output
- [x] Phase 1.2 — Forced Dissent Protocol (dissent_items)
- [x] Phase 1.3 — Sycophancy Detector (cosine BoW)
- [x] Phase 2 — Adaptive Termination (rolling std, scipy-free)
- [x] Phase 3 — BinaryChunker (fonksiyon/API/flow boundary splitting)
- [x] Phase 3 — ChunkMerger (merge_chunk_isrs)
- [x] Phase 3 — safe_analyze_isr_chunked (agent katmanı)
- [x] Phase 4.2 — ATTCKIndex (lokal STIX cache, cosine search)
- [x] Phase 4.3 — ATTCKValidator (hallucination rate)
- [x] Phase 4 Layer 3 — TTPCascadeEngine (cross-domain corroboration)
- [x] Phase 5 — InMemoryStore (in-process RAG)
- [x] Phase 5 — QdrantStore (persistent vector DB)
- [x] Phase 5 — LongTermMemory (few-shot injection into JudgeAgent)
- [x] Phase 6 — MockSandboxClient (fixture-based testing)
- [x] Phase 6 — CAPEv2Client (live sandbox, httpx)
- [x] Phase 7.1 — SchemaPruner (dynamic STIX schema pruning)
- [x] Phase 7.2 — ConfidenceAnnotatedRelationship (per-claim intervals)
- [x] Phase 8.1 — LangSmith observability (ServiceContainer._configure_langsmith)
- [x] Phase 8.2 — BenchmarkRunner + BenchmarkSuite
- [x] Phase 8.2 — NegotiationMetrics / TTPAccuracyMetrics / STIXQualityMetrics
- [x] Phase 8.2 — 5 sentetik ground truth fixture
- [x] Phase 8.2 — `maljan benchmark` CLI komutu
- [x] CI/CD — mypy strict, ruff, pre-commit, pytest (661 test)
- [x] ARCHITECTURE.md — tam teknik referans (17 bölüm)
- [x] .gitignore — .env eklendi, httpx pyproject.toml'a eklendi
