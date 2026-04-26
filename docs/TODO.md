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

### YARA Katmanı: TAMAMLANDI

YARA kısmı implemente edildi (`src/maljan/analysis/yara_layer.py`, `data/yara_ttp_rules.yaml`).
Bakınız: aşağıdaki "Tamamlanan Maddeler" listesi.

### Sigma Katmanı: YAPILACAK

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

## TODO-4: Phase 8.2 — Empirical Ground Truth Dataset Entegrasyonu [TAMAMLANDI]

### Sorun (Orijinal)

Master plan Phase 8.2'de şunu tarif eder:

> "aCTIon dataset (204 STIX bundle, 36k entity, %93.1 F1 baseline)"

Gerçek implementasyon (orijinal durumda):
- 5 adet el yazımı sentetik fixture vardı
- 204 gerçek STIX bundle yoktu
- Benchmark, sentetik "perfect precision" baseline üzerinde çalışıyordu

### Uygulanan Çözüm: TRAM2 Dataset

**aCTIon repository'si artık erişilebilir durumda olmadığından**, eşdeğer veya
daha kapsamlı bir alternatif olarak **MITRE Center for Threat-Informed Defense
TRAM2 dataset** kullanıldı.

**TRAM2 Avantajları:**
- Apache-2.0 lisanslı, publicly available, aktif bakımlı
- 149 gerçek tehdit raporu (NotPetya, Lazarus, LockBit, Black Basta vb.)
- Her cümle ATT&CK tekniğine etiketlenmiş (`text` -> `T-ID` mapping)
- Dataset kaynağı: `center-for-threat-informed-defense/tram`

### Uygulanan Dosyalar

| Dosya | Açıklama |
|---|---|
| `scripts/prepare_tram_dataset.py` | TRAM2'yi indirir, doküman bazlı aggregate eder, fixture üretir |
| `tests/evaluation/ground_truth/tram/` | 140 adet gerçek rapor fixture'i (JSON) |
| `tests/evaluation/test_tram_ground_truth.py` | 10 pytest testi (şema, F1, hallucination doğrulama) |
| `Makefile` (`prepare-tram`, `benchmark-tram`) | Yeni make hedefleri |

### Sonuçlar

```
Fixtures : 140 tehdit raporu (NotPetya, Rorschach, LockBit, APT41 ...)
Teknikler: 50 unique ATT&CK teknik ID (dataset geneli attck_valid_ids baseline'i)
Testler  : 10/10 passed (pytest tests/evaluation/test_tram_ground_truth.py)
```

### Kullanım

```bash
# Fixture'ları yenile (internetten TRAM2 indirir)
make prepare-tram

# Sentetik mod (tam F1=1.0 baseline doğrulama)
make benchmark-tram

# Doğrudan çalıştırma
uv run python -m tests.evaluation.benchmark_suite \
    --fixtures-dir tests/evaluation/ground_truth/tram \
    --output benchmark_tram_report.md
```

### Kalan İş: Gerçek Pipeline Çıktıları ile Karşılaştırma

Mevcut benchmark sentetik "perfect TTP" output üzerinde çalışır (F1=1.0).
Gerçek LLM pipeline çıktısı ile karşılaştırma yapmak için:

1. Gerçek bir analiz çalıştır -> `AnalysisState["run_summary"]` + `stix_output` kaydet
2. `from_run_summary()` ile `BenchmarkRunner`'a besle
3. Hedef: **TTP F1 >= 0.75** (140 rapor üzerinden)

Bu adım TODO-1 (YARA Layer 1) tamamlandıktan sonra anlam kazanacak.

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

## TODO-6: ATT&CK Enterprise Catalog Entegrasyonu

**Durum: YAPILACAK**

### Sorun

Mevcut ground truth pipeline iki kritik zayıflık barındırıyor:

1. **`attck_valid_ids` evreni çok küçük.** TRAM2 dataset'inde rastlanan 50 ID
   kullanılıyor. ATT&CK Enterprise gerçekte ~700 aktif teknik içeriyor (teknikler +
   alt-teknikler, revoke edilmemişler). Hallucination rate hesabı bu yüzden yanıltıcı:
   LLM'nin ürettiği bilinmeyen bir ID, 50-elemanlı evrende "hallucination" sayılırken
   700-elemanlı gerçek evrende "geçerli ama yanlış attribution" sayılmalıydı.

2. **Malware ailesi bazında MITRE-otoriter ground truth eksik.** TRAM2 "tehdit raporu →
   teknik" eşlemesi sağlıyor; ancak ATT&CK'in "WannaCry → {T1486, T1210, T1027, ...}"
   gibi MITRE'nin bizzat doğruladığı malware→TTP ilişkileri kullanılmıyor.

### Çözüm

`mitre-attack/attack-stix-data` reposunun `enterprise-attack.json` (~60MB STIX 2.1
bundle) indirilir ve işlenir.

#### 6.1 — `data/attck_valid_ids.json` (tam ATT&CK teknik evreni)

- **Script:** `scripts/prepare_attck_malware_fixtures.py` (aşağıda)
- **Çıktı:** `data/attck_valid_ids.json` — sıralı, aktif (revoke edilmemiş,
  deprecated olmayan) ATT&CK teknik ID listesi (~700 ID)
- **Kapsam:** Hem ana teknikler (T1055) hem alt-teknikler (T1055.001) dahil
- **Kullanım:** `prepare_tram_dataset.py` bu dosyayı okuyarak tüm TRAM2 fixture
  `attck_valid_ids` alanlarını 50'den 700+'e güncelleyecek
- **Commit:** Evet (küçük JSON dosyası, ~15KB)

#### 6.2 — `tests/evaluation/ground_truth/attck_malware/*.json` (per-malware fixtures)

- **Script:** `scripts/prepare_attck_malware_fixtures.py`
- **Çıktı:** `tests/evaluation/ground_truth/attck_malware/` dizini
- **İçerik:** ATT&CK'te kayıtlı her malware/tool ailesi için bir `GroundTruth`
  uyumlu fixture dosyası. Her fixture:
  ```json
  {
    "sample_id": "cobalt_strike",
    "notes": "ATT&CK ground truth — software: 'Cobalt Strike'. Source: mitre-attack/attack-stix-data (ATT&CK Terms of Use).",
    "technique_ids": ["T1055", "T1059.001", "T1071.001", ...],
    "attck_valid_ids": ["T1001", "T1001.001", ...],  // 700+ ID
    "expected_stix_types": ["malware", "attack-pattern", "relationship"],
    "expected_rel_types": ["uses"]
  }
  ```
- **Eşik:** Min. 3 teknik (düşük eşik — TRAM2'nin 3 ile aynı)
- **Beklenen:** ~250-350 fixture (ATT&CK'te ~700 malware/tool, çoğunun ≥3 tekniği var)
- **Örnekler:** `cobalt_strike.json`, `wannacry.json`, `emotet.json`, `mimikatz.json`,
  `lazarus_group.json`, `fin7.json` ...
- **Commit:** Evet
- **Test:** `tests/evaluation/test_attck_malware_fixtures.py`

**Not:** Bu fixture'lar TRAM2 fixture'larından farklı bir değerlendirme boyutu sağlar:
TRAM2 "bu CTI raporu hangi teknikleri anlatıyor?" sorusunu yanıtlar; ATT&CK malware
fixture'ları "bu malware ailesi hangi teknikleri kullanır?" sorusunu yanıtlar.
Maljan'ın bir binary'i doğru aileye atfedip atfetmediğini ölçmek için idealdir.

#### 6.3 — `data/attck_labeled_sentences.jsonl` (TRAM2-benzeri etiketli dataset)

- **Script:** `scripts/prepare_attck_malware_fixtures.py` (ek çıktı)
- **Commit:** **Hayır** (`.gitignore`'a eklenir, `make prepare-attck` ile üretilir)
- **Format:** JSONL, her satır bir örnek:
  ```json
  {"text": "...", "label": "T1055", "source": "Cobalt Strike", "source_type": "malware", "layer": "relationship_description"}
  ```

**Üç katman:**

| Katman | Kaynak | Nasıl | Miktar | Kalite |
|---|---|---|---|---|
| `relationship_description` | `relationship.description` | Malware/group/campaign'in bir tekniği NASIL kullandığının açıklaması → tek teknik etiketi | ~1,500 | En yüksek: MITRE attribution |
| `technique_description` | `attack-pattern.description` | Tekniğin kendi tanımı → kendi ID'si ile etiketli | ~700 | Yüksek: otoriter tanım |
| `technique_detection` | `attack-pattern.x_mitre_detection` | Tekniğin tespit metni → kendi ID'si | ~600 | Orta: detection odaklı |

- **Toplam:** ~2,800 örnek (TRAM2: 25,000+, ama bu MITRE-otoriter)
- **Kullanım:** TODO-5 DistilBERT/CTI-BERT classifier fine-tuning için training data
- **TRAM2 ile fark:** TRAM2 = dış kaynaktan okunmuş tehdit raporu dili;
  bu dataset = MITRE'nin kendi teknik terminolojisi. İkisi birlikte kullanılırsa
  classifier daha güçlü olur.

#### 6.4 — TRAM2 Fixture Güncellemesi

`prepare_tram_dataset.py` güncellenir:
- `--attck-valid-ids PATH` argümanı eklenir
- `data/attck_valid_ids.json` varsa otomatik okunur (fallback: mevcut davranış)
- 140 fixture yeniden üretilir: `attck_valid_ids` 50 → 700+ ID

#### 6.5 — Makefile Hedefleri

```makefile
prepare-attck:  ## ATT&CK bundle indir → malware fixture + valid IDs + labeled sentences
    uv run python scripts/prepare_attck_malware_fixtures.py

benchmark-attck:  ## ATT&CK malware ground truth'a karşı benchmark çalıştır
    uv run python -m pytest tests/evaluation/ -k "attck_malware" -v
```

### Yapılacaklar (Adım Sırası)

1. `scripts/prepare_attck_malware_fixtures.py` oluştur
2. `.gitignore`'a `data/attck_labeled_sentences.jsonl` ekle
3. `prepare_tram_dataset.py`'ı `--attck-valid-ids` argümanı ile güncelle
4. `make prepare-attck` çalıştır → `data/attck_valid_ids.json` + malware fixtures
5. `make prepare-tram` çalıştır → TRAM2 fixture'larını 700+ ID ile yeniden üret
6. `tests/evaluation/test_attck_malware_fixtures.py` oluştur
7. Makefile güncelle
8. Testleri çalıştır, commit

---

## Öncelik Sırası

| # | Madde | Öncelik | Tahmini Efor |
|---|---|---|---|
| TODO-4 | TRAM2 dataset entegrasyonu | **Tamamlandı** | — |
| TODO-6 | ATT&CK Enterprise katalog entegrasyonu | **Tamamlandı** | — |
| TODO-1 (YARA) | YARA Layer 0 deterministik imza tarama | **Tamamlandı** | — |
| TODO-1 (Sigma) | Sigma Layer 0 log-tabanlı kural eşleşmesi | **Yüksek** | 1-2 gün |
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
- [x] TODO-6 — ATT&CK Enterprise katalog entegrasyonu (691 ID, 724 malware fixture, 16k labeled sentences)
- [x] TODO-1 (YARA) — `YaraLayer` + `data/yara_ttp_rules.yaml` (40+ kural, 27 test)
  - domain="yara", weight=0.90, 4-layer multiplier=1.75
  - `isr_models.py` domain Literal genişletildi: "yara" eklendi
  - `ttp_cascade.py` LAYER_WEIGHTS + CROSS_LAYER_MULTIPLIERS güncellendi
  - `container.py` get_yara_layer() fabrika metodu eklendi
  - `nodes.py` judge node'a YARA Layer 0 entegrasyonu (pre-cascade)
  - Toplam test: 714 passed (önceki: 687)
