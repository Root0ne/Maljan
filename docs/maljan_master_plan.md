# Maljan: Master Development Plan
## Cross-Validated Research Synthesis & Prioritized Roadmap

> **Kaynak**: 5 bağımsız AI araştırma raporunun (research1.md, Maljan_Research_Report.md,
> Multi-Agent Malware Analysis Framework Research.md, deep-research-report.md,
> Beyond Automation…md) çapraz doğrulama analizi.

---

## 1. RESEARCH CROSS-VALIDATION SUMMARY

### 1.1 Unanimous Findings (5/5 raporlar hemfikir)

Tüm raporların tartışmasız uzlaştığı bulgular — bunlar en güvenilir:

| Bulgu | Pratik Etki |
|---|---|
| **LangGraph doğru seçim** — stateful döngü, koşullu kenar, checkpoint | Mimariyi değiştirme; derinleştir |
| **Echo chamber / sycophancy temel tehdit** — ajanlar çoğunluk görüşüne kayar | Aktif muhalefet zorunlu, sessiz oy yok |
| **CAPEv2 en iyi açık kaynak sandbox** — REST API, YARA, config extraction | Dinamik veri kaynağı |
| **Qdrant production vector DB** — Rust core, payload filter, HNSW | Long-term memory için |
| **STIX 2.1 çıktı doğrulama zorlu** — F1 %57–81 arası, ilişki üretimi zayıf | Pydantic v2 zorunlu validation katmanı |

### 1.2 Majority Findings (4/5 raporlar hemfikir)

| Bulgu | Güvenilirlik |
|---|---|
| Context window ≥32K zorunlu; büyük binary'ler için hiyerarşik chunking gerekli | Yüksek |
| Heterojen model ensemble (farklı sağlayıcı/aileler) echo chamber'ı kırıyor | Yüksek |
| RAG ile geçmiş STIX bundle'ları sorgulanarak few-shot attribution | Yüksek |
| Fine-tuning assembly LLM performansını dramatik artırıyor (asmLLM: +39.7% Recall) | Yüksek |

### 1.3 Minority/Divergent Findings (dikkatli yaklaş)

| Rapor | İddia | Kendi Değerlendirmem |
|---|---|---|
| research1.md | Kimi-Dev-72B %60.4 SWE-bench | SWE-bench malware değil; transferi kanıtlanmamış |
| deep-research-report.md | CrewAI hızlı prototip için yeterli | Maljan'ın döngüsel yapısı için uygun değil |
| Beyond Automation | AutoGen GroupChat negotiation alternatifi | Hybrid mimari ilginç ama karmaşıklık artırır |
| research1.md | Qwen3-Coder 235B önerildi | 235B parametreli model production'da pratik değil |

### 1.4 Kritik Uyarılar (Raporlara direkt inanma)

1. **"93.25% precision TTPDetect"** — Bu binary-level fonksiyon analizi içindi, genel malware için değil. Maljan'da bu rakamı bekleme.
2. **"99.5% accuracy LAMPS"** — PyPI paketi tespitiydi, PE/ELF binary analizi değil. Farklı problem.
3. **"DeepSeek-V3.2 frontier model kadar"** — Context: kod reasoning benchmark. Assembly/malware özgül değerlendirme yok.
4. **CyberLLMInstruct uyarısı**: Fine-tuning siber güvenlik verisine göre güvenlik hizalamasını bozuyor. Production'da dikkat.

---

## 2. CURRENT ARCHITECTURE ANALYSIS

### 2.1 Güçlü Yönler (koru)

```
src/maljan/
├── agents/
│   ├── base_agent.py        # Protocol-based soyutlama
│   ├── static_analyst.py    # Generic peer revision
│   ├── dynamic_analyst.py   # Generic peer revision
│   ├── network_analyst.py   # Generic peer revision
│   ├── judge_agent.py       # Bağımsız hakem
│   └── registry.py          # @register_agent plugin sistemi
├── pipeline/
│   ├── builder.py           # LangGraph graph builder
│   ├── nodes.py             # Fan-out/fan-in paralel yürütme
│   ├── state.py             # AgentState, typed
│   ├── routing.py           # Koşullu kenarlar
│   └── mediation_models.py  # MediatorVerdict (structured output)
├── core/
│   └── container.py         # ServiceContainer, DI, cache
├── parsers/                 # @register_parser plugin sistemi
├── schemas/
│   └── stix_models.py       # Pydantic v2 STIX modelleri
└── loaders/                 # Veri yükleme
```

**Doğru yapılan şeyler:**
- Paralel fan-out execution (3 agent aynı anda)
- Generic negotiation loop (hardcoded agent ismi yok)
- Registry + plugin architecture (sıfır core değişikliği ile yeni ajan)
- MediatorVerdict structured output + fallback
- ServiceContainer multi-tier cache
- 67 test, %100 coverage yeni modüllerde

### 2.2 Eksikler ve Boşluklar

| Eksik | Etki | Öncelik |
|---|---|---|
| Sycophancy önleme mekanizması yok | Echo chamber riski yüksek | Kritik |
| Structured ISR (Intermediate Structural Representation) yok | Context bloat, kayıp | Yüksek |
| Adversarial Critic Agent yok | Hataları tutmakta güçlük | Yüksek |
| Adaptive termination (K-S test, Beta-Binomial) yok | Token israfı veya erken dur | Orta |
| RAG / vector memory yok | Geçmiş analiz bilgisi kullanılmıyor | Yüksek |
| Chunked hierarchical analysis yok | Büyük binary'ler başarısız | Yüksek |
| Real sandbox entegrasyonu yok | JSON fixture'larla çalışıyor | Orta |
| STIX relationship generation zayıf | %57 F1 literatür tabanı | Kritik |
| Per-claim confidence interval yok | STIX'te belirsizlik yok | Orta |
| MITRE ATT&CK RAG index yok | Hallucination riski | Yüksek |

---

## 3. PRIORITIZED DEVELOPMENT ROADMAP

### Phase 0 — Stabilization (TAMAMLANDI)
- [x] Paralel fan-out pipeline
- [x] Generic negotiation loop
- [x] Registry + plugin architecture
- [x] 67 test suite
- [x] mypy + ruff temiz

---

### Phase 1 — Anti-Echo-Chamber Engine (1-2 hafta)

**Hedef**: Mevcut negotiation loop'u gerçek adversarial debate'e dönüştür.

#### 1.1 Structured ISR (Intermediate Structural Representation)

Ajanlar ham metin değil, JSON schema iletir:

```python
# src/maljan/schemas/isr_models.py
class ClaimEvidence(BaseModel):
    claim: str
    evidence_ref: str          # "API call: VirtualAllocEx @ 0x401234"
    confidence: float          # 0.0 - 1.0
    technique_id: str | None   # "T1055.001"

class AgentISR(BaseModel):
    agent_id: str
    domain: Literal["static", "dynamic", "network"]
    claims: list[ClaimEvidence]
    dissent_items: list[str]   # Peer'lardan hala itiraz ettiği iddialar
    revision_round: int
```

**Neden**: MalEval çalışması (rapor 3) LLM'lerin büyük ham veri geçirildiğinde başarısız olduğunu gösterdi. ISR context bloat'ı %60-80 azaltır.

#### 1.2 Forced Dissent Protocol

Her revision round'da ajan en az 1 `dissent_item` belirtmek zorunda. Boş liste = aktif convergence sinyali (otomatik kabul değil).

```python
# pipeline/nodes.py eklentisi
def _validate_dissent(isr: AgentISR, round_num: int) -> bool:
    if round_num > 0 and len(isr.dissent_items) == 0:
        # Convergence flag — judge'a ilet, loglama yap
        return True  # converged
    return False
```

**Literatür Dayanağı**: Free-MAD (arXiv:2509.11035) — "Silent Agreement" problemi; CONSENSAGENT — sycophancy önleme.

#### 1.3 Cosine Similarity Sycophancy Detector

CONSENSAGENT metodolojisinden: Agent raporları birbirine çok yakınsa otomatik "devil's advocate" prompt inject et.

```python
# pipeline/nodes.py
from sklearn.metrics.pairwise import cosine_similarity
from sentence_transformers import SentenceTransformer

SYCOPHANCY_THRESHOLD = 0.90

def _detect_sycophancy(reports: dict[str, str], embedder) -> bool:
    embeddings = embedder.encode(list(reports.values()))
    for i in range(len(embeddings)):
        for j in range(i + 1, len(embeddings)):
            if cosine_similarity([embeddings[i]], [embeddings[j]])[0][0] > SYCOPHANCY_THRESHOLD:
                return True
    return False
```

**Prompt injection**: Sycophancy tespit edilirse o ajanın revise() çağrısına "devil's advocate" directifi eklenir.

**Yeni bağımlılık**: `sentence-transformers` (hafif, Ollama compatible)

---

### Phase 2 — Adaptive Termination (1 hafta)

**Hedef**: Sabit round sayısı yerine istatistiksel olarak kararlı durumda dur.

#### 2.1 Beta-Binomial Mixture Model

"Multi-Agent Debate for LLM Judges" (arXiv:2510.12697) metodolojisi:

```python
# pipeline/routing.py eklentisi
from scipy.stats import kstest
import numpy as np

def should_continue_negotiation(state: GraphState) -> str:
    confidence_history = state["confidence_history"]  # son 3 round
    if len(confidence_history) < 2:
        return "continue"
    
    # K-S testi: confidence dağılımı stabilize oldu mu?
    stat, p_value = kstest(confidence_history[-1], confidence_history[-2])
    if p_value > 0.05:  # distributions are same — stabilized
        return "judge"
    
    if state["round"] >= state["max_rounds"]:
        return "judge"
    
    return "continue"
```

**Beklenen kazanım**: SELENE çalışması (research1.md) token tüketimini ~%50 azalttığını gösterdi.

---

### Phase 3 — Chunked Hierarchical Static Analysis (2 hafta)

**Hedef**: Büyük binary'leri (>100KB) analiz edebilir hale gel.

#### 3.1 Function-Level Chunker

```
src/maljan/preprocessors/
├── __init__.py
├── binary_chunker.py     # Ghidra output'unu fonksiyon bazında böl
├── function_summarizer.py # Her chunk için lightweight model (CodeLLaMA 13B)
└── cfg_orderer.py         # CFG pozisyonuna göre sırala
```

**Akış**:
1. Ghidra decompile → fonksiyon listesi (JSON)
2. Her fonksiyon bağımsız analiz (küçük/hızlı model)
3. CFG sırasına göre özetler birleştirilir
4. Birleşik özet Static Analyst'e verilir

**Literatür Dayanağı**: "Decompilation-Driven Framework" (arXiv:2601.09035) — "lost in the middle" sorunu; Feasibility Study (SECAI 2024) — chunked processing zorunlu.

---

### Phase 4 — Three-Layer TTP Mapping (2-3 hafta)

**Hedef**: Tek LLM TTP mapping → deterministic-to-LLM cascade.

```
Layer 1: CAPE YARA signatures + Sigma rules   (deterministic, zero hallucination)
Layer 2: TIEF/DistilBERT classifier           (high-precision NLP, F1=0.933)
Layer 3: Judge agent LLM                       (contextual reasoning, STIX generation)
```

#### 4.1 MITRE ATT&CK RAG Index

```python
# src/maljan/memory/attck_index.py
class ATTCKIndex:
    """MITRE ATT&CK STIX 2.1 knowledge base indexed in Qdrant."""
    
    def retrieve_technique(self, behavioral_desc: str, top_k: int = 5) -> list[ATTCKTechnique]:
        """Semantic search over ATT&CK technique descriptions."""
        ...
    
    def validate_technique_id(self, technique_id: str, evidence: str) -> float:
        """Cross-check proposed TTP against ATT&CK definition. Returns confidence."""
        ...
```

**Yeni bağımlılık**: `qdrant-client`, MITRE ATT&CK STIX 2.1 dataset (ücretsiz, GitHub)

---

### Phase 5 — Long-Term Memory / RAG (2 hafta)

**Hedef**: Geçmiş analizleri gelecek analizlere bağla.

```
src/maljan/memory/
├── __init__.py
├── stix_store.py      # Qdrant STIX bundle indexing
├── retriever.py       # Similarity search + metadata filter
└── embedder.py        # SecureBERT embeddings veya text-embedding-3-large
```

**STIX Bundle İndeksleme Stratejisi**:
1. Her SDO (Malware, AttackPattern, Indicator) ayrı embed edilir
2. Metadata: malware_family, mitre_ids, ioc_hashes, campaign_id
3. Retrieval: Mevcut binary'nin behavioral signature → top-3 benzer geçmiş analiz → few-shot context olarak agent'lara verilir

**Neden bu order önemli**: RAG, Phase 4'teki TTP validation'ı destekler. Phase 4 bitmeden Phase 5 tam verimli olmaz.

---

### Phase 6 — Real Sandbox Integration (2-3 hafta)

**Hedef**: `data/samples/*.json` fixture'larını gerçek sandbox pipeline'ı ile değiştir.

```
src/maljan/sandbox/
├── __init__.py
├── capev2_client.py    # CAPEv2 REST API wrapper
├── triage_client.py    # Hatching Triage (development/testing)
├── models.py           # SandboxReport Pydantic modeli
└── normalizer.py       # CAPEv2/Triage → Maljan internal format
```

**CAPEv2 API Akışı**:
```
POST /apiv2/tasks/create/file/  → task_id
GET  /apiv2/tasks/status/{id}/  → polling
GET  /apiv2/tasks/get/report/{id}/ → behavior.json, network.json, CAPE.json
```

**Öncelik sırası**: Hatching Triage önce (free tier, hızlı), CAPEv2 production'da.

---

### Phase 7 — STIX 2.1 Quality Improvement (1-2 hafta)

**Hedef**: Relationship generation F1'ini %57'den %75+'a çıkar.

#### 7.1 Dynamic Schema Pruning

CTI-GEN (IEEE CSR 2025) metodolojisi: Judge agent'a tüm STIX schema yerine context'e göre filtrelenmiş alt-schema ver.

```python
# agents/judge_agent.py eklentisi
def _get_pruned_schema(threat_context: str) -> dict:
    """Return only relevant STIX SDO/SCO schemas based on analysis context."""
    # Eğer ransomware ise: Malware, AttackPattern, File, Directory, EncryptedTraffic
    # Eğer RAT ise: Malware, C2Server, NetworkTraffic, Process
    ...
```

#### 7.2 Per-Claim Confidence Intervals

```python
# schemas/stix_models.py eklentisi
class ConfidenceAnnotatedRelationship(BaseModel):
    source_ref: str
    relationship_type: str
    target_ref: str
    confidence: float          # 0.0–1.0
    evidence_basis: str        # "API call trace", "network PCAP", "static string"
    contributing_agents: list[str]  # Hangi ajanlar bu ilişkiyi destekledi
```

**Akademik Değeri**: Literatürde STIX ile per-claim confidence yok. Novel contribution.

---

### Phase 8 — Observability & Evaluation (sürekli)

#### 8.1 LangSmith Integration

```python
# core/container.py
from langsmith import Client
ls_client = Client()
# Otomatik: model versiyonu, temperature, prompt hash, input hash loglanır
```

#### 8.2 Maljan Evaluation Benchmark

Literatürde malware multi-agent evaluation için standart benchmark yok (Gap 5). Maljan bunu tanımlayabilir:

```
tests/evaluation/
├── benchmark_suite.py
│   ├── negotiation_efficiency()    # Kaç round gerekti?
│   ├── adversarial_effectiveness() # Critic agent hata buldu mu?
│   ├── ttp_mapping_accuracy()      # MITRE ground truth ile karşılaştır
│   └── stix_output_quality()       # F1 entity, F1 relationship
└── ground_truth/
    └── aCTIon_dataset/             # 204 STIX bundle, 36k entity
```

---

## 4. MODEL SELECTION GUIDE

### Pratik Öneriler (doğrulanmış benchmarklara göre)

| Agent | Development | Production | Not |
|---|---|---|---|
| **Static Analyst** | `deepseek-coder:6.7b` (Ollama) | `codestral` (256K ctx) | Büyük binary → chunking zorunlu |
| **Dynamic Analyst** | `llama3.1:8b` (Ollama) | `llama3.3:70b` | API call seq. analizi, assembly değil |
| **Network Analyst** | `llama3.1:8b` (Ollama) | `claude-3-5-sonnet` | NL reasoning yeterli |
| **Judge Agent** | `llama3.1:8b` (Ollama) | `claude-3-5-sonnet` / `gpt-4o` | JSON compliance kritik |

**Heterogeneity Rule**: Production'da her agent farklı model ailesinden olmalı (ReConcile + Wu et al. kanıtladı).

**Context Window Minimums**:
- Static Analyst: 32K (chunking olmadan), 8K (chunk başına)
- Dynamic/Network: 16K yeterli
- Judge: 32K (tüm ISR raporları toplandığında)

---

## 5. ARCHITECTURE EVOLUTION DIAGRAM

```
[Şimdiki Durum]
Malware Artifacts
      |
      v
  Parsers (static/dynamic/network JSON)
      |
      v
  Fan-Out (parallel)
  ┌───┼───┐
  S   D   N     (Static / Dynamic / Network Analyst)
  └───┼───┘
      |
  negotiate() loop — maksimum round'a kadar
      |
      v
  JudgeAgent → STIX Bundle


[Hedef Mimari - Phase 8 sonrası]
MalwareBazaar / CAPEv2 / Custom Binary
      |
      v
  Preprocessors
  ├── binary_chunker (Ghidra → fonksiyon listesi)
  ├── capev2_normalizer (behavior/network/CAPE JSON)
  └── pcap_summarizer (zeek/tshark özeti)
      |
      v
  ATT&CK RAG Index Query (top-3 benzer geçmiş)
      |
      v
  Fan-Out (parallel, ISR format)
  ┌───┼───┐
  S   D   N
  └───┼───┘
      |
  Sycophancy Detector
  ├── [normal] → revise() + forced dissent
  └── [sycophancy] → devil's advocate inject → revise()
      |
  Adaptive Termination (K-S test)
  ├── [stable] → Judge
  └── [unstable] → next round
      |
  Layer 1: YARA/Sigma (deterministic TTP)
  Layer 2: TIEF/DistilBERT (NLP classification)
  Layer 3: JudgeAgent (context reasoning)
      |
      v
  STIX 2.1 Bundle (with confidence intervals)
      |
      v
  Qdrant STIX Store (long-term memory)
      |
      v
  OpenCTI Export (optional)
```

---

## 6. ACADEMIC POSITIONING

### 6.1 Proposed Title
*"Maljan: Evidence-Grounded Multi-Domain Malware Analysis via Structured Adversarial Consensus and STIX 2.1 Intelligence Generation"*

### 6.2 Novel Contributions (literatürde yok)

1. **Cross-domain contradiction resolution**: Static/dynamic/network'ün çelişen bulgularını çözme — gap olarak 4/5 rapordan doğrulandı.

2. **Structured STIX from multi-agent deliberation**: CTI-GEN single-pass; Maljan debate sonrası STIX üretiyor. Literatürde yok.

3. **Per-claim confidence intervals in STIX bundles**: Hiçbir mevcut sistem STIX ilişkilerine belirsizlik skoru eklemedi.

4. **Echo chamber measurement in security MAD**: Wu et al. logic puzzles üzerinde çalıştı. Cybersecurity domain'inde ölçüm yapılmadı.

### 6.3 Target Venues
- **Full paper**: IEEE S&P, USENIX Security, ACM CCS
- **Workshop**: AISEC @ CCS, DLS @ IEEE S&P
- **Preprint**: arXiv cs.CR

### 6.4 vs. Existing Work

| Sistem | Fark |
|---|---|
| Sentinel Labs Pipeline | Tool-level (Ghidra/IDA), Maljan domain-level (static/dynamic/network) |
| ReConcile / SELENE | NLP benchmarks; Maljan cybersecurity domain, real ground truth |
| CTI-GEN / eLLM-CTI | Threat report'tan STIX; Maljan raw artifact'lardan (binary/PCAP) |
| TTPDetect | Static binary only; Maljan cross-domain corroboration |
| DECODE | Sadece CAPE sandbox output; Maljan üç alan entegre |

---

## 7. DEPENDENCY MAP (Yeni Eklenecekler)

```toml
# pyproject.toml eklentileri

[project.dependencies]
# Mevcut: langchain, langgraph, pydantic v2, uv
# Yeni:
sentence-transformers = ">=3.0"     # Sycophancy detection embeddings
qdrant-client = ">=1.9"             # Vector DB (long-term memory)
scipy = ">=1.13"                    # K-S test (adaptive termination)
stix2 = ">=3.0"                     # STIX 2.1 validation (python-stix2)
requests = ">=2.31"                 # CAPEv2 / sandbox API
```

---

## 8. OPEN QUESTIONS (Karar Gerektirenler)

> [!IMPORTANT]
> Aşağıdaki sorular implementation başlamadan cevaplanmalı:

1. **Model Provider Policy**: Development'ta tamamen Ollama mı? Yoksa bazı agent'lar için cloud (OpenAI/Anthropic) API key'i hazır mı?

2. **Sandbox Infrastructure**: CAPEv2 local kurulum yapılacak mı? Yoksa Hatching Triage (cloud) free tier yeterli mi başlangıç için?

3. **Evaluation Dataset**: aCTIon dataset (204 STIX bundle) erişimi var mı? Ground truth olmadan TTP accuracy ölçülemiyor.

4. **Academic Paper Hedefi**: Paper şu anda mı yazılmaya başlanmalı (paralel)? Yoksa Phase 5 bittikten sonra mı?

5. **Qdrant Deployment**: Docker Compose ile local mı (development), yoksa managed cloud (production)?

---

## 9. IMMEDIATE NEXT STEPS (Önümüzdeki 2 hafta)

Raporları okuyup planı onayladıktan sonra şu sırayla başla:

1. `src/maljan/schemas/isr_models.py` — AgentISR, ClaimEvidence modelleri
2. `src/maljan/pipeline/sycophancy_detector.py` — cosine similarity guard
3. `nodes.py` güncelleme — ISR format, forced dissent validation
4. `routing.py` güncelleme — adaptive termination (basit round-count → K-S test)
5. Test suite genişletme — ISR validation, sycophancy injection tests
6. `src/maljan/memory/attck_index.py` — MITRE ATT&CK Qdrant index
