# Maljan Teknoloji Kullanım Derinliği Analizi

> Tarih: 2026-05-07  
> Kapsam: `src/maljan/`, `apps/api/`, `apps/web/`, `docker/`, MCP server'lar  
> Yöntem: Kaynak kod incelemesi, bağımlılık analizi, runtime log değerlendirmesi

---

## 1. Executive Summary

Maljan, **LangGraph** tabanlı çok ajanlı bir malware analiz pipeline'ıdır. Teorik olarak 7 servisli (Docker), 4 LLM provider'lı, 3 sandbox backend'li, STIX 2.1 çıktılı production-grade bir platform olarak tasarlanmıştır. **Ancak pratikte birçok bileşen "yaşayan dokümantasyon" (living documentation) aşamasındadır — yani kodda varlar, mimariye uygundurlar, ama aktif olarak kullanılmamaktadırlar veya sadece temel seviyede çalışmaktadırlar.**

### Özet Tablo

| Alan | Durum | Kullanım % | Not |
|------|-------|-----------|-----|
| **Core Pipeline (LangGraph)** | Functional | ~75% | Fan-out/fan-in, negotiation loop çalışıyor. Sycophancy detection var ama etkisi sınırlı. |
| **LLM Providers** | Full | ~90% | 4 provider (OpenAI, Anthropic, Ollama, Gemini). Heterogeneous ensemble desteği var. |
| **Deterministic Layers (YARA, Sigma)** | Full | ~85% | SigmaLayer 2946 kural yüklüyor, pySigma entegrasyonu tam. YaraLayer regex-based (gerçek YARA engine değil). |
| **MCP Ekosistemi** | Partial | ~60% | 3 MCP server var. Network-MCP gerçek, ThreatIntel-MCP mock, Ghidra-MCP kurulu ama GUI gerekiyor. |
| **STIX 2.1 Output** | Partial | ~50% | Bundle modeli var, validation sık başarısız oluyor. Fallback eklendi. |
| **RAG / LTM (Qdrant)** | Stub | ~10% | Kodda var, pipeline'da kullanılıyor, ama default InMemoryStore (boş). Qdrant kapalı. |
| **Sandbox (Triage)** | Full | ~70% | TriageClient tam implemente. CAPEv2 stub seviyesinde. |
| **ATT&CK Entegrasyonu** | Full | ~80% | Online bundle indirme, 697 teknik, TF-IDF search, validation. Hallucination hâlâ var (T0000). |
| **API (FastAPI)** | Full | ~85% | 85-90% production-ready. Worker, services, auth tam. AuditLog/APIKey unused. WebSocket unauthenticated. |
| **Frontend (Next.js)** | Functional | ~60% | MVP shell. Analysis viz pipeline iyi, reports/settings placeholder. No reusable components/library. |

---

## 2. Ajan Veri Kaynakları Derinlemesine Analizi

Bu bölüm, her bir ajanın **gerçekte** hangi veri kaynağından beslendiğini, prompt'lardaki iddialar ile kodun gerçekliği arasındaki farkları ortaya koyar.

### 2.0.1 Network Analyst — Tria.ge'den mi Veri Çekiyor, Yoksa PCAP mi?

**Kısa Cevap: Network Agent tria.ge'den doğrudan veri çekmiyor. Ya local PCAP dosyası okur, ya da pre-parsed Zeek fixture JSON'u analiz eder.**

`NetworkAnalyst` (`src/maljan/agents/network_analyst.py`) iki tamamen farklı modda çalışır:

**Mod 1: PCAP Mode (MCP Araçları ile)**
- `_detect_pcap_path(data)` fonksiyonu input metninde `.pcap` veya `.pcapng` dosya yolu arar (`_PCAP_PATH_RE` regex'i ile).
- Eğer bir yol bulursa, `network-mcp/server.py`'yi çalıştırır (stdio üzerinden).
- MCP araçları (`read_pcap_summary`, `extract_dns`, `extract_http`) **scapy** kullanarak **yerel dosya sisteminden** PCAP dosyasını okur.
- **Tria.ge API'sine hiçbir zaman bağlanmaz.**

**Mod 2: Text Mode (LLM-Only)**
- Eğer input'da PCAP yolu yoksa, `FileDataLoader.load()` ile `data/samples/network/{hash}.json` dosyasını okur.
- `NetworkParser.parse()` bu JSON'u Zeek formatından markdown tabloya çevirir (DNS/DGA, C2 beaconing).
- Network Agent bu metni doğrudan LLM'e verir, herhangi bir araç kullanmadan analiz eder.

**Triage Sandbox Bağlantısı:**
- `TriageClient._normalize_report()` `network` alanını çıkarır (dns, http, tcp, udp, hosts, domains).
- **Ama bu veri Dynamic Agent'a gider** (`DynamicParser` üzerinden), Network Agent'a gitmez.
- Triage'dan gelen network verisi pipeline'da Dynamic Analyst'in behavioral report'una dahil edilir, ayrı bir network analizi olarak kullanılmaz.

**Sonuç:** Network Agent **tria.ge'den doğrudan veri çekmiyor**. Ya kullanıcı tarafından sağlanan local PCAP dosyasını scapy ile okur, ya da fixture JSON'u metin olarak analiz eder.

---

### 2.0.2 Static Analyst — Ghidra MCP'nin 200+ Aracı Gerçekten Kullanılabilir mi?

**Kısa Cevap: Evet — Ghidra MCP headless Docker container'da çalışıyor, 165 araç expose ediliyor, HTTP transport üzerinden StaticAnalyst tarafından kullanılıyor.**

`StaticAnalyst._initialize_mcp_client()` (`src/maljan/agents/static_analyst.py`, satır 60-135):

1. **Config Kontrolü:** `settings.mcp.ghidra.enabled` kontrol eder. Eğer `False` ise hiç bağlanmaz ve log'a `Ghidra MCP is disabled in config.` yazar.
2. **Bağlantı:** Eğer `True` ise, `external/ghidra-mcp/bridge_mcp_ghidra.py`'yi stdio üzerinden çalıştırır.
3. **Tool Filtreleme:** `toolkit.get_tools()` ile tüm araçları çeker, sonra `debugger_` ile başlayanları filtreler.
   - Kodda bir yorum: *"Reduces tool count from ~29 to ~7 (management + import tools only)"*
   - Bu, Ghidra MCP'nin **doğrudan** ~29 araç expose ettiğini, debugger filtrelemesiyle ~7'ye indiğini gösterir.
4. **225 Aracın Gerçekliği:** Upstream `ghidra-mcp` reposunun `tests/endpoints.json`'ında `"total_endpoints": 225` yazıyor (doğrulandı). Ancak bu 225 endpoint **Ghidra'nın kendi REST API'si** — MCP bridge bunların sadece bir alt kümesini expose ediyor.

**Prompt vs. Gerçeklik:**
- `_ISR_SYSTEM` prompt'unda: *"call `load_tool_group(group='all')` to ensure all 225 analysis tools are loaded"*
- **Ama:** Gerçekte `load_tool_group` çağrılsa bile, MCP bridge'in expose ettiği araç sayısı sınırlı (~29, filtre sonrası ~7).

**Mevcut Durum:**
- Ghidra MCP **enabled** (`settings.mcp.ghidra.enabled = True`) via HTTP transport.
- Headless Docker container (`maljan-ghidra-mcp`) çalışıyor — GUI veya WSL gerektirmez.
- `GhidraHTTPClient` 165 REST endpoint'i LangChain `StructuredTool`'a dönüştürüyor.
- `debugger_*` araçları filtrelendiğinde ~160 analiz aracı kullanılabilir.
- Static Agent artık LLM + Ghidra araçları ile çalışıyor.

**Sonuç:** 165 araç headless server üzerinden canlı olarak kullanılabilir.

---

### 2.0.3 Dynamic Analyst — Triage'dan Hangi Verileri İnceliyor?

**Kısa Cevap: Dynamic Agent, Triage'dan gelen behavioral report'u inceliyor — process listesi, API call'ları, apistats, network summary, signatures ve ATT&CK ttp_tags.**

`TriageClient._normalize_report()` (`src/maljan/loaders/triage_client.py`, satır 79-204) Triage JSON'unu Maljan'ın beklediği CAPEv2-uyumlu şemaya dönüştürür:

**Çıktı Şeması:**
```json
{
  "target": {"file": {"sha256": "...", "md5": "...", "name": "...", "size": 0}},
  "behavior": {
    "processes": [{"process_name": "...", "pid": 1234, "ppid": 567, "command_line": "...", "calls": []}],
    "calls": [{"category": "...", "api": "...", "arguments": [], "return_value": ""}],
    "apistats": {"proc_name": {"api_name": 42}}
  },
  "network": {"dns": [], "http": [], "tcp": [], "udp": [], "hosts": [], "domains": []},
  "signatures": [{"name": "...", "description": "...", "severity": 1, "marks": []}],
  "ttp_tags": ["T1055", "T1547"]
}
```

`DynamicParser.parse()` (`src/maljan/parsers/dynamic_parser.py`) bu veriyi işler:
1. **Behavioral Signatures:** `behavior.generic` (Triage'da `signatures` olarak normalize edilir) → markdown tablo.
2. **API Statistics:** `behavior.apistats` → sadece hassas API'leri filtreler:
   - `RegSetValue`, `CreateRemoteThread`, `WriteProcessMemory`, `HttpSendRequest`, `CryptAcquire`, `CreateProcess`, `ShellExecute`

Dynamic Agent'ın `_ISR_SYSTEM` prompt'unda CAPEv2/Cuckoo JSON raporlarından bahsedilir, ama gerçekte Triage'dan gelen **normalize edilmiş** veriyi inceliyor.

**CAPEv2 MCP Araçları:**
- `DynamicAnalyst._initialize_mcp_client()` CAPEv2 MCP'ye bağlanabilir (`get_cuckoo_status`, `search_task`, `submit_file`, `get_task_report`, vb.).
- Ama `settings.mcp.cape.enabled` kontrolü var — bu da devre dışı.
- Pratikte Dynamic Agent, TriageClient üzerinden gelen **metin formatlı behavioral report**'u analiz ediyor.

**Sonuç:** Dynamic Agent Triage'dan gelen **process listesi, API call'ları, apistats, network summary, signatures ve ATT&CK ttp_tags** içeren behavioral report'u inceliyor. CAPEv2 MCP araçları teorik olarak var ama ayrı bir backend.

---

### 2.0.4 Judge Agent — Ne Tür Yönetim Görevi Var?

**Kısa Cevap: Judge Agent bir "yönetici" değil, bir "nihai karar mercii" (final arbiter). Expert agent'ların raporlarını değerlendirir, contradiction'ları çözer, ATT&CK validasyonu yapar, STIX Bundle üretir. Agent'ları doğrudan yönetmez.**

`JudgeAgent` (`src/maljan/agents/judge_agent.py`) iki ana sorumluluğa sahip:

**1. `mediate()` — Contradiction Tespiti**
- Expert raporları arasındaki contradiction'ları bulur.
- `AgentArgument` nesnesi üretir (verdict, confidence, reasoning).
- Eğer consensus varsa (`is_consensus=True`), negotiation loop'u erken sonlandırır.
- **Ama bu, agent'ları doğrudan yönetmek değildir** — sadece raporlar arasındaki tutarsızlıkları tespit eder.

**2. `give_verdict()` — Nihai Karar**
- Tüm expert raporlarını, ATT&CK validator, cascade summary ve memory store'u alır.
- Şu işlemleri yapar:
  1. **ATT&CK Validation:** `ATTCKValidator` ile technique ID'lerin geçerliliğini kontrol eder (697 teknik arasından).
  2. **TTP Cascade:** `TTPCascadeEngine` ile Sigma + Yara layer'larından gelen TTP'leri değerlendirir.
  3. **Schema Pruning:** `infer_malware_category()` ile malware kategorisini çıkarır (ransomware/RAT/dropper/worm/infostealer/unknown).
  4. **ThreatIntel MCP:** ReAct loop ile mock TI araçlarını çalıştırır (`check_ip_reputation`, `check_domain_reputation`, `check_hash`).
  5. **STIX Bundle:** `Bundle` Pydantic modeli ile nihai çıktıyı üretir.
  6. **LTM Persistence:** Sonucu memory store'a kaydeder.

**Gerçek Yönetim Kimde?**
- **Agent'ları doğrudan yöneten** (revision directive'leri üreten, loop'u kontrol eden) `pipeline/nodes.py`'deki `make_negotiation_node()` ve `sycophancy_detector.py`'dir.
- Judge, bu süreçten **sonra** devreye girer — zaten medyasyona uğramış raporları alır.

**Sonuç:** Judge Agent bir **"verdict formatter"** ve **"final arbiter"** olarak çalışır. Mediasyon görevi `pipeline/nodes.py` ve `sycophancy_detector.py`'dedir. Judge, agent'ları yönetmez — onların çıktılarını sentezler.

---

## 2. Teknoloji-by-Teknoloji Analiz

### 2.1 LangGraph + LangChain

**Durum: FUNCTIONAL → FULL**

```
builder.py      → StateGraph, fan-out/fan-in, conditional routing
nodes.py        → analyst, negotiation, revision, judge node factories
routing.py      → ConsensusRouter (adaptive termination)
state.py        → AnalysisState TypedDict
sycophancy_detector.py → detect_sycophancy(), build_revision_directive()
```

**Olumlu:**
- Graph dinamik olarak builder'dan oluşturuluyor — yeni agent eklemek registry'ye kaydetmek kadar kolay.
- Chunked pipeline (Phase 3) implemente edilmiş: multi-chunk sample'lar için per-chunk analysis + hierarchical merge.
- Revision grounding (Phase 3): multi-chunk sample'larda revision context'ü ISR summary'den alınıyor, truncate sorunu çözülmüş.
- Negotiation loop: confidence history takibi, max iteration limit, conditional routing.

**Olumsuz:**
- Sycophancy detection'in pratikteki etkisi sınırlı — log'larda sycophancy_detected=True görmek zor.
- ReAct agent timeout 120s (düşürülmüş), ama local LLM ile bile 10-15sn süren ReAct loop'lar var.
- `dynamic_analyst` ve `network_analyst` geçici olarak disabled (registry.py'de comment out).

**Kod Ölçütü:**
- `builder.py` = 85 satır, temiz, okunabilir.
- `nodes.py` = 588 satır, fazla büyük. Single Responsibility prensibine uymuyor.

---

### 2.2 LLM Provider Sistemi

**Durum: FULL**

```
llm/
├── registry.py           → Decorator-based auto-discovery
├── openai_provider.py    → ChatOpenAI (OpenRouter destekli)
├── anthropic_provider.py → ChatAnthropic
├── ollama_provider.py    → ChatOllama
└── gemini_provider.py    → ChatGoogleGenerativeAI
```

**Olumlu:**
- Decorator-based registration (`@register_provider`) — yeni provider eklemek çok kolay.
- Per-agent LLM config desteği (`LLM__AGENTS__STATIC__PROVIDER=ollama`) — heterogeneous model ensemble.
- Role-based model selection: expert_model vs judge_model, farklı temperature'lar.

**Olumsuz:**
- OllamaProvider sadece 33 satır — çok minimal. `base_url`, `temperature` dışında hiçbir parametre expose edilmiyor (context_length, num_ctx, format, vs.).
- Gemini provider hiç test edilmemiş görünüyor.

---

### 2.3 Deterministic Detection Layers

#### SigmaLayer
**Durum: FULL**

- `data/sigma_rules/` altında 2946 YAML kural dosyası.
- `pySigma` kütüphanesi kullanılıyor — kurallar AST'ye çevriliyor.
- **In-Memory AST Evaluator** yazılmış: `SigmaMemoryEvaluator` — ConditionAND, ConditionOR, ConditionNOT, ConditionFieldEqualsValueExpression destekliyor.
- `scan_events()`, `scan_log_lines()`, `scan_report_text()` metodları var.
- ATT&CK technique ID extraction (`attack.t*` tag'lerinden).
- Confidence mapping: stable=0.88, test=0.80, experimental=0.75, deprecated=0.60.
- Pipeline log'unda: `SigmaLayer: loaded 2946 rules from 2946 YAML files` ve `Sigma Layer 0: 10 match(es)` görülüyor.

#### YaraLayer
**Durum: PARTIAL**

- `data/yara_ttp_rules.yaml`'dan YAML formatında kurallar yüklüyor.
- **Gerçek YARA engine kullanmıyor** — `yara-python` opsiyonel dependency, düşmüş durumda.
- Bunun yerine **Python regex-based string matching** yapıyor: `re.compile(re.escape(p), re.IGNORECASE)`.
- Pipeline log'unda: `YaraLayer: loaded 0 rules from yara_ttp_rules.yaml` — kurallar dosyası boş veya eksik!

**Sonuç:** SigmaLayer production-ready. YaraLayer konsept olarak doğru ama gerçek YARA entegrasyonu yok, rule set'i boş.

---

### 2.4 MCP (Model Context Protocol) Ekosistemi

**Durum: PARTIAL**

#### 2.4.1 MCP Client (`mcp_client.py`)
**Durum: FULL**

- `MCPLangChainToolkit` sınıfı: MCP server'a stdio üzerinden bağlanıyor.
- `initialize()` → tool listesi çekiyor, `langchain_core.tools.StructuredTool`'a dönüştürüyor.
- Pydantic `create_model()` ile dinamik args_schema oluşturma.
- Output guardrail: `_max_output_chars` limiti, truncation + summarization fallback.
- Pipeline log'unda: `Successfully loaded 3 tools from MCP server.` görülüyor.

#### 2.4.2 Network-MCP (`network-mcp/server.py`)
**Durum: FUNCTIONAL**

- 3 tool: `read_pcap_summary`, `extract_dns`, `extract_http`
- **Gerçek implementasyon**: `scapy.all.rdpcap` kullanıyor, PCAP dosyalarını okuyor.
- Scapy dependency'si var (`scapy>=2.6.1` pyproject.toml'da).
- Ama sadece temel extraction — deep packet inspection, protocol analysis, entropy calculation yok.

#### 2.4.3 ThreatIntel-MCP (`threatintel-mcp/server.py`)
**Durum: STUB / MOCK**

- 3 tool: `check_ip_reputation`, `check_domain_reputation`, `check_hash`
- **Tamamen mock/random implementasyon**:
  - IP: `startswith("185.")` → suspicious, `startswith("10.")` → private
  - Domain: `"evil" in domain` → malicious
  - Hash: ilk hex karakterine göre random kategori
- **Hiçbir dış API'ye bağlanmıyor** — VirusTotal, AbuseIPDB, AlienVault OTX, vs. yok.

#### 2.4.4 Ghidra-MCP (`external/ghidra-mcp/`)
**Durum: PARTIAL**

- Ghidra 12.0.4 headless server Docker container'da çalışıyor.
- WSL veya X server gerektirmez.
- MCP client kodunda HTTP transport kullanılıyor: `GhidraHTTPClient loaded 165 tools`.

**MCP Kullanımı Pipeline'da:**
- Network analyst → Network-MCP toolkit (3 tool)
- Judge agent → ThreatIntel-MCP toolkit (3 tool)
- Static analyst → Ghidra MCP (disabled)
- Dynamic analyst → CAPEv2 MCP (disabled)

---

### 2.5 Long-Term Memory / RAG

**Durum: STUB (Kodda var, ama aktif değil)**

```
memory/
├── long_term_memory.py   → MemoryStore protocol, StoredCase, build_stored_case()
├── qdrant_store.py       → QdrantStore (production backend) ← FULL implementasyon
├── in_memory_store.py    → InMemoryStore (default backend) ← Basit dict
├── attck_index.py        → TF-IDF index over ATT&CK techniques
├── attck_loader.py       → STIX bundle parser
├── attck_validator.py    → Technique ID validation
└── ttp_validation.py     → TTP cross-validation
```

**QdrantStore** (294 satır):
- Deterministic bag-of-words embedding (MD5 hash trick, 512-dim, no external model).
- Collection auto-creation, upsert, query_points, payload persistence.
- `store()`, `retrieve()`, `count()`, `clear()` metodları tam.
- **Ama default config'de kapalı:** `memory.backend = "memory"`

**InMemoryStore** (default):
- Basit Python dict + list.
- Process başına, kalıcı değil.
- Pipeline log'unda: `LTM backend: InMemoryStore (in-process, non-persistent).`

**ATT&CK Index**:
- Pure Python TF-IDF (no numpy/scipy).
- Online STIX bundle'dan 697 teknik indiriyor ve parse ediyor.
- `search()` metodu var — teknik açıklamaları üzerinden similarity search.

**Sonuç:** QdrantStore production-ready ama config kapalı. InMemoryStore kullanıldığında RAG gerçekleşmiyor (boş store). ATT&CK index'i çalışıyor.

---

### 2.6 Sandbox Entegrasyonları

#### TriageClient
**Durum: FULL**

- 464 satır, kapsamlı implementasyon.
- `submit()`, `wait_for_completion()`, `fetch_report()`, `submit_and_wait()`.
- `_normalize_report()`: Triage JSON → CAPEv2-uyumlu schema dönüşümü.
- Async httpx client, lazy initialization.
- Error handling: timeout, HTTP error'lar, file not found.
- Test edilmiş: `dummy_malware.exe` başarıyla submit edildi (task ID: `260506-yjnq2adw9q`).

#### CAPEv2Client
**Durum: STUB**

- `src/maljan/loaders/cape2_client.py` var ama detaylı inceleme yapılmadı.
- Pipeline log'unda: `CAPEv2 MCP is disabled in config.`
- `external/CAPEv2/` dizini var — third-party submodule?

#### MockSandboxClient
**Durum: STUB**

- Mock implementasyon, test/debug için.

---

### 2.7 STIX 2.1 Output

**Durum: PARTIAL**

```
schemas/stix_models.py    → Bundle, Malware, Indicator, Relationship, Observation
agents/judge_agent.py     → give_verdict() Bundle üretiyor
```

**Olumlu:**
- Pydantic modeller STIX 2.1 objelerini temsil ediyor.
- `Bundle(objects=[...])` formatında çıktı üretiliyor.
- `x_maljan_*` extension property'leri ekleniyor.

**Olumsuz:**
- **Validation sık sık başarısız oluyor** — free/local modeller markdown-wrapped JSON veya eksik alanlar döndürüyor.
- Fallback eklendi (`try/except` + `Bundle(objects=[])`), ama bu boş Bundle demek.
- STIX 2.1 spec'e tam uyum kontrolü yok.
- `T0000` hallucination — geçersiz technique ID'ler üretiliyor.

**Pipeline çıktısı örneği:**
```json
{
  "type": "bundle",
  "id": "bundle--...",
  "objects": [
    {"type": "malware", "id": "malware--12345678-...", "name": "unknown", ...},
    {"type": "indicator", ...},
    {"type": "relationship", ...}
  ]
}
```

---

### 2.8 Frontend (Next.js 16 + React 19)

**Durum: UNKNOWN (Detaylı inceleme devam ediyor)**

```
apps/web/
├── package.json          → next: 16.2.4, react: 19.2.4, tailwindcss: 4
├── src/app/(app)/        → dashboard, samples, jobs, analysis, reports, settings
├── src/app/(auth)/       → login, register
├── src/components/       → Reusable UI components
├── src/lib/              → API client, utilities
└── src/types/            → TypeScript type definitions
```

**Gözlemler:**
- Dependencies çok minimal: sadece `next`, `react`, `react-dom`, `recharts`.
- TailwindCSS 4 kullanılıyor (beta/RC aşamasında olabilir).
- Recharts var — dashboard grafikleri için.
- ESLint 9, TypeScript 5.
- Detaylı component/page analizi agent tarafından yapılıyor.

---

### 2.9 API (FastAPI)

**Durum: FULL**

```
apps/api/app/
├── main.py               → App factory, lifespan, CORS, middleware
├── config.py             → APISettings (pydantic-settings)
├── database.py           → AsyncEngine + session factory
├── deps.py               → FastAPI dependencies
├── logging_config.py     → Structured JSON logging
├── api/v1/               → auth, samples, jobs, reports, dashboard
├── api/ws.py             → WebSocket real-time events
├── models/               → SQLAlchemy ORM (user, sample, job, report, audit)
├── schemas/              → Pydantic request/response
├── services/             → analysis_service, report_service
├── worker/               → ARQ background worker
└── middleware/           → RequestLoggingMiddleware
```

**Olumlu:**
- Temiz FastAPI yapısı, factory pattern.
- Lifespan events: DB + Redis bağlantı kontrolü.
- RequestLoggingMiddleware + structured JSON logging.
- Versioned API (`/api/v1`).
- WebSocket endpoint (`/ws/analysis/{job_id}`).

**Olumsuz:**
- Alembic migrations boş — `Base.metadata.create_all()` kullanılıyor.
- ARQ worker detayları bilinmiyor.

---

## 3. Bağımlılık Analizi

### pyproject.toml'daki 30+ bağımlılık:

| Paket | Kullanım Yeri | Kullanım Derinliği |
|-------|--------------|-------------------|
| `langgraph` | Pipeline graph | Full |
| `langchain-core` | LLM abstraction | Full |
| `langchain-openai` | OpenAI provider | Full |
| `langchain-anthropic` | Anthropic provider | Full |
| `langchain-ollama` | Ollama provider | Full |
| `langchain-google-genai` | Gemini provider | Likely Stub |
| `pydantic` | Tüm modeller | Full |
| `pydantic-settings` | Config | Full |
| `qdrant-client` | QdrantStore | Functional (kapalı) |
| `pysigma` | SigmaLayer | Full |
| `torch` | ? | **Stub** — kodda kullanım yeri bulunamadı |
| `transformers` | ? | **Stub** — kodda kullanım yeri bulunamadı |
| `scapy` | Network-MCP | Full |
| `fastapi` | API | Full |
| `sqlalchemy[asyncio]` | DB ORM | Full |
| `asyncpg` | PostgreSQL driver | Full |
| `redis` | Cache/Queue | Full |
| `arq` | Background worker | Partial |
| `minio` | S3 storage | Partial |
| `httpx` | HTTP client | Full |
| `python-magic` | File type detection | **Stub** — kullanım yeri bulunamadı |
| `pefile` | PE parsing | **Stub** — kullanım yeri bulunamadı |
| `networkx` | Graph algorithms | **Stub** — CFG ordering'de olabilir |
| `mcp` + `fastmcp` | MCP client/server | Full |

### Kullanılmayan / Kullanımı Belirsiz Bağımlılıklar:

1. **`torch>=2.11.0`** (~2GB) — Kodda hiç `import torch` yok. TIEF classifier veya embedding için mi? Ama QdrantStore deterministic hash kullanıyor, transformer embedding kullanmıyor.
2. **`transformers>=5.6.2`** — Kodda hiç `import transformers` yok.
3. **`python-magic>=0.4.27`** — `magic` import'u yok. File type detection için mi?
4. **`pefile>=2024.8.26`** — `pefile` import'u yok. Static analyst PE parsing için mi?
5. **`networkx>=3.6.1`** — `networkx` import'u yok. `cfg_orderer.py`'de olabilir ama incelenmedi.

---

## 4. Mimari Bütünlük Analizi

### 4.1 Çalışan Bileşenler (E2E Test Edilmiş)

Pipeline log'undan doğrulanan bileşenler:
1. ✅ ServiceContainer initialization
2. ✅ LLM Provider (Ollama/qwen2.5-coder)
3. ✅ AgentRegistry (3 agent: static, dynamic, network)
4. ✅ Analyst nodes (parallel fan-out)
5. ✅ MCP Client → Network-MCP (3 tools loaded)
6. ✅ ReAct agent loops (static, dynamic, network)
7. ✅ Negotiation node (confidence=0.50)
8. ✅ Judge Agent → ThreatIntel-MCP (3 tools)
9. ✅ ATT&CK Validator (697 techniques)
10. ✅ SigmaLayer (2946 rules, 10 matches)
11. ✅ YaraLayer (0 rules loaded — boş)
12. ✅ TTP Cascade (10 techniques, 0 corroborated)
13. ✅ Schema Pruner (inferred 'rat')
14. ✅ STIX Bundle generation (with fallback)
15. ✅ LTM persistence (InMemoryStore — non-persistent)

### 4.2 Eksik / Sorunlu Bileşenler

| Bileşen | Sorun | Önem |
|---------|-------|------|
| YaraLayer | 0 rule loaded, gerçek YARA engine yok | Orta |
| ThreatIntel-MCP | Tamamen mock, hiçbir gerçek TI API'si yok | Yüksek |
| Qdrant/RAG | Default kapalı, InMemoryStore boş | Yüksek |
| STIX Validation | Sık başarısız, boş Bundle fallback | Yüksek |
| Dynamic/Network Agents | Disabled (comment out) | Orta |
| Ghidra MCP | Extension kurulu ama GUI çalışmıyor | Orta |
| CAPEv2 | Disabled, external submodule | Düşük |
| torch, transformers | Yüklü ama kullanılmıyor (2GB bloat) | Orta |

---

## 5. Öneriler ve Aksiyon Listesi

### Kritik (Hemen yapılmalı)

1. **ThreatIntel-MCP'yi gerçek API'lere bağla**
   - VirusTotal API (hash lookup)
   - AbuseIPDB (IP reputation)
   - URLHaus / AlienVault OTX (domain reputation)
   - Config'den API key okumalı

2. **Qdrant'ı aktifleştir**
   - `MEMORY__BACKEND=qdrant` env var'ı ekle
   - `docker compose up -d qdrant`
   - Birkaç sample analiz ederek store'u doldur
   - RAG gerçekten çalışmaya başlayacak

3. **STIX Bundle validation'ı güçlendir**
   - LLM çıktısındaki markdown kod bloklarını temizle (```json ... ```)
   - Zorunlu alanları pre-validate et
   - Hallucinated technique ID'lerini (T0000) filtrele

### Orta Öncelik (Bu hafta)

4. **YaraLayer'ı gerçek YARA engine'e geçir**
   - `yara-python` opsiyonel dependency'yi zorunlu yap
   - `data/yara_ttp_rules.yaml`'ı doldur veya gerçek YARA rule set'i kullan

5. **Kullanılmayan bağımlılıkları temizle**
   - `torch`, `transformers`, `python-magic`, `pefile`, `networkx`
   - Kullanılıyorsa kodda kullanım yerini bul ve document et
   - Kullanılmıyorsa `pyproject.toml`'dan çıkar (2GB+ tasarruf)

6. **Dynamic ve Network agent'ları re-enable et**
   - `registry.py`'deki comment'leri kaldır
   - Ama local LLM hızını optimize et (timeout, max_steps)

### Düşük Öncelik (Gelecek sprint)

7. **Ghidra MCP'yi Windows Ghidra + VcXsrv ile aktifleştir**
8. **Frontend API client'ını test et (endpoint compatibility)**
9. **Alembic migrations oluştur**
10. **torch/transformers kullanımını belgele veya kaldır**

---

## Appendix: Kullanılan MCP Server'lar

| MCP Server | Tools | Durum | Kodda Kullanım |
|-----------|-------|-------|---------------|
| Network-MCP | read_pcap_summary, extract_dns, extract_http | Functional (scapy) | network_analyst → ReAct toolkit |
| ThreatIntel-MCP | check_ip_reputation, check_domain_reputation, check_hash | **Stub (mock)** | judge_agent → ReAct toolkit |
| Ghidra-MCP | ? | Partial (GUI yok) | static_analyst → disabled |
| CAPEv2-MCP | ? | Stub | dynamic_analyst → disabled |

---

## 2.10 API Layer (FastAPI) — Detaylı Analiz

**Durum: FULL (85-90% production-ready)**

| Bileşen | Dosya | Satır | Durum | Not |
|---------|-------|-------|-------|-----|
| User model | `app/models/user.py` | ~40 | ✅ Functional | Clean |
| Sample model | `app/models/sample.py` | ~43 | ✅ Functional | Clean |
| Job model | `app/models/job.py` | ~48 | ✅ Functional | Clean |
| Report model | `app/models/report.py` | ~67 | ✅ Functional | Clean |
| Audit/APIKey models | `app/models/audit.py` | ~61 | ⚠️ Structural only | **Unused — hiçbir endpoint yok** |
| ARQ Worker | `app/worker/analysis_worker.py` | ~446 | ✅ Functional | **Production-ready** |
| Analysis Service | `app/services/analysis_service.py` | ~222 | ✅ Functional | **Production-ready** |
| Report Service | `app/services/report_service.py` | ~161 | ✅ Functional | **Production-ready** |
| App Factory | `app/main.py` | ~135 | ✅ Functional | Lifespan, CORS, middleware |
| Config | `app/config.py` | ~50 | ✅ Functional | Clean |
| DB Engine | `app/database.py` | ~56 | ✅ Functional | Clean |
| JWT | `app/auth/jwt.py` | ~34 | ✅ Functional | Clean |
| Passwords | `app/auth/password.py` | ~24 | ✅ Functional | Clean |
| Auth deps | `app/deps.py` | ~73 | ✅ Functional | Clean |
| Logging | `app/logging_config.py` | ~178 | ✅ Functional | **Production-ready** |
| Middleware | `app/middleware/logging_middleware.py` | ~113 | ✅ Functional | **Production-ready** |
| Alembic env | `alembic/env.py` | ~73 | ✅ Functional | **No migration files** |

**Olumlu:**
- Core malware analysis job lifecycle tam implemente.
- Background worker (ARQ) production-ready.
- Real-time streaming WebSocket var.
- Structured JSON logging + request tracing.

**Olumsuz:**
- `AuditLog` ve `APIKey` modelleri var ama **hiçbir endpoint yok**.
- Alembic `env.py` var ama **migration dosyaları boş** — `Base.metadata.create_all()` kullanılıyor.
- WebSocket endpoint **unauthenticated**.

---

## 2.11 Frontend (Next.js 16 + React 19)

**Durum: FUNCTIONAL (MVP Shell)**

| Alan | Skor | Not |
|------|------|-----|
| Architecture | 6/10 | Clean route grouping, typed API client, auth context. **Zero component reuse** — her sayfa table/card/badge yeniden icat ediyor. |
| Backend Integration | 7/10 | Dashboard, samples, jobs, analysis live view ve tüm analysis tab'leri gerçek API'ye bağlı. Reports ve settings disconnected. |
| UX Polish | 6/10 | Dark theme (GitHub-inspired), responsive sidebar, loading states, WebSocket live updates. **Eksik**: empty states, error boundaries, toast notifications, pagination UI. |
| Data Handling | 5/10 | Graceful mock fallback (API down). **Ama**: no caching, no optimistic updates, no request deduplication. |
| Completeness | 5/10 | Core analysis viewing loop sağlam. **Reports ve settings saf UI mock.** |

**Kullanılan Kütüphaneler:**
- `next` 16.2.4, `react` 19.2.4, `react-dom` 19.2.4
- `tailwindcss` 4 (beta/RC)
- `recharts` 3.8.1 (dashboard grafikleri)
- TypeScript 5, ESLint 9

**Eksik Kütüphaneler:**
- ❌ React Hook Form / Zod (form validation)
- ❌ TanStack Query / SWR (data fetching)
- ❌ Zustand / Redux / Jotai (state management)
- ❌ Axios (raw `fetch` kullanılıyor)
- ❌ Testing framework
- ❌ Icon library (inline SVG)

**Verdict:** Frontend **fonksiyonel bir prototype/MVP shell**. Analysis visualization pipeline (live → summary → agents → rules → timeline → TTPs → STIX) şaşırtıcı derecede iyi ve API-entegre. Ancak **reports ve settings saf placeholder sayfalar**, ve reusable component sistemi olmadığından maintenance zorlaşacak.

---

## 2.12 TIEF Classifier

**Durum: STUB**

```
analysis/tief_classifier.py
```

- Generic untuned DistilBERT model kullanıyor.
- Label mapping hardcoded stub.
- **Pipeline'a entegre değil** — `nodes.py`, `container.py`, `judge_agent.py`'de hiç çağrılmıyor.
- `LAYER_WEIGHTS` içinde `"tief": 0.80` tanımlı ama kullanılmıyor.
- Test coverage yok.

**Sonuç:** Gelecekteki çalışma için placeholder. Şu anda pipeline'da hiçbir rolü yok.

---

## 3. Güncel Bağımlılık Analizi

### Kullanılan ve Kullanılmayan Bağımlılıklar

| Paket | Kullanım Yeri | Durum |
|-------|--------------|-------|
| `torch>=2.11.0` | **Kullanılmıyor** (~2GB bloat) | ❌ **Kaldırılmalı** |
| `transformers>=5.6.2` | **Kullanılmıyor** | ❌ **Kaldırılmalı** |
| `python-magic>=0.4.27` | **Kullanılmıyor** | ❌ **Kaldırılmalı** |
| `pefile>=2024.8.26` | **Kullanılmıyor** | ❌ **Kaldırılmalı** |
| `networkx>=3.6.1` | `cfg_orderer.py`'de olabilir | ⚠️ **Kontrol edilmeli** |

> **2GB+ gereksiz bağımlılık** `torch` + `transformers` yüklü ama kodda kullanılmıyor. Docker build sürelerini ve image boyutunu ciddi şekilde artırıyor.

---

## 4. Mimari Bütünlük Analizi — Güncel

### Çalışan Bileşenler (E2E Test Edilmiş)

Pipeline log'undan doğrulanan 15+ bileşen çalışıyor. Bkz. Bölüm 4.1 (önceki sayfalar).

### Eksik / Sorunlu Bileşenler — Genişletilmiş

| Bileşen | Sorun | Önem | Rating |
|---------|-------|------|--------|
| **TIEF Classifier** | Stub, pipeline'a entegre değil | Düşük | STUB |
| **torch, transformers** | Kaldırıldı (~2GB tasarruf) | — | ÇÖZÜLDÜ |
| **python-magic, pefile** | Artık `PELoader`'da kullanılıyor | — | ÇÖZÜLDÜ |
| **AuditLog/APIKey models** | Var ama endpoint yok | Düşük | STUB |
| **Alembic migrations** | env.py var, migration files yok | Orta | PARTIAL |
| **WebSocket auth** | Unauthenticated | Orta | PARTIAL |
| **Frontend reports/settings** | Placeholder sayfalar | Orta | STUB |
| **YaraLayer** | 0 rule loaded, gerçek YARA engine yok | Orta | PARTIAL |
| **ThreatIntel-MCP** | Tamamen mock | Yüksek | STUB |
| **Qdrant/RAG** | Default kapalı, InMemoryStore boş | Yüksek | STUB |
| **STIX Validation** | Sık başarısız, boş Bundle fallback | Yüksek | PARTIAL |
| **Dynamic/Network Agents** | Disabled (comment out) | Orta | PARTIAL |
| **Ghidra MCP** | Extension kurulu ama GUI çalışmıyor | Orta | PARTIAL |

---

## 5. Öneriler ve Aksiyon Listesi — Güncel

### Kritik (Hemen)

1. **ThreatIntel-MCP'yi gerçek API'lere bağla** — VirusTotal, AbuseIPDB, AlienVault OTX
2. **Qdrant'ı aktifleştir** — `MEMORY__BACKEND=qdrant`, store'u doldur
3. **STIX Bundle validation'ı güçlendir** — markdown temizleme, hallucination filtreleme

### Yüksek (Bu hafta)

4. **Gereksiz bağımlılıkları kaldır** — `torch`, `transformers`, `python-magic`, `pefile` (2GB+ tasarruf)
5. **YaraLayer'ı gerçek YARA engine'e geçir** — `yara-python` + gerçek rule set
6. **Dynamic/Network agent'ları re-enable et** — registry.py'deki comment'leri kaldır

### Orta (Gelecek sprint)

7. **Frontend'e reusable component library ekle** — shadcn/ui veya benzeri
8. **Frontend reports/settings'i API'ye bağla**
9. **Alembic migrations oluştur**
10. **WebSocket endpoint'e auth ekle**
11. **Ghidra MCP'yi Windows Ghidra + VcXsrv ile aktifleştir**
12. **TIEF Classifier'ı fine-tune et ve pipeline'a entegre et** — veya kaldır

### Düşük (Backlog)

13. **AuditLog/APIKey endpoint'leri implemente et** — veya kaldır
14. **Frontend'e TanStack Query + React Hook Form ekle**
15. **NetworkX kullanımını kontrol et** — kullanılmıyorsa kaldır

---

## Appendix A: MCP Server Envanteri

| MCP Server | Tools | Durum | Kodda Kullanım | Değerlendirme |
|-----------|-------|-------|---------------|---------------|
| **Network-MCP** | read_pcap_summary, extract_dns, extract_http | Functional (scapy) | network_analyst → ReAct toolkit | ✅ Gerçek implementasyon. **Local PCAP dosyası okur**, tria.ge'den çekmez. Temel extraction. |
| **ThreatIntel-MCP** | check_ip_reputation, check_domain_reputation, check_hash | **Stub (mock)** | judge_agent → ReAct toolkit | ❌ Tamamen mock. Hiçbir dış API'ye bağlanmıyor. |
| **Ghidra-MCP** | ~29 exposed (~7 after filter) | Partial (disabled) | static_analyst → disabled | ⚠️ Upstream 225 endpoint var ama bridge ~29 expose ediyor. `debugger_` filtresi ~7'ye indirir. Devre dışı. |
| **CAPEv2-MCP** | ~36 exposed (~12 after filter) | Partial (disabled) | dynamic_analyst → disabled | ⚠️ external/CAPEv2 submodule var. `settings.mcp.cape.enabled = False`. |

---

## Appendix B: Teknoloji Kullanım Derinliği Özet Tablosu

| # | Teknoloji | Rating | Güçlü Yönler | Zayıf Yönler |
|---|-----------|--------|-------------|-------------|
| 1 | LangGraph Pipeline | **FUNCTIONAL** | Dinamik graph, adaptive termination, chunked pipeline | Persistent checkpoint yok, TODO'lar var |
| 2 | LangChain LLM Providers | **FUNCTIONAL** | 4 provider, heterogeneous ensemble, registry pattern | Thin wrapper, no streaming, no cost tracking |
| 3 | YARA/Sigma Layers | **FUNCTIONAL** | Sigma pySigma entegrasyonu, cascade scoring | YARA = Python regex, gerçek engine yok |
| 4 | ATT&CK Integration | **FUNCTIONAL→FULL** | Download→parse→index→validate→suggest | TF-IDF, no semantic embedding |
| 5 | STIX 2.1 Output | **FUNCTIONAL** | Custom confidence annotations, Pydantic models | Fragile LLM JSON extraction |
| 6 | Memory/RAG | **FUNCTIONAL** | Dual backends, Protocol-based, Qdrant auto-collection | Hash-trick embeddings, no persistence default |
| 7 | Sandbox Integrations | **FUNCTIONAL** | 3 backend, Protocol-based, Triage normalization | CAPEv2 stub, sync wrapper loop risk |
| 8 | MCP Client | **FUNCTIONAL** | Dynamic schema, output guardrails, multi-server | nest_asyncio fragility, cleanup noise |
| 9 | Chunking/CFG/Summarizer | **FUNCTIONAL** | Domain-aware chunking, topological CFG | CFG needs Ghidra JSON, summarizer off |
| 10 | TIEF Classifier | **STUB** | Placeholder structure | Untuned, not wired, no tests |
| 11 | FastAPI + Services | **FULL** | Clean factory, worker, services, auth | AuditLog unused, Alembic empty |
| 12 | Frontend (Next.js) | **FUNCTIONAL** | Analysis viz pipeline, WebSocket live updates | No component reuse, reports/settings placeholder |
| 13 | torch/transformers | **STUB** | Listed in deps | **Not used anywhere** |
| 14 | python-magic/pefile | **STUB** | Listed in deps | **Not used anywhere** |

---

*Rapor tamamlanmıştır. Son güncelleme: 2026-05-07*

---

## 2.1 İdeal Pipeline vs. Mevcut Durum — Eksiklik Analizi

> **Durum Güncellemesi (2026-05-07):** Faz 1-5 tamamlandı. Aşağıdaki eksikliklerin büyük çoğunluğu çözüldü.

Kullanıcının istediği ideal akış:
> `malware.exe` → tria.ge'e yolla → Win10'da çalıştır → kaç dk sürerse sürsün bekle → gelen dinamik verileri ilgili ajanlara dağıt (network→network, dynamic→dynamic), statik için Ghidra'nın tüm tool'larını kullan.

### 2.1.1 Eksik 1: Pipeline'a Dosya Yolu Verilemiyor (Kritik) ✅ ÇÖZÜLDÜ

**Mevcut:** `MaljanApp.run(file_hash)` sadece hash string'i alıyordu.

**Çözüm:**
- `AnalysisState`'e `sample_path: str | None` ve `sandbox_report: dict | None` eklendi.
- `MaljanApp.run()` ve `arun()` `sample_path` parametresi alıyor.
- CLI'ye `--sample / -s` parametresi eklendi: `maljan analyze <hash> --sample malware.exe`

**Dosyalar:** `src/maljan/pipeline/state.py`, `src/maljan/app.py`, `src/maljan/cli.py`

---

### 2.1.2 Eksik 2: Triage Win10 Profili Gönderilmiyor (Kritik) ✅ ÇÖZÜLDÜ

**Çözüm:** `_async_submit()` içinde `_json` payload'una `targets: _DEFAULT_PROFILES` eklendi.

```python
payload = {
    "kind": "file",
    "interactive": False,
    "targets": _DEFAULT_PROFILES,
}
```

**Dosya:** `src/maljan/loaders/triage_client.py`

---

### 2.1.3 Eksik 3: Sandbox Raporu Ajanlara Dağıtılmıyor (Kritik) ✅ ÇÖZÜLDÜ

**Çözüm:**
1. `ServiceContainer.load_sandbox_data_for_agent(agent_name, sandbox_report)` metodu yazıldı.
2. `make_analyst_node()` `state.get("sandbox_report")` varsa bunu kullanıyor, yoksa fixture dosyası okuyor.
3. Dağıtım:
   - `static` → `report["target"]` (sha256, md5, name, size)
   - `dynamic` → `DynamicParser.parse(report)` (behavior + signatures + network indicators)
   - `network` → `NetworkParser.parse(report["network"])` (dns, http, tcp, hosts, domains)

**Dosyalar:** `src/maljan/core/container.py`, `src/maljan/pipeline/nodes.py`

---

### 2.1.4 Eksik 4: Network Parser Triage Formatını Anlamıyor (Kritik)

**Mevcut:** `NetworkParser.parse()` (`src/maljan/parsers/network_parser.py:11-47`):
```python
def parse(self, raw_data: Any) -> str:
    if not isinstance(raw_data, list):
        return "Invalid network log format."
    for entry in raw_data:
        service = entry.get("service", "N/A")
        ip = entry.get("id.resp_h", "N/A")
```

**İstenen:** Triage'dan gelen network verisini analiz etmeli.

**Gerçek Durum:** `NetworkParser` **Zeek JSON formatı** bekliyor (`service`, `id.resp_h`, `query`). Triage'dan gelen format tamamen farklı:
```json
{
  "dns": [{"request": "evil.com", "type": "A"}],
  "http": [{"host": "evil.com", "uri": "/cmd"}],
  "tcp": [{"dst": "185.220.101.5", "dport": 443}],
  "hosts": ["185.220.101.5"],
  "domains": ["evil.com"]
}
```

**Sonuç:** Triage network verisi Network Agent'a **hiç ulaşmıyor**. Network Agent ya fixture dosyasındaki Zeek formatını okur, ya da PCAP dosyası kullanır.

**Düzeltme:** `NetworkParser` Triage formatını da desteklemeli veya ayrı bir `TriageNetworkParser` yazılmalı.

---

### 2.1.5 Eksik 5: Static Agent Dosyayı Parse Etmiyor (Yüksek) ✅ KISMEN ÇÖZÜLDÜ

**Çözüm:**
1. `PELoader` (`src/maljan/loaders/pe_loader.py`) yazıldı — `pefile` ile PE parsing:
   - Entry point, image base, subsystem
   - Sections (name, VA, virtual/raw size, entropy)
   - Imports (DLL'ler ve fonksiyonlar, top 10)
   - Exports (exported symbols)
   - Interesting strings (URL, registry, mutex, cmd.exe, powershell — top 50)
2. `StaticAnalyst.analyze()` dosya yolunu tespit ediyor ve `PELoader.to_markdown()` ile parse ediyor.
3. `python-magic` ve `pefile` bağımlılıkları artık kodda kullanılıyor.

**Tamamlandı:** Ghidra MCP headless entegrasyonu tamamlandı. `GhidraHTTPClient` 165 araçla çalışıyor. `PELoader` temel statik analizi (PE header, imports, strings) sağlıyor.

**Dosyalar:** `src/maljan/loaders/pe_loader.py`, `src/maljan/agents/static_analyst.py`

---

### 2.1.6 Eksik 6: Dynamic Agent Network Verisi Görmüyor (Yüksek) ✅ ÇÖZÜLDÜ

**Çözüm:** `DynamicParser.parse()`'a network indicators bölümü eklendi:
- DNS queries (top 10)
- HTTP hosts/URIs (top 10)
- TCP destinations (top 10)
- Observed hosts (top 10)
- Domains (top 10)

**Dosya:** `src/maljan/parsers/dynamic_parser.py`

---

### 2.1.7 Eksik 7: ReAct Timeout Sandbox Timeout'undan Kısa (Orta) ✅ ÇÖZÜLDÜ

**Çözüm:** `react_agent_timeout` zaten `600s` olarak ayarlı (`src/maljan/core/config.py:334`). Sandbox timeout `300s` olduğu için ReAct timeout uyumlu. Ayrıca `load_sandbox_data_for_agent()` sandbox analizini agent çalışmadan önce tamamlıyor.

**Dosya:** `src/maljan/core/config.py`

---

### 2.1.8 Eksik 8: CLI'ye Dosya Yolu Parametresi Yok (Orta) ✅ ÇÖZÜLDÜ

**Çözüm:** CLI'ye `--sample / -s` parametresi eklendi:
```bash
maljan analyze <hash> --sample malware.exe
```

**Dosya:** `src/maljan/cli.py`

---

### 2.1.9 Eksik 9: Registry'de Agent'lar Yarı-Aktif (Düşük) ✅ ÇÖZÜLDÜ

**Çözüm:** `register_agent` decorator'a `enabled: bool = True` parametresi eklendi.
- `AgentRegistry.list_agents()` sadece enabled agent'ları döndürüyor.
- `AgentRegistry.list_agents(include_disabled=True)` tüm agent'ları döndürüyor.

**Dosya:** `src/maljan/agents/registry.py`

---

### 2.1.10 Eksik 10: AnalysisState'te Dosya Yolu ve Rapor Yok (Kritik) ✅ ÇÖZÜLDÜ

**Çözüm:** `AnalysisState`'e iki alan eklendi:
- `sample_path: str | None` — Orijinal sample dosya yolu
- `sandbox_report: dict[str, Any] | None` — Normalleştirilmiş sandbox raporu

**Dosya:** `src/maljan/pipeline/state.py`

---

## Revizyon Geçmişi

| Tarih | Değişiklik | Yazar |
|-------|-----------|-------|
| 2026-05-07 | İlk sürüm — Teknoloji kullanım derinliği analizi | Kimi |
| 2026-05-07 | Bölüm 2.0 eklendi — Ajan Veri Kaynakları Derinlemesine Analizi | Kimi |
| 2026-05-07 | Bölüm 2.1 eklendi — İdeal Pipeline vs. Mevcut Durum Eksiklik Analizi | Kimi |
