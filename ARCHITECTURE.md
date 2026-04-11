# Maljan: Mimari Tasarim ve Proje Durumu

Bu dokuman, Maljan Multi-Agent Malware Analysis Framework'unun mimari tasarimini, tamamlanan bilesenleri ve gelecek yol haritasini icermektedir.

---

## Mimari Genel Bakis

Maljan, zararli yazilim orneklerini uc farkli perspektiften analiz eden, uzmanlarin birbirleriyle muzakere ettigi ve bir hakemm nihai karari verdigi cok katmanli bir LLM tabanli analiz framework'udur.

```
                    +------------------+
                    |   CLI (typer)    |
                    +--------+---------+
                             |
                    +--------v---------+
                    |   MaljanApp      |  <-- Composition Root
                    | (ServiceContainer)|
                    +--------+---------+
                             |
              +--------------+--------------+
              |              |              |
     +--------v---+  +-------v----+  +------v-------+
     |   Static   |  |  Dynamic   |  |   Network    |  <-- Expert Agents
     |  Analyst   |  |  Analyst   |  |   Analyst    |      (@register_agent)
     +------+-----+  +-----+------+  +------+-------+
              |              |              |
              +--------------+--------------+
                             |
                    +--------v---------+
                    |   Negotiation    |  <-- Muzakere Dongusu
                    |   (Mediator)     |
                    +--------+---------+
                             |
                     consensus? -------+
                     |  no             | yes
              +------v-------+  +-----v------+
              |   Revision   |  |   Judge    |  <-- Nihai Karar
              |   (Loop)     |  |  (Verdict) |
              +--------------+  +-----+------+
                                      |
                              +-------v-------+
                              |  STIX 2.1     |
                              |  Bundle       |
                              +---------------+
```

---

## Katman 1: Veri Zenginlestirme ve On Isleme

LLM'lere ham dosyalari (ornegin bir `.exe` dosyasini) dogrudan veremeyiz. Bu nedenle sistemin ilk adimi, zararli yazilimi uc farkli boyutta ayristiran bir otomasyon boru hatti (pipeline) olmalidir.

- **Statik Veri Cikarimi:** Zararli yazilim `Ghidra` veya `Radare2` komut satiri araclarindan gecirilerek decompiled kod parcaciklari, string ifadeler ve PE baslik (header) bilgileri elde edilir.

- **Dinamik Davranis Cikarimi:** Dosya, izole bir `CAPEv2` veya `Cuckoo Sandbox` ortaminda calistirilir. Sistem cagrilari (API calls), dosya sistemi hareketleri ve kayit defteri (registry) degisiklikleri JSON formatinda alinir.

- **Ag Trafigi Cikarimi:** Sandbox calisirken yakalanan PCAP dosyasi `Zeek` (eski adiyla Bro) uzerinden gecirilerek DNS istekleri, HTTP/HTTPS baglantilari ve beacon benzeri periyodik iletisimler ayristirilir.

### Uygulama Durumu

| Bilesen | Durum | Aciklama |
|---------|-------|----------|
| DataLoader | Tamamlandi | `FileDataLoader` + `ParserRegistry` ile dinamik parser kesfi |
| Advanced Parsers | Tamamlandi | Static, Dynamic, Network parserlari `@register_parser` ile kayitli |
| Davranissal Imza Eslestirme | Tamamlandi | Parser seviyesinde "Code Injection", "Persistence" gibi olaylarin tespiti |
| Otomatik Arac Entegrasyonu | Planlanmis | Ghidra/CAPEv2/Zeek otomatik pipeline (su an elle hazirlanan JSON dosyalari) |

---

## Katman 2: Uzman Ajan Katmani

Bu katmanda calisan modellerin her biri sadece kendi uzmanlik alanindaki veriyi gorecek ve kendi perspektifinden bir analiz uretecektir.

- **Ajan 1 (Statik Kod Analisti):**
    - **Girdi:** Decompile edilmis kodlar ve stringler.
    - **Odak:** Kodda obfuscation (gizleme) var mi? Zararli kutuphaneler (ornegin kriptografi veya enjeksiyon apileri) kullanilmis mi?

- **Ajan 2 (Dinamik Analist):**
    - **Girdi:** JSON formatindaki sandbox davranis loglari.
    - **Odak:** Hangi kalicilik (persistence) yontemleri kullaniliyor? Sisteme zararli bir payload dusurulmus mu (dropper davranisi)?

- **Ajan 3 (Ag ve C2 Analisti):**
    - **Girdi:** Zeek baglanti loglari ve PCAP ozetleri.
    - **Odak:** Disariya veri sizdiriliyormu? Hangi IP veya domainler ile haberlesiliyor? Bir C2 altyapisiyla baglanti kuruldu mu?

### Uygulama Durumu

| Bilesen | Durum | Aciklama |
|---------|-------|----------|
| OOP Agent Structure | Tamamlandi | `BaseAnalyst` + `@register_agent` dekoratoru ile plugin mimarisi |
| Expert Analysts (3x) | Tamamlandi | Static, Dynamic, Network uzmanlari |
| Revizyon Yetkinligi | Tamamlandi | `revise()` metodu ile muzakere sirasinda rapor guncelleme |
| Token Overflow Korumasi | Tamamlandi | `tiktoken` ile girdi truncation |
| Hata Yonetimi | Tamamlandi | `safe_analyze()` / `safe_revise()` ile graceful fallback |
| Multi-Provider LLM | Tamamlandi | OpenAI, Anthropic, Ollama - `@register_provider` ile genisletilebilir |

---

## Katman 3: Tartisma ve Muzakere Motoru

Sistemin en can alici noktasi ajanlarin statik bir rapor uretip birakmamasi, birbirlerinin bulgularini inceleyerek tartisabilmesidir.

- **Altyapi:** Bu iletisimi yonetmek icin **LangGraph** (Python) framework'u kullanilmaktadir. Durum yonetimi (State Management) sayesinde ajanlarin konusma sirasi graf tabanli olarak kontrol edilmektedir.

- **Surec:**
    1. Her ajan ilk raporunu yazar ve `reports` dict'ine yazar.
    2. Ajanlar birbirlerinin raporlarini okur. Ornegin Statik Ajan, "Kodda ag baglantisi fonksiyonu bulamadim" derken Ag Ajani, "Fakat PCAP'te disariya giden sifreli bir trafik var" diyebilir.
    3. Ajanlar celisen noktalarda argumanlarini revize eder (genellikle 2 veya 3 tur tartisma - _iteration_ - doner).

### Uygulama Durumu

| Bilesen | Durum | Aciklama |
|---------|-------|----------|
| LangGraph Orchestration | Tamamlandi | Dinamik graf builder, `AgentRegistry`'den otomatik node olusturma |
| Gercek Muzakere | Tamamlandi | `revision_node` ile ajanlar birbirlerinin raporlarini okuyup itiraz ediyor |
| Consensus Detection | Tamamlandi | Mediator'un confidence skoruna dayali konsensus tespiti |
| Early Exit | Tamamlandi | Konsensus saglandiginda dongudan erken cikis |

---

## Katman 4: Hakem ve Cikti Uretimi

Tartisma dongusu bittiginde, konusma gecmisi ve ajanlarin son argumanlari Hakem modele iletilir. Hakem model, celiskileri cozer, nihai karari ("Malware" veya "Benign") verir ve detayli bir rapor yazar.

- **Hakem Model:** `Llama-3.1-70B` (Yerel) veya donanim yetersizse `GPT / Claude` (API).
- **Istihbarat Entegrasyonu:** Hakem model, analiz sonucunu ham metin yerine **STIX 2.1** formatinda yapilandirilmis bir JSON nesnesi olarak cikti verecek sekilde (Structured Output) yonlendirilir.
- **Operasyonel Akis:** Tespit edilen tehdit aktoru taktikleri (MITRE ATT&CK TTP'leri), IP'ler, domainler ve hash degerleri STIX bundle olarak uretilir.

### Uygulama Durumu

| Bilesen | Durum | Aciklama |
|---------|-------|----------|
| STIX 2.1 Verdict | Tamamlandi | Pydantic uzerinden kati kuralli STIX 2.1 Bundle formati |
| MITRE ATT&CK Mapping | Tamamlandi | AttackPattern nesneleri ile TTP eslestirme |
| OpenCTI Entegrasyonu | Planlanmis | STIX bundle'in otomatik istihbarat aktarimi |

---

## v1.0.0 Enterprise Mimari Desenleri

### Registry Pattern (Plugin Mimarisi)

Yeni bir agent/parser/LLM provider eklemek icin sadece **1 dosya** olusturup dekorator eklemek yeterli:

```python
# Yeni ajan ekleme ornegi
@register_agent("memory")
class MemoryAnalyst(BaseAnalyst):
    def analyze(self, data: str) -> str: ...
    def revise(self, ...) -> str: ...

# Yeni parser ekleme ornegi
@register_parser("memory")
class MemoryParser(BaseParser):
    def parse(self, raw_data) -> str: ...

# Yeni LLM provider ekleme ornegi
@register_provider("groq")
class GroqProvider:
    def build_model(self, model, temperature, **kwargs) -> BaseChatModel: ...
```

**Baska hicbir dosya degistirmeye gerek yok.** Pipeline builder, registry'den yeni bileseni otomatik kesfeder.

### Dependency Injection (ServiceContainer)

`ServiceContainer` tum bagimliliklari wire eder. Mock/real mod merkezi kontrol altinda:

```python
container = ServiceContainer(config=settings, mock=True)
agents = container.agent_registry.list_agents()  # ["static", "dynamic", "network"]
llm = container.get_expert_llm()  # RuntimeError in mock mode
```

### Protocol-Based Contracts

Tum alt-sistemler `typing.Protocol` ile tanimli kontratlar uzerinden calisir:
- `AnalystProtocol` - Agent arayuzu
- `ParserProtocol` - Parser arayuzu
- `LLMProviderProtocol` - LLM provider arayuzu
- `DataLoaderProtocol` - Data loader arayuzu

---

## Proje Yapisi

```
src/maljan/
    app.py                  # Composition Root (MaljanApp)
    cli.py                  # Thin CLI wrapper (typer)
    core/
        config.py           # Hiyerarsik nested config (Pydantic Settings)
        container.py        # ServiceContainer (Dependency Injection)
        protocols.py        # Interface contracts (typing.Protocol)
        exceptions.py       # MaljanError, AnalystError, LLMError, ...
        logger.py           # Merkezi loglama
    agents/
        registry.py         # @register_agent + AgentRegistry
        base_agent.py       # BaseAnalyst (ABC)
        static_analyst.py   # @register_agent("static")
        dynamic_analyst.py  # @register_agent("dynamic")
        network_analyst.py  # @register_agent("network")
        judge_agent.py      # Hakem ajan
    parsers/
        registry.py         # @register_parser + ParserRegistry
        base_parser.py      # BaseParser (ABC)
        static_parser.py    # @register_parser("static")
        dynamic_parser.py   # @register_parser("dynamic")
        network_parser.py   # @register_parser("network")
    llm/
        registry.py         # @register_provider + LLMProviderRegistry
        openai_provider.py  # @register_provider("openai")
        anthropic_provider.py  # @register_provider("anthropic")
        ollama_provider.py  # @register_provider("ollama")
    loaders/
        file_loader.py      # FileDataLoader (ParserRegistry ile)
    pipeline/
        state.py            # AnalysisState (dinamik reports dict)
        nodes.py            # Generic node factory
        builder.py          # Dinamik graf builder
        routing.py          # ConsensusRouter
    schemas/
        stix_models.py      # STIX 2.1 Pydantic modelleri
```

---

## Altyapi Durumu

| Bilesen | Durum | Aciklama |
|---------|-------|----------|
| CLI Entrypoint | Tamamlandi | `typer` tabanli thin wrapper (`analyze`, `info` komutlari) |
| Modern Tooling | Tamamlandi | `uv` paket yonetimi, `ruff` linting, `mypy` strict typing |
| Gelismis Logging | Tamamlandi | Ajanlarin "dusunme sureclerini" takip eden merkezi log yapisi |
| Mock Mode | Tamamlandi | API anahtari olmadan tum pipeline'i test edebilme |
| Custom Exception System | Tamamlandi | `MaljanError`, `AnalystError`, `DataLoadError`, `LLMError`, `WorkflowError` |
| Test Suite | Tamamlandi | 46 test: parser, agent, STIX model, registry, container, integration |

---

## Tavsiye Edilen Yazilim Yigini

| Bilesen | Onerilen Arac / Framework |
|---------|---------------------------|
| Model Sunucusu | vLLM (Yuksek hiz) veya Ollama (Kolay kurulum) |
| Orkestrasyon | LangGraph (Python) |
| Ozel Istem (Prompt) Yonetimi | LangChain |
| Sandbox | CAPEv2 (API uzerinden otomatik tetiklenebilir) |
| Cikti Formati | STIX 2.1 (Pydantic ile LLM ciktisi formatlanarak dogrulanir) |

---

## Gelecek Yol Haritasi

### 1. Otomatik Veri Toplama
- [ ] **Ghidra Headless Plugin**: `analyzeHeadless` ile otomatik decompilation pipeline.
- [ ] **CAPEv2 REST API Connector**: Dosya submit + sonuc cekme otomasyonu.
- [ ] **Zeek Log Pipeline**: PCAP dosyalarindan otomatik JSON cikti uretimi.

### 2. Gorsellestirme ve Izlenebilirlik (Web UI)
- [ ] **LangGraph Dashboard**: Ajanlarin tartismalarini gercek zamanli izleyebildigimiz web arayuzu.
- [ ] **STIX Visualizer**: Uretilen STIX bundle'ini grafiksel olarak gosteren viewer.

### 3. Derin Analiz Araclari
- [ ] **YARA/Sigma Generator**: Analist uzmanlarin otomatik olarak YARA kurallari uretmesi.
- [ ] **Additional Parsers**: Any.Run, IDA Pro, Procmon ve Sysmon log destekleri.
- [ ] **ML-based Pre-Scoring**: Binary entropi/PE header supheli skor modeli.

### 4. Otomasyon ve Mudahale
- [ ] **Responder Agent**: Firewall kurali veya EDR block listesi oneren ajan.
- [ ] **Automated Report Export**: PDF/HTML formatinda profesyonel rapor uretici.
- [ ] **OpenCTI Entegrasyonu**: STIX bundle'in otomatik istihbarat aktarimi.

### 5. Olceklenebilirlik
- [ ] **Async Execution**: Ajanlarin paralel calistirilmasi.
- [ ] **Database Integration**: Vektor veritabaninda (RAG) gecmis analiz hafizasi.
