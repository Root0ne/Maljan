# Maljan: Proje Durum ve Mimari Yol Haritasi (MIMARI_DURUM.md)

Bu dokuman, Maljan projesinin su anki teknik olgunluk seviyesini, tamamlanan bilesenleri ve gelecekte eklenmesi planlanan ozellikleri ozetlemektedir.

---

## Tamamlanan Mimari Katmanlar

### 1. Veri Ingestion ve Zenginlestirme (Layer 1 & 1.5)
- [x] **DataLoader**: Ghidra, CAPEv2 ve Zeek ciktilarini okuyan evrensel yukleyici.
- [x] **Advanced Parsers**: Ham JSON verisindeki gurultuyu temizleyen ve LLM'e sadece kritik veriyi Markdown tablolari halinde sunan parser katmani.
- [x] **Davranissal Imza Eslestirme**: Parser seviyesinde "Code Injection", "Persistence" gibi kritik guvenlik olaylarinin tespiti ve skorlanmasi.
- [ ] **Otomatik Arac Entegrasyonu**: Ghidra/CAPEv2/Zeek araclariyla otomatik pipeline (su an elle hazirlanan JSON dosyalari okunmaktadir).

### 2. Multi-Agent Zekasi (Layer 2)
- [x] **OOP Agent Structure**: Tum ajanlarin miras aldigi `BaseAnalyst` altyapisi.
- [x] **Expert Analysts**: Statik, Dinamik ve Ag uzmanlarina sahip bagimsiz ajanlar.
- [x] **Revizyon Yetkinligi**: Ajanlarin muzakere sirasinda birbirlerinin raporlarini okuyup kendi analizlerini revize etme yetenegi (`revise()` metodu).
- [x] **Token Overflow Korumasi**: `tiktoken` ile girdi truncation, buyuk veriler icin koruma.
- [x] **Hata Yonetimi**: `safe_analyze()` / `safe_revise()` ile hata yakalama ve graceful fallback.
- [x] **Multi-Provider LLM**: OpenAI, Anthropic ve Ollama (yerel) model destegi.

### 3. Muzakere ve Karar Mekanizmasi (Layer 3 & 4)
- [x] **LangGraph Orchestration**: Ajanlar arasi state yonetimi ve dongusal tartisma akisi.
- [x] **Gercek Muzakere**: Ajanlar birbirlerinin raporlarini okuyup itiraz ediyor (revision node).
- [x] **Consensus Detection**: Mediator'un confidence skoruna dayali gercek konsensus tespiti.
- [x] **Early Exit**: Konsensus saglandiginda muzakere dongusunden erken cikis.
- [x] **STIX 2.1 Verdict**: Nihai kararin Pydantic uzerinden kati kuralli STIX 2.1 Bundle formatinda uretilmesi.

### 4. Altyapi
- [x] **CLI Entrypoint**: `typer` tabanli komut satiri araci (`analyze`, `info` komutlari).
- [x] **Modern Tooling**: `uv` paket yonetimi, `ruff` linting, `mypy` strict typing.
- [x] **Gelismis Logging**: Ajanlarin "dusunme sureclerini" takip eden merkezi log yapisi.
- [x] **Mock Mode**: API anahtari olmadan tum pipeline'i test edebilme.
- [x] **Custom Exception System**: `MaljanError`, `AnalystError`, `DataLoadError`, `LLMError`, `WorkflowError`.
- [x] **Test Suite**: Parser, agent, STIX model unit testleri + integration testleri.

---

## Neler Kaldi? (Gelecek Yol Haritasi)

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
