# Maljan — TODO (Master Plan Senkronize Edilmiş)

Bu belge, `maljan_master_plan.md` (Master Plan) ile projenin mevcut implementasyonu karşılaştırılarak hazırlanmıştır.
Geliştirme süreci, ajanların "gerçek dünya araçlarını" (MCP, Ghidra, CAPE) kullanma yeteneklerini öne çekecek şekilde revize edilmiş, ardından ajanların karar mekanizmalarını (Anti-Echo-Chamber) güçlendirecek Master Plan adımları sıraya konmuştur.

---

## 📋 Öncelik ve Tamamlanma Sırası

| # | Görev (Phase) | Durum | Etki / Öncelik |
|---|---|---|---|
| **A** | YARA kural seti genişletmesi (MITRE verisi uyarlaması) | `[x] TAMAMLANDI` | Kritik |
| **B** | Sigma Layer 0 (log tabanlı deterministik TTP tespiti) | `[x] TAMAMLANDI` | Yüksek |
| **C** | Hatching Triage sandbox client | `[x] TAMAMLANDI` | Orta |
| **D** | FunctionSummarizer (iki aşamalı chunk pipeline) | `[x] TAMAMLANDI` | Düşük |
| **E** | **CAPEv2 MCP Araç (Tool) Genişletmesi & Optimizasyonu** | `[x] TAMAMLANDI` | Yüksek |
| **F** | **Ghidra MCP Prompt Tuning (Agent Eğitimi)** | `[x] TAMAMLANDI` | Yüksek |
| **G** | **Uçtan Uca (E2E) ReAct Pipeline & Orkestrasyon** | `[x] TAMAMLANDI` | Kritik |
| **H** | **Phase 1: Anti-Echo-Chamber Engine (Sycophancy Detector)**| `[ ] BEKLİYOR` | Kritik |
| **I** | **Phase 2: Adaptive Termination (K-S Test)** | `[ ] BEKLİYOR` | Yüksek |
| **J** | **Phase 5: Long-Term Memory / RAG (Qdrant & STIX Store)** | `[ ] BEKLİYOR` | Yüksek |

---

## 🎯 Yakın Vadeli Görevler (MCP ve Canlı Entegrasyon)

Bu aşamadaki görevler, projeye sonradan eklenen ve ajanların yeteneklerini büyük ölçüde artıran **Model Context Protocol (MCP)** altyapısının meyvelerini toplamak için sıraya konmuştur.

### [x] TODO-E: CAPEv2 MCP Araç (Tool) Genişletmesi & Optimizasyonu
**Durum:** TAMAMLANDI
**Etki:** Yüksek — CAPEv2 entegrasyonu sağlandı ancak LLM'e tüm araçlar (tools) başarılı şekilde aktarılamadı.

- [x] **Tool Discovery Çözümü:** `CAPEv2/mcp/server.py` içerisinde tanımlı olan `submit_file`, `cuckoo_status`, `task_report` gibi araçların LangChain `mcp_client` tarafından neden tam olarak yüklenmediği (FastMCP kaynaklı sorunlar vb.) tespit edilip çözülecek.
- [x] **Prompt Güncellemesi:** Ajanın `submit_file` aracını çağırıp, ardından dosyanın analiz edilmesini beklemek için `cuckoo_status` ve `task_report` araçlarını bir döngüde çağırmasını sağlayacak spesifik ReAct (Reasoning and Acting) talimatları `dynamic_analyst.py` içindeki sistem promptlarına eklenecek.

### [x] TODO-F: Ghidra MCP Prompt Tuning (Agent Eğitimi)
**Durum:** TAMAMLANDI
**Etki:** Yüksek — `test_static_analyst.py` ile Ghidra'dan başarıyla 29 adet tool çekildi ancak ajan bu araçları hangi sırayla ve mantıkla kullanacağını bilmiyor.

- [x] **Few-Shot Örneklerinin Eklenmesi:** `static_analyst.py` içerisindeki `_ISR_SYSTEM` promptuna standart bir tersine mühendislik (reverse engineering) iş akışı eklenecek. (Örn: Önce `import_file` kullan, sonra `debugger_modules` ile bellek adreslerini çek, ardından `debugger_read_memory` kullan).
- [x] **Veri Optimizasyonu:** Ghidra'dan dönen devasa Assembly dökümleri LLM'in bağlam limitini (context window) aşmaması için, `FunctionSummarizer` ile özetlenecek şekilde bir kısıtlama (guardrail) mekanizması kurulacak.

### [x] TODO-G: Uçtan Uca (E2E) ReAct Pipeline & Orkestrasyon
**Durum:** TAMAMLANDI
**Etki:** Kritik — Araçlar (Ghidra, CAPE) artık ajanlara yüklenebiliyor, ancak bu araçların canlı bir malware örneği üzerinde *LangGraph* aracılığıyla uçtan uca, tüm pipeline boyunca kullanılması gerekiyor.

- [x] **`scripts/run_analysis.py` Oluşturulması:** Sistemin giriş noktası olacak komut satırı arayüzü yazılacak. Kullanıcıdan alınan dosya (`.exe`, `.dll`) veya hash üzerinden LangGraph akışı (Negotiation -> Revision -> Judge) başlatılacak.
- [x] **Araç Kullanım Döngüsü (Tool Loop) Testi:** Canlı veri akışında `create_react_agent` tabanlı döngünün, dış araçlara istekleri doğru yönlendirdiği test edilecek.
- [x] **Rapor Çıktısı:** Judge ajanının nihai STIX 2.1 kararının ve ISR (Intelligence Summary Report) çıktılarının disk üzerinde (`reports/`) JSON olarak kaydedilmesi sağlanacak.

---

## 🏛️ Orta/Uzun Vadeli Görevler (Master Plan'a Dönüş)

Araç kullanımı (Tool Use) testleri TODO G ile kanıtlandıktan sonra, ajanların karar alma süreçlerinin doğruluğunu ve güvenilirliğini artırmak için Master Plan'daki asıl vizyon maddelerine geri dönülecektir.

### [ ] TODO-H: Phase 1 - Anti-Echo-Chamber Engine (Sycophancy Detector)
**Durum:** BEKLİYOR
**Etki:** Kritik — Ajanların "sessiz kalarak çoğunluğa uyma" (sycophancy) riskini ortadan kaldırır.

- [ ] **Structured ISR (Intermediate Structural Representation):** Ajanların ham metin yerine `ClaimEvidence` ve `dissent_items` (itiraz edilenler) içeren JSON şeması ile haberleşmesi sağlanacak.
- [ ] **Forced Dissent Protocol:** Her revizyon turunda ajan en az 1 `dissent_item` belirtmeye zorlanacak.
- [ ] **Cosine Similarity Denetleyicisi:** Ajanların raporları anlamsal olarak (embeddings) birbirine %90'dan fazla benziyorsa, ajana "Şeytanın Avukatı" (Devil's Advocate) promptu otomatik inject edilecek.

### [ ] TODO-I: Phase 2 - Adaptive Termination (K-S Test)
**Durum:** BEKLİYOR
**Etki:** Yüksek — Müzakere turlarını token israfını önlemek için dinamik olarak sonlandırır.

- [ ] **Beta-Binomial Modellemesi:** Sabit round sayısı (örn: 3) yerine, ajanların güvenilirlik (confidence) skorlarının dağılımı K-S testi (Kolmogorov-Smirnov) ile karşılaştırılacak. Dağılım sabitlendiğinde müzakere erken sonlandırılıp Judge (Hakem) ajana aktarılacak.

### [ ] TODO-J: Phase 5 - Long-Term Memory / RAG (Qdrant & STIX Store)
**Durum:** BEKLİYOR
**Etki:** Yüksek — Geçmiş analizlerin gelecekteki analizlerde RAG altyapısıyla (Few-shot context) kullanılması.

- [ ] **Qdrant Entegrasyonu:** Çıktı olarak üretilen her STIX SDO (Malware, Indicator) bundle'ının `qdrant-client` kullanılarak vektör veritabanına indekslenmesi.
- [ ] **Retrieve & Augment:** Yeni bir malware analiz edildiğinde, benzer TTP'lere veya hash'lere sahip geçmiş STIX bundle'larının çekilerek ajan promptuna "Benzer geçmiş analizler" olarak eklenmesi.

---

## 📁 Tamamlanmış Görev Arşivi

*(Geçmişte tamamlanmış temel altyapı görevleri referans amaçlı burada tutulmaktadır)*

### [x] TODO-A: YARA Kural Seti Genişletmesi
- `[x]` MITRE ATT&CK verileri parse edilerek 300+ yeni YARA kuralı otomatik oluşturuldu. 200+ teknik kapsandı.

### [x] TODO-B: Sigma Layer 0
- `[x]` 2,946 SigmaHQ kuralı entegre edildi. TTP Cascade mimarisine `sigma` domain'i eklendi.

### [x] TODO-C: Hatching Triage Sandbox Client
- `[x]` Triage API'sine uygun olarak `TriageClient` yazıldı, CAPEv2 uyumlu veri normalizasyonu sağlandı.

### [x] TODO-D: FunctionSummarizer
- `[x]` Büyük binary'lerde LLM çağrılarını rahatlatmak adına, fonksiyonları özetleyen hafif pre-summarizer eklendi.
