# Maljan: Proje Durum ve Mimari Yol Haritası (MIMARI_DURUM.md)

Bu döküman, Maljan projesinin şu anki teknik olgunluk seviyesini, tamamlanan bileşenleri ve gelecekte eklenmesi planlanan özellikleri özetlemektedir.

---

## ✅ Tamamlanan Mimari Katmanlar (100% Hazır)

Şu anki mimari, bir malware'in ham verisini alıp saniyeler içinde siber istihbarat raporuna dönüştürebilen tam fonksiyonel bir pipeline'dır.

### 1. Veri Ingestion ve Zenginleştirme (Layer 1 & 1.5)
- [x] **DataLoader**: Ghidra, CAPEv2 ve Zeek çıktılarını okuyan evrensel yükleyici.
- [x] **Advanced Parsers**: Ham JSON verisindeki gürültüyü %80-90 oranında temizleyen ve LLM'e sadece kritik veriyi Markdown tabloları halinde sunan akıllı parser katmanı.
- [x] **Davranışsal İmza Eşleştirme**: Parser seviyesinde "Code Injection", "Persistence" gibi kritik siber güvenlik olaylarının tespiti ve skorlanması.

### 2. Multi-Agent Zekası (Layer 2)
- [x] **OOP Agent Structure**: Tüm ajanların miras aldığı `BaseAnalyst` altyapısı.
- [x] **Expert Analysts**: Statik, Dinamik ve Ağ uzmanlığına sahip, her biri kendi MITRE ATT&CK TTP'sine odaklanmış bağımsız ajanlar.

### 3. Müzakere ve Karar Mekanizması (Layer 3 & 4)
- [x] **LangGraph Orchestration**: Ajanlar arası state yönetimi ve döngüsel tartışma (negotiation) akışı.
- [x] **Conflict Detection**: Ajanların raporlarındaki çelişkileri bulan Hakem (Mediator) mantığı.
- [x] **STIX 2.1 Verdict**: Nihai kararın Pydantic üzerinden katı kurallı STIX 2.1 Bundle formatında (Malware, Indicator, Relationship, AttackPattern) üretilmesi.

### 4. Enterprise-Grade Altyapı
- [x] **Modern Tooling**: `uv` paket yönetimi, `ruff` linting, `mypy` strict typing.
- [x] **Gelişmiş Logging**: Ajanların "düşünme süreçlerini" takip eden merkezi log yapısı.
- [x] **Mock Mode**: API anahtarı olmadan tüm pipeline'ı test edebilmemizi sağlayan simülasyon modu.

---

## 🚀 Şimdiye Kadar Neler Eklendi? (Özet)

1.  **MITRE ATT&CK Mapping**: Analiz sonuçlarının T1027, T1055, T1071 gibi global tekniklerle eşleştirilmesi.
2.  **State Reducer Mantığı**: `operator.add` ile tartışma geçmişinin silinmeden kümülatif olarak büyümesi.
3.  **Markdown Table Optimization**: LLM'lerin veriyi daha iyi anlaması için optimize edilmiş yapılandırılmış veri sunumu.
4.  **Custom Exception System**: Analist ve veri yükleme hatalarını izole eden hata hiyerarşisi.
5.  **Quality Gates**: CI/CD uyumlu `Makefile` ve kapsamlı entegrasyon testleri.

---

## 🛠 Neler Kaldı? (Gelecek Yol Haritası)

Projenin bir sonraki seviyeye taşınması için planlanan adımlar:

### 1. Görselleştirme ve İzlenebilirlik (Web UI)
- [ ] **LangGraph Dashboard**: Ajanların tartışmalarını gerçek zamanlı izleyebildiğimiz bir web arayüzü.
- [ ] **STIX Visualizer**: Üretilen STIX bundle'ını grafiksel olarak gösteren bir viewer.

### 2. Derin Analiz Araçları
- [ ] **YARA/Sigma Generator**: Analist uzmanlarının, analiz sonunda otomatik olarak YARA kuralları veya Sigma imzaları üretmesi.
- [ ] **Additional Parsers**: Any.Run, IDA Pro, Procmon ve Sysmon logları için yeni parser destekleri.
- [ ] **ML-based Pre-Scoring**: Binary entropisini veya PE başlık şüpheliliğini ölçen (LLM olmayan) bir makine öğrenmesi modelinin parser katmanına eklenmesi.

### 3. Otomasyon ve Müdahale (Remediation)
- [ ] **Responder Agent**: Analiz sonucuna göre firewall kuralı veya EDR block listesi öneren yeni bir ajan.
- [ ] **Automated Report Export**: PDF veya HTML formatında profesyonel malware analiz raporu üreticisi.

### 4. Ölçeklenebilirlik
- [ ] **Async Execution**: Ajanların paralel çalıştırılarak analiz süresinin kısaltılması (Şu an sıralı/sequential çalışmaktadır).
- [ ] **Database Integration**: Daha önceki analizlerin sonuçlarını vektör veritabanında (RAG) tutarak yeni analizlerde "benzer vakaları" hatırlayan bir hafıza katmanı.
