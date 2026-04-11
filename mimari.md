### Katman 1: Veri Zenginleştirme ve Ön İşleme

LLM'lere ham dosyaları (örneğin bir `.exe` dosyasını) doğrudan veremeyiz. Bu nedenle sistemin ilk adımı, zararlı yazılımı üç farklı boyutta ayrıştıran bir otomasyon boru hattı (pipeline) olmalıdır.

- **Statik Veri Çıkarımı:** Zararlı yazılım `Ghidra` veya `Radare2` komut satırı araçlarından geçirilerek decompiled kod parçacıkları, string ifadeler ve PE başlık (header) bilgileri elde edilir.
    
- **Dinamik Davranış Çıkarımı:** Dosya, izole bir `CAPEv2` veya `Cuckoo Sandbox` ortamında çalıştırılır. Sistem çağrıları (API calls), dosya sistemi hareketleri ve kayıt defteri (registry) değişiklikleri JSON formatında alınır.
    
- **Ağ Trafiği Çıkarımı:** Sandbox çalışırken yakalanan PCAP dosyası `Zeek` (eski adıyla Bro) üzerinden geçirilerek DNS istekleri, HTTP/HTTPS bağlantıları ve beacon benzeri periyodik iletişimler ayrıştırılır.
    

---

### Katman 2: Uzman Ajan Katmanı

Bu katmanda çalışan modellerin her biri sadece kendi uzmanlık alanındaki veriyi görecek ve kendi perspektifinden bir analiz üretecektir.

- **Ajan 1 (Statik Kod Analisti):** * **Girdi:** Decompile edilmiş kodlar ve stringler.
    
    - **Odak:** Kodda obfuscation (gizleme) var mı? Zararlı kütüphaneler (örneğin kriptografi veya enjeksiyon apileri) kullanılmış mı?
        
    - **Teknoloji:** `Qwen-Coder` (Ollama veya vLLM üzerinden yerel olarak barındırılır).
        
- **Ajan 2 (Dinamik Analist):**
    
    - **Girdi:** JSON formatındaki sandbox davranış logları.
        
    - **Odak:** Hangi kalıcılık (persistence) yöntemleri kullanılıyor? Sisteme zararlı bir payload düşürülmüş mü (dropper davranışı)?
        
    - **Teknoloji:** `Qwen-Coder`.
        
- **Ajan 3 (Ağ ve C2 Analisti):**
    
    - **Girdi:** Zeek bağlantı logları ve PCAP özetleri.
        
    - **Odak:** Dışarıya veri sızdırılıyor mu? Hangi IP veya domainler ile haberleşiliyor? Bir C2 altyapısıyla bağlantı kuruldu mu?
        
    - **Teknoloji:** `Qwen-Coder-7B`.

---

### Katman 3: Tartışma ve Müzakere Motoru

Sistemin en can alıcı noktası ajanların statik bir rapor üretip bırakmaması, birbirlerinin bulgularını inceleyerek tartışabilmesidir.

- **Altyapı:** Bu iletişimi yönetmek için **LangGraph** (Python) framework'ü kullanılmalıdır. Durum yönetimi (State Management) sayesinde ajanların konuşma sırası graf tabanlı olarak kontrol edilebilir.
    
- **Süreç:**
    
    1. Her ajan ilk raporunu yazar ve "Ortak Hafıza (Shared Memory)" havuzuna atar.
        
    2. Ajanlar birbirlerinin raporlarını okur. Örneğin Statik Ajan, "Kodda ağ bağlantısı fonksiyonu bulamadım" derken Ağ Ajanı, "Fakat PCAP'te dışarıya giden şifreli bir trafik var" diyebilir.
        
    3. Ajanlar çelişen noktalarda argümanlarını revize eder (genellikle 2 veya 3 tur tartışma - _iteration_ - döner).
        

---

### Katman 4: Hakem ve Çıktı Üretimi

Tartışma döngüsü bittiğinde, konuşma geçmişi ve ajanların son argümanları Hakem modele iletilir. Hakem model, çelişkileri çözer, nihai kararı ("Malware" veya "Benign") verir ve detaylı bir rapor yazar.

Bu noktada elde edilen değerli verilerin sadece bir PDF veya metin dosyası olarak kalmaması, doğrudan operasyonel süreçlere dahil edilebilmesi gerekir.

- **Hakem Model:** `Llama-3.1-70B` (Yerel) veya donanım yetersizse `GPT / Claude` (API).
    
- **İstihbarat Entegrasyonu:** Hakem model, analiz sonucunu ham metin yerine **STIX 2.1** formatında yapılandırılmış bir JSON nesnesi olarak çıktı verecek şekilde (Structured Output) yönlendirilir.
    
- **Operasyonel Akış:** Tespit edilen tehdit aktörü taktikleri (MITRE ATT&CK TTP'leri), IP'ler, domainler ve hash değerleri bir Python konnektörü aracılığıyla doğrudan bir **OpenCTI** envanterine veya merkezi bir C2 istihbarat toplayıcısına (aggregator) aktarılarak ağ güvenlik cihazlarının (IPS/WAF) anında beslenmesi sağlanır.
    

---

### Tavsiye Edilen Yazılım Yığını

| **Bileşen**                      | **Önerilen Araç / Framework**                                |
| -------------------------------- | ------------------------------------------------------------ |
| **Model Sunucusu**               | vLLM (Yüksek hız için) veya Ollama (Kolay kurulum için)      |
| **Orkestrasyon**                 | LangGraph (Python)                                           |
| **Özel İstem (Prompt) Yönetimi** | LangChain veya LlamaIndex                                    |
| **Sandbox**                      | CAPEv2 (API üzerinden otomatik tetiklenebilir)               |
| **Çıktı Formatı**                | STIX 2.1 (Pydantic ile LLM çıktısı formatlanarak doğrulanır) |

Bu mimariyi koda dökmeye başlarken ilk aşamada modellerin tamamını API üzerinden (örneğin OpenAI veya Anthropic kullanarak) hızlıca bağlayıp ajanların birbirleriyle mantıklı bir şekilde tartışabildiğini (Proof of Concept) görmek, sonrasında bu modelleri "Open Source" yerel modellere dönüştürmek çok daha verimli bir yol haritası olacaktır.