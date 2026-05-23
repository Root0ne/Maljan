# CAPEv2 entegrasyonu (Docker dev stack)

Bu doküman Maljan'ın sandbox entegrasyonunu **CAPEv2** üstüne kurmak için iki kısma ayrılır (eski Triage / tria.ge entegrasyonu tamamen kaldırıldı):

1. **Dev tarafı (bu repodaki Docker stack):** CAPEv2 web + REST API container'da, Postgres ile, gerçek VM olmadan. Maljan'ın `CAPEv2Client` entegrasyon yolunu end-to-end test etmek için.
2. **Prod tarafı (follow-up):** Gerçek malware analizi için Linux host + KVM + Windows guest VM gerekiyor — upstream CAPE deployment yolu.

---

## 1. Neden iki kısım?

CAPEv2 architecture'ü monolitik: web/REST API + scheduler + result server + reporting modulleri **aynı host'ta** çalışıyor ve analiz için **gerçek hipervizör + Windows guest VM** istiyor. Upstream'in Dockerfile'ı yok ve Docker-only "tam CAPEv2" mümkün değil.

Bu repo'daki yaklaşım:

| Bileşen | Docker'da mı? | Notu |
|---|---|---|
| Django web + REST API (`/apiv2/*`) | Evet | Maljan'ın konuştuğu yüzey |
| Postgres (task DB) | Evet | Compose içinde sibling container |
| Scheduler / Result Server | Hayır | Gerçek VM olmadan iş yapmıyorlar |
| MongoDB / Elasticsearch | Hayır | Reporting opsiyonel; off |
| KVM + Windows guest | Hayır | Host'ta ayrıca kurulması gerek |

**Sonuç:** Sample submit eder, task DB'ye yazılır, ama statüsü `pending`'de kalır (process eden worker yok). Maljan'ın `submit → poll → fetch_report` yolu çalışır; sadece `wait_for_completion` gerçek bir VM olmadığı için timeout'a düşer. Tam analiz için aşağıdaki "Prod" bölümüne bakın.

---

## 2. Dev stack'i çalıştır

### 2.1. Build + start

```powershell
docker compose -f docker/cape-compose.yml up -d --build
```

İlk build ~10-15 dk (Ubuntu base + Python deps). Sonraki build'ler cache ile saniyeler içinde.

### 2.2. Doğrula

```powershell
# Postgres hazır mı?
docker exec maljan-cape-postgres pg_isready -U cape -d cape

# REST API yanıt veriyor mu?
curl http://localhost:18000/apiv2/

# Token üzerinden korumalı endpoint:
curl -H "Authorization: Token maljan_cape_dev_token" `
     http://localhost:18000/apiv2/tasks/list/
```

### 2.3. Maljan'ı CAPE'ye yönlendir

Root `.env`:

```
SANDBOX__BACKEND=cape2
SANDBOX__CAPE2_BASE_URL=http://localhost:18000
SANDBOX__CAPE2_API_TOKEN=maljan_cape_dev_token
SANDBOX__CAPE2_TIMEOUT_SECONDS=300
SANDBOX__CAPE2_POLL_INTERVAL_SECONDS=10
```

Maljan worker + API'yi restart edin:

```powershell
# Sırayla:
#   - apps/api uvicorn process
#   - apps/api arq worker process
```

`tests/unit/test_sandbox_client.py` zaten CAPEv2Client'ı mock httpx ile test ediyor — değişiklik gerekmez.

### 2.4. Stack komutları

```powershell
# Logları gör
docker compose -f docker/cape-compose.yml logs -f cape-web

# Shell aç
docker exec -it maljan-cape-web bash

# Durdur
docker compose -f docker/cape-compose.yml down

# DB sıfırla
docker compose -f docker/cape-compose.yml down -v
```

---

## 3. Mimari detaylar

### 3.1. Maljan tarafı

Hiçbir kod değişikliği gerekmez. İlgili noktalar:

- [src/maljan/loaders/cape2_client.py](../src/maljan/loaders/cape2_client.py) — REST client
- [src/maljan/core/config.py:192-226](../src/maljan/core/config.py#L192-L226) — `SandboxConfig.backend` `cape2`'yi kabul ediyor
- [src/maljan/core/container.py](../src/maljan/core/container.py) — Factory `backend=="cape2"` branch'i

### 3.2. CAPE container yapısı

| Dosya | Görev |
|---|---|
| [docker/cape/Dockerfile.cape-web](../docker/cape/Dockerfile.cape-web) | Ubuntu 22.04 + Python 3.10 + minimum CAPE deps |
| [docker/cape/entrypoint.sh](../docker/cape/entrypoint.sh) | conf/* patch + alembic migrate + Django runserver |
| [docker/cape-compose.yml](../docker/cape-compose.yml) | cape-postgres + cape-web servisleri |

### 3.3. Entrypoint config patch'leri

Container ayağa kalkarken `entrypoint.sh` şunları yapar:

1. `conf/cuckoo.conf` → `database.connection` = Postgres DSN
2. `conf/reporting.conf` → `[mongodb]`, `[elasticsearchdb]` `enabled = no`
3. `conf/web.conf` → `recaptcha = no`
4. `conf/api.conf` + `conf/apiv2.conf` → tüm `enabled = no` → `yes`
5. `conf/api.conf` → `token` = `CAPE_API_TOKEN` env değeri
6. `alembic upgrade head` (SQLAlchemy şemasını kur)
7. `python3 web/manage.py runserver 0.0.0.0:8000`

### 3.4. REST endpoint'leri

Maljan'ın `CAPEv2Client`'ı şunları çağırıyor (upstream `external/CAPEv2/web/apiv2/urls.py` ile doğrulandı):

| Method | Path | Görev |
|---|---|---|
| POST | `/apiv2/tasks/create/file/` | Sample submit |
| GET | `/apiv2/tasks/view/{id}/` | Task status |
| GET | `/apiv2/tasks/get/report/{id}/` | Full JSON report |

> **Bug fix kaydı:** `cape2_client.py` önceden `/apiv2/tasks/report/{id}/` çağırıyordu (yanlış path). Bu audit kapsamında düzeltildi.

---

## 4. Production / gerçek analiz follow-up

Gerçek sample analizi için Docker yetmez. Upstream'in resmi yolu:

### 4.1. Host gereksinimleri

- **Linux** (Ubuntu 22.04 / 24.04 önerilen)
- **KVM** veya **QEMU** + libvirt
- **CPU:** virtualization desteği (Intel VT-x / AMD-V)
- **RAM:** minimum 16 GB (Windows VM 4 GB + host)
- **Disk:** 200 GB+ (Windows VM imajları + analiz çıktıları)

### 4.2. Kurulum yolu

```bash
# external/CAPEv2/installer/cape2.sh otomatize ediyor:
sudo bash external/CAPEv2/installer/cape2.sh base cape
```

Bu script (1500+ satır) şunları kurar:
- KVM/libvirt
- Python deps + native deps (yara, ssdeep, suricata, capa)
- PostgreSQL + MongoDB
- Systemd unit'leri (cape, cape-rooter, cape-processor, cape-web)
- Nginx + uWSGI reverse proxy

### 4.3. Windows guest VM

CAPE'in `data/guest_images_examples/` altında örnekler var. Tipik flow:

1. KVM ile Windows 10 VM oluştur (4 GB RAM, 60 GB disk)
2. `cape` user'ı (Linux) → libvirt erişimi
3. VM içinde `extra/win10_disabler.ps1` çalıştır (telemetry kapama, defender devre dışı)
4. VM içine **CAPE agent**'i kur (`external/CAPEv2/agent/agent.py`)
5. `conf/kvm.conf`'da VM'i kayıt et (label, ip, snapshot adı)
6. `cape` servisini başlat:
   ```bash
   sudo systemctl start cape cape-rooter cape-processor cape-web
   ```

### 4.4. Dev → Prod geçiş

Maljan tarafından **hiçbir kod değişikliği gerekmez**. Sadece `.env`:

```diff
- SANDBOX__CAPE2_BASE_URL=http://localhost:18000
+ SANDBOX__CAPE2_BASE_URL=http://cape-prod-host.internal:8000
- SANDBOX__CAPE2_API_TOKEN=maljan_cape_dev_token
+ SANDBOX__CAPE2_API_TOKEN=<prod token from cape conf/api.conf>
```

---

## 5. Bilinen kısıtlar (dev stack)

| Kısıt | Açıklama | Workaround |
|---|---|---|
| Sample yürütülmüyor | Scheduler/worker yok | Prod kurulumuna geç |
| `wait_for_completion` timeout | Status hiç "reported"'a geçmiyor | `SANDBOX__CAPE2_TIMEOUT_SECONDS=10` ile hızla geç |
| Mongo'suz reporting | Bazı UI bölümleri boş | Web UI başarılı submission gösterir |
| pyre2 build edilmiyorsa | Bazı signature modülleri yüklenmez | Web/REST yolu etkilenmez |
| Windows host | KVM Linux-only | Hyper-V için `conf/hyperv.conf.default`'a bak |

---

## 6. Mock backend

Lokal geliştirme + CI için sandbox'a hiç ihtiyaç olmadığı durumlarda
fixture dosyalarından yararlanan `mock` backend kullanılabilir:

```
SANDBOX__BACKEND=mock
```

`MockSandboxClient` `data/samples/dynamic/{sha256|name}.json` altındaki
hazır rapor JSON'larını okur — gerçek bir CAPE örneğine erişim
gerektirmez. Production kullanım için `cape2` backend'ine geçin.
