# Local LLM via ik_llama.cpp (Qwen3.6-35B-A3B)

Maljan'ı yerel olarak çalıştırırken bir LLM sağlayıcıya ihtiyaç var. Bu belge, [ik_llama.cpp](https://github.com/ikawrakow/ik_llama.cpp) (llama.cpp'nin imatrix-quant fork'u) üzerinden **Qwen3.6-35B-A3B** (35B MoE, sadece 3B param/token aktif) modelini Windows + NVIDIA üzerinde nasıl ayağa kaldıracağınızı anlatır.

## Neden bu kurulum?

- Ollama + qwen3.5:9b ile çok-agent pipeline'da (3 expert + mediator + verdict) **timeout** ve sessiz crash'ler oluşuyordu.
- `ik_llama.cpp` + `Qwen3.6-35B-A3B-IQ3_K_R4` kombinasyonu, 8 GB VRAM bir GPU üzerinde **55-60 tok/s** üretiyor ve context derinliği arttıkça **hız düşmüyor**.
- Daha akıllı (35B) ve daha hızlı model → mediator/verdict zamanlarında nefes alıyoruz.

Referans: [AboveSpec'in Mayıs 2026 X thread'leri](https://huggingface.co/abovespec/Qwen3.6-35B-A3B-IQ3_K_R4-GGUF).

## Önkoşullar (Windows)

- Visual Studio Build Tools 2022 ("Desktop development with C++" workload)
- CUDA Toolkit 12.x veya 13.x (NVIDIA driver versiyonuna uygun)
- CMake 3.27+
- Git for Windows
- 16+ GB RAM (32 GB önerilir)
- NVIDIA GPU (8 GB VRAM yeterli — RTX 3060/3070/4060 Ti/5060 sınıfı)

## Kurulum

### 1. ik_llama.cpp'yi klonla ve derle

```powershell
cd D:\Projects\Maljan
git clone https://github.com/ikawrakow/ik_llama.cpp external\ik_llama.cpp
cd external\ik_llama.cpp
cmake -B build -G "Visual Studio 17 2022" -A x64 `
  -DGGML_CUDA=ON `
  -DCMAKE_BUILD_TYPE=Release `
  -DLLAMA_BUILD_TESTS=OFF
cmake --build build --config Release --target llama-server -j
```

Build artefact: `external\ik_llama.cpp\build\bin\Release\llama-server.exe`

### 2. GGUF modeli indir (Unsloth MTP varyantı)

Mayıs 2026 Unsloth/AboveSpec/Snixtp X thread'lerinin tavsiyesi: **MTP (Multi-Token
Prediction)** head'leri eklenmiş GGUF + ik_llama.cpp'nin `-mtp` flag'iyle decode
1.4-2.4x hızlanıyor (özellikle uzun context'te).

```powershell
hf download unsloth/Qwen3.6-35B-A3B-MTP-GGUF `
  Qwen3.6-35B-A3B-UD-IQ3_S.gguf `
  --local-dir .\models
```

Boyut: ~14.3 GB.

> **Alternatif** (MTP'siz, ik_llama hub'ı): `abovespec/Qwen3.6-35B-A3B-IQ3_K_R4-GGUF`
> dosyası `Qwen3.6-35B-A3B-IQ3_K_R4.gguf`. MTP yok, dosya boyutu aynı.

### 3. llama-server'ı başlat (MTP + checkpoint-disable)

```powershell
.\external\ik_llama.cpp\build\bin\Release\llama-server.exe `
  -m .\models\Qwen3.6-35B-A3B-UD-IQ3_S.gguf `
  -ngl 99 --n-cpu-moe 99 `
  --host 127.0.0.1 --port 8080 `
  -fa on `
  -c 262144 `
  -ctk q4_0 -ctv q4_0 `
  --jinja `
  --alias qwen3.6-35b-a3b `
  -mtp --spec-type mtp --draft-max 6 `
  --ctx-checkpoints 0
```

Bayraklar:

| Bayrak | Açıklama |
|---|---|
| `-ngl 99` | Tüm attention/shared weights GPU'da |
| `--n-cpu-moe 99` | Tüm expert FFN'ler CPU+RAM'de (8 GB VRAM senaryosu) |
| `--host 127.0.0.1` | Sadece localhost'tan erişim (güvenlik) |
| `--port 8080` | Maljan `.env`'deki `LLM__OPENAI__BASE_URL` ile eşleşir |
| `-fa on` | FlashAttention (KV scan hızlanır) — `on/off/auto` değer ister, çıplak flag değil |
| `-c 262144` | 256k context (modelin tam eğitim sınırı). Maljan için 64k de yeterlidir |
| `-ctk/-ctv q4_0` | KV cache 4-bit (RAM yarıya iner) |
| `--jinja` | OpenAI `tools` parametresi (fonksiyon çağrısı / ReAct) için ZORUNLU |
| `--alias` | OpenAI API'sinin `model` alanında dönen ad |
| **`-mtp --spec-type mtp`** | Multi-Token Prediction'ı aç — yeni GGUF'taki ek tahmin head'lerini kullanır |
| **`--draft-max 6`** | Her adımda en fazla 6 token speculate et (Unsloth tavsiyesi) |
| **`--ctx-checkpoints 0`** | Context checkpoint mekanizmasını kapat — uzun context'te decode 2x hızlanır (witcheer X thread) |

Daha hızlı varyant (GPU bolsa): `--n-cpu-moe 30` (11 expert GPU'da, ~60 t/s, 7.5 GB VRAM)
— MTP ile birlikte VRAM 10 GB'a çıkar, 8 GB GPU'lara sığmaz. **MTP veya ncmoe=30 — ikisinden birini seç.**

**Context vs. RAM:** q4_0 KV cache ile her token ~5 KB. 256k context → ~1.3 GB ek RAM. 64k istersen `-c 65536` yap, ~320 MB tasarruf.

**Ölçülen kaynak profil (RTX 5060 8 GB + AMD Ryzen 9 8940HX + 32 GB DDR5-5200):**

| Metrik | IQ3_K_R4 (eski, MTP yok) | UD-IQ3_S + MTP (yeni) |
|---|---|---|
| RSS (llama-server) | 17.9 GB | **13.9 GB** (−4 GB) |
| VRAM | 4.3 GB | 5.5 GB (+1.2 GB) |
| Toplam (RAM+VRAM) | 22.2 GB | **19.4 GB** (−2.8 GB) |
| Decode (reasoning'li) | ~30-50 t/s | 26-27 t/s (acceptance %93) |
| Decode (uzun ctx >32K) | düşer | 1.4-2.4x sabit (Snixtp benchmark) |
| Sistem free RAM | ~14 GB | **~18 GB** |

### 4. Maljan'ı yapılandır

`.env` dosyasında:

```env
LLM__PROVIDER=openai
LLM__OPENAI__API_KEY=dummy_key_no_auth_needed
LLM__OPENAI__BASE_URL=http://127.0.0.1:8080/v1
LLM__OPENAI__EXPERT_MODEL=qwen3.6-35b-a3b
LLM__OPENAI__JUDGE_MODEL=qwen3.6-35b-a3b
```

**Not:** `LLM__OPENAI__API_KEY` boş olamaz — provider başlangıçta reddediyor. llama-server kimlik doğrulaması yapmıyor; dummy değer yeterli.

### 5. Docker stack ile çalıştırıyorsanız

`docker-compose.yml` zaten `host.docker.internal:8080/v1`'a yönlendirilmiş. Sadece çevre değişkenleri override etmek isterseniz:

```env
LLM_OPENAI_BASE_URL=http://host.docker.internal:8080/v1
LLM_OPENAI_API_KEY=dummy_key_no_auth_needed
```

## Doğrulama

```powershell
# llama-server ayakta mı?
curl http://127.0.0.1:8080/v1/models

# Sohbet smoke test
curl http://127.0.0.1:8080/v1/chat/completions `
  -H "Content-Type: application/json" `
  -d '{\"model\":\"qwen3.6-35b-a3b\",\"messages\":[{\"role\":\"user\",\"content\":\"Say hi\"}]}'

# Maljan mock pipeline (LLM'i atlar, regresyon kontrolü)
uv run maljan analyze test_sample --mock --name smoke -i 1

# Maljan gerçek pipeline
uv run maljan analyze f5a7696239b801496743753f8066775f68793e81b5d4eceb15f701950774733d `
  -s samples\zararli.elf --provider openai -i 3 --name llamacpp-test
```

## Geri Alma (Ollama'ya dön)

`.env`'de aşağıdaki bloğu yorum işaretsiz, openai bloğunu yorumlu yapın:

```env
LLM__PROVIDER=ollama
LLM__OLLAMA__BASE_URL=http://localhost:11434
LLM__OLLAMA__EXPERT_MODEL=qwen3.5:9b
LLM__OLLAMA__JUDGE_MODEL=qwen3.5:9b
```

Kod tarafında değişiklik yok — provider seçimi tamamen env üzerinden.

## Sorun Giderme

| Belirti | Olası neden | Çözüm |
|---|---|---|
| `OPENAI_API_KEY is not set` | API key env'de yok | `LLM__OPENAI__API_KEY=dummy_key_no_auth_needed` ekle |
| llama-server `failed to load model` | GGUF dosya yolu yanlış veya yetki sorunu | Mutlak yol ver, dosyanın okunabilir olduğunu kontrol et |
| GPU OOM | `-ngl 99` ile attention da GPU'da kalmış | `-ncmoe 99` doğru, ama context'i (`-c`) küçült veya KV cache'i 4-bit'e indir (`-ctk q4_0`) |
| Yavaş (40 t/s altı) | DDR4 RAM darboğazı | DDR5'e yükselt; yoksa daha küçük model (Q4_K_S) |
| MTP draft acceptance düşük (<%80) | Model fazla "thinking" yapıyor, MTP fark edemiyor | Beklenen davranış — uzun çıktıda yine de net kazanç var. Reasoning'i kapatmak için sistem prompt'una `/no_think` ekleyin |
| `error: unknown argument: -mtp` | ik_llama.cpp build eski | Repo'yu güncelleyip yeniden derleyin (MTP desteği 2026-Q2 sonrası) |
| Pipeline mediator yine timeout | Local model hâlâ kompleks STIX bundle için yavaş | `REACT_AGENT_TIMEOUT=600` env ile timeout'u yükselt |
| Build hatası: NCCL bulunamadı | NCCL Windows'ta yok, uyarı normal | Yoksay — single-GPU için NCCL gereksiz |

## Güvenlik notları

- `llama-server` `127.0.0.1`'e bind ediliyor → LAN/internet erişimi yok.
- `models/` ve `external/ik_llama.cpp/` `.gitignore`'da → git'e sızmaz.
- Maljan'ın mevcut güvenlik katmanları (MCP allowlist, JWT, rate limit) yerinde — bu kurulum onlara dokunmuyor.
