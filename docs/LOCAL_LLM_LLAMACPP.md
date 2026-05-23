# Local LLM via ik_llama.cpp (Qwen3.6-35B-A3B)

Running Maljan locally requires an LLM provider. This document explains how to bring up **Qwen3.6-35B-A3B** (35B MoE, only 3B params active per token) on Windows + NVIDIA via [ik_llama.cpp](https://github.com/ikawrakow/ik_llama.cpp) (an imatrix-quant fork of llama.cpp).

## Why this setup?

- The previous Ollama + qwen3.5:9b combination produced **timeouts** and silent crashes in the multi-agent pipeline (3 experts + mediator + verdict).
- `ik_llama.cpp` + `Qwen3.6-35B-A3B-IQ3_K_R4` runs at **55-60 t/s** on a single 8 GB VRAM GPU and **does not degrade** as context depth grows.
- A larger (35B) and faster model gives the mediator / verdict stages real breathing room.

Reference: [AboveSpec's May 2026 X threads](https://huggingface.co/abovespec/Qwen3.6-35B-A3B-IQ3_K_R4-GGUF).

## Prerequisites (Windows)

- Visual Studio Build Tools 2022 ("Desktop development with C++" workload)
- CUDA Toolkit 12.x or 13.x (matching your NVIDIA driver)
- CMake 3.27+
- Git for Windows
- 16+ GB RAM (32 GB recommended)
- An NVIDIA GPU (8 GB VRAM is enough — RTX 3060/3070/4060 Ti/5060 class)

## Setup

### 1. Clone and build ik_llama.cpp

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

### 2. Download the GGUF model (Unsloth MTP variant)

May 2026 X threads from Unsloth / AboveSpec / Snixtp converge on the same recipe: **MTP (Multi-Token Prediction)** heads baked into the GGUF + ik_llama.cpp's `-mtp` flag yields a 1.4-2.4x decode speedup (most noticeable at long context).

```powershell
hf download unsloth/Qwen3.6-35B-A3B-MTP-GGUF `
  Qwen3.6-35B-A3B-UD-IQ3_S.gguf `
  --local-dir .\models
```

Size: ~14.3 GB.

> **Alternative** (no MTP, ik_llama hub): `abovespec/Qwen3.6-35B-A3B-IQ3_K_R4-GGUF`,
> file `Qwen3.6-35B-A3B-IQ3_K_R4.gguf`. No MTP, identical disk size.

### 3. Launch llama-server (MTP + checkpoint-disable)

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

Flags:

| Flag | Description |
|---|---|
| `-ngl 99` | All attention / shared weights on the GPU |
| `--n-cpu-moe 99` | All expert FFNs on CPU+RAM (8 GB VRAM scenario) |
| `--host 127.0.0.1` | Localhost only (security) |
| `--port 8080` | Matches `LLM__OPENAI__BASE_URL` in Maljan's `.env` |
| `-fa on` | FlashAttention (speeds up KV scan) — takes `on/off/auto`, not a bare flag |
| `-c 262144` | 256k context (model's full training window). 64k is more than enough for Maljan |
| `-ctk/-ctv q4_0` | KV cache in 4-bit (halves the cache RAM) |
| `--jinja` | REQUIRED for the OpenAI `tools` parameter (function calling / ReAct) |
| `--alias` | The name returned in the OpenAI API `model` field |
| **`-mtp --spec-type mtp`** | Enables Multi-Token Prediction — uses the extra prediction heads in the new GGUF |
| **`--draft-max 6`** | Speculate at most 6 tokens per step (Unsloth's recommendation) |
| **`--ctx-checkpoints 0`** | Disable the context-checkpoint mechanism — ~2x decode improvement at long context (witcheer X thread) |

Faster variant (if you have VRAM to spare): `--n-cpu-moe 30` (11 experts on GPU, ~60 t/s, 7.5 GB VRAM)
— combined with MTP this pushes VRAM to ~10 GB and will not fit on an 8 GB GPU. **Pick one: MTP or ncmoe=30.**

**Context vs. RAM:** with q4_0 KV cache every token is ~5 KB. 256k context → ~1.3 GB extra RAM. Drop to `-c 65536` for 64k to save ~320 MB.

**Measured resource profile (RTX 5060 8 GB + AMD Ryzen 9 8940HX + 32 GB DDR5-5200):**

| Metric | IQ3_K_R4 (old, no MTP) | UD-IQ3_S + MTP (new) |
|---|---|---|
| RSS (llama-server) | 17.9 GB | **13.9 GB** (−4 GB) |
| VRAM | 4.3 GB | 5.5 GB (+1.2 GB) |
| Total (RAM+VRAM) | 22.2 GB | **19.4 GB** (−2.8 GB) |
| Decode (with reasoning) | ~30-50 t/s | 26-27 t/s (93% draft acceptance) |
| Decode (long ctx >32K) | drops off | 1.4-2.4x flat (Snixtp benchmark) |
| Free system RAM | ~14 GB | **~18 GB** |

### 4. Configure Maljan

In `.env`:

```env
LLM__PROVIDER=openai
LLM__OPENAI__API_KEY=dummy_key_no_auth_needed
LLM__OPENAI__BASE_URL=http://127.0.0.1:8080/v1
LLM__OPENAI__EXPERT_MODEL=qwen3.6-35b-a3b
LLM__OPENAI__JUDGE_MODEL=qwen3.6-35b-a3b
```

**Note:** `LLM__OPENAI__API_KEY` cannot be empty — the provider rejects it at startup. llama-server does not authenticate; a dummy value is enough.

### 5. If you run via the Docker stack

`docker-compose.yml` already targets `host.docker.internal:8080/v1`. To override the env vars only:

```env
LLM_OPENAI_BASE_URL=http://host.docker.internal:8080/v1
LLM_OPENAI_API_KEY=dummy_key_no_auth_needed
```

## Verification

```powershell
# Is llama-server up?
curl http://127.0.0.1:8080/v1/models

# Chat smoke test
curl http://127.0.0.1:8080/v1/chat/completions `
  -H "Content-Type: application/json" `
  -d '{\"model\":\"qwen3.6-35b-a3b\",\"messages\":[{\"role\":\"user\",\"content\":\"Say hi\"}]}'

# Maljan mock pipeline (LLM bypassed — regression check)
uv run maljan analyze test_sample --mock --name smoke -i 1

# Maljan real pipeline
uv run maljan analyze f5a7696239b801496743753f8066775f68793e81b5d4eceb15f701950774733d `
  -s samples\zararli.elf --provider openai -i 3 --name llamacpp-test
```

## Rollback (back to Ollama)

In `.env` uncomment the block below and comment out the openai block:

```env
LLM__PROVIDER=ollama
LLM__OLLAMA__BASE_URL=http://localhost:11434
LLM__OLLAMA__EXPERT_MODEL=qwen3.5:9b
LLM__OLLAMA__JUDGE_MODEL=qwen3.5:9b
```

No code changes required — provider selection is entirely env-driven.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `OPENAI_API_KEY is not set` | API key missing in env | Add `LLM__OPENAI__API_KEY=dummy_key_no_auth_needed` |
| llama-server `failed to load model` | Bad GGUF path or permission issue | Use an absolute path; verify the file is readable |
| GPU OOM | Attention pinned to GPU via `-ngl 99` | `-ncmoe 99` is fine, but lower `-c` or quantise the KV cache further (`-ctk q4_0`) |
| Slow (below 40 t/s) | DDR4 RAM bandwidth bottleneck | Upgrade to DDR5; otherwise use a smaller quant (Q4_K_S) |
| MTP draft acceptance low (<80%) | The model is doing heavy "thinking" content MTP cannot anticipate | Expected — long-output workloads still see net gain. Append `/no_think` to the system prompt to disable reasoning |
| `error: unknown argument: -mtp` | Old ik_llama.cpp build | Pull the repo and rebuild (MTP support landed mid-2026) |
| Pipeline mediator still times out | The local model is still slow on complex STIX bundles | Raise the timeout via `REACT_AGENT_TIMEOUT=600` |
| Build error: NCCL not found | NCCL is not available on Windows — the warning is normal | Ignore — NCCL is unnecessary for single-GPU setups |

## Security notes

- `llama-server` binds to `127.0.0.1` → no LAN / internet exposure.
- `models/` and `external/ik_llama.cpp/` are in `.gitignore` → they never reach the repo.
- Maljan's existing security layers (MCP allowlist, JWT, rate limit) are untouched by this setup.
