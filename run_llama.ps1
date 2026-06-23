# ik_llama.cpp llama-server: Qwen3.6-35B-A3B-IQ3_K_R4 on RTX 5060 8 GB (38-44 tok/s output, ~15 min/sample end-to-end).
#
# CLIENT NOTE (2026-06-23 live-UI audit): the Maljan client MUST set
# LLM__OPENAI__DISABLE_THINKING=true (see .env.example). With Qwen3 thinking ON,
# each analyst LLM call emits a ~22k-token reasoning trace that never reaches
# `content`, so the tool-less dynamic/network analysts time out at their hard
# cap and the static Ghidra ReAct loop stalls -> degraded, zero-confidence
# reports. This server launch is unaffected; the toggle is forwarded per
# request as chat_template_kwargs.enable_thinking=false.
#
# Wave 10 W10-LLM-05 (2026-05-30): context window bumped 16384 -> 32768.
# 2026-05-31: 32768 -> 131072 -> 262144 (the model's native max).
#
# KV-cache (MEASURED at boot, 2026-05-31, -ctk q8_0 -ctv q8_0 -fa on):
#   - ~10.85 KiB/token, both caches (128k measured at 1422.82 MiB on CUDA0).
#     262144 -> ~2.78 GiB KV, GPU-resident, next to the ~2.5 GiB of resident
#     weight tensors. The bulk of the model (~12.1 GiB of MoE experts) sits in
#     PINNED HOST RAM via --n-cpu-moe 36, so context size barely moves system
#     RAM -- the RAM cost is the weight offload, NOT the KV cache. (An earlier
#     "262k = OOM" note was wrong: KV had been over-estimated ~4x.)
#   - Observed at idle (128k): llama-server working set ~12.7 GiB; ~5.0 GiB free
#     of 31 GiB. 262k adds only ~1.4 GiB more KV (on the GPU, not host RAM).
#     The real pressure during analysis is the Dockerized Ghidra container
#     competing for the remaining host headroom -- NOT the KV cache. Watch
#     FreePhysicalMemory on very large binaries; cap the WSL2 VM via .wslconfig
#     (memory=...) so Ghidra cannot starve llama-server.
#   - -ctv q8_0 (added 2026-05-31, was K-only) halves the V-cache vs f16.
#     Requires -fa (already on).
#   - 262144 is the GGUF native max (n_ctx_train). Our prompts (tool schemas +
#     decompiled code + ReAct) never approach it; the headroom just removes the
#     "context shift is disabled" 500s on the largest binaries. Trade-off: a
#     bigger -c only lengthens worst-case prefill, never idle cost.
# If the operator runs llama-server on a smaller card, drop -c back to 131072 /
# 32768 / 16384 and adjust react.max_iterations downstream instead.
#
# Launch check: some ik_llama builds reject a quantized V-cache.
# 2026-06-21: dropped `-ctv q8_0` and lowered `-c` 262144 -> 131072 for runtime
# STABILITY. During the family-RAG A/B the server kept wedging (GPU idle, HTTP
# unresponsive) roughly every 7-10 min under sustained load; ~9 watchdog restarts
# in two hours, ~4x throughput loss. The quantized V-cache + 256k context were
# the suspect; f16 V-cache at 131k has run stably since. To squeeze idle VRAM
# back, re-add `-ctv q8_0` and/or raise `-c`, but re-validate stability first.
& "D:\Projects\Maljan\external\ik_llama.cpp\build\bin\Release\llama-server.exe" `
  -m "D:\Projects\Maljan\models\Qwen3.6-35B-A3B-IQ3_K_R4.gguf" `
  -ngl 99 `
  --n-cpu-moe 36 `
  -fa on `
  -c 131072 `
  -ctk q8_0 `
  --jinja `
  --alias qwen3.6-35b-a3b `
  --host 127.0.0.1 `
  --port 8080
