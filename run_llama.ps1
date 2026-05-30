# ik_llama.cpp llama-server: Qwen3.6-35B-A3B-IQ3_K_R4 on RTX 5060 8 GB (38-44 tok/s output, ~15 min/sample end-to-end).
#
# Wave 10 W10-LLM-05 (2026-05-30): context window bumped 16384 -> 32768.
# The 2026-05-30 ELF + APK smoke runs (jobs f4a1fee9, 37d9c976) both
# tripped the static analyst's ReAct loop with HTTP 500
# "context shift is disabled" -- the 16k ceiling could not hold the
# Ghidra MCP tool schemas (12 tools) plus a 5-round ReAct conversation.
# At -c 32768 + -ctk q8_0 the KV cache grows by ~64 MiB, which still
# fits inside the RTX 5060's 8 GiB budget alongside the IQ3_K_R4 weights
# (~7 GiB resident with --n-cpu-moe 36 offload). If the operator runs
# llama-server on a smaller card, drop -c back to 16384 and adjust
# react.max_iterations downstream instead.
& "D:\Projects\Maljan\external\ik_llama.cpp\build\bin\Release\llama-server.exe" `
  -m "D:\Projects\Maljan\models\Qwen3.6-35B-A3B-IQ3_K_R4.gguf" `
  -ngl 99 `
  --n-cpu-moe 36 `
  -fa on `
  -c 32768 `
  -ctk q8_0 `
  --jinja `
  --alias qwen3.6-35b-a3b `
  --host 127.0.0.1 `
  --port 8080
