# ik_llama.cpp llama-server: Qwen3.6-35B-A3B-IQ3_K_R4 on RTX 5060 8 GB (38-44 tok/s output, ~15 min/sample end-to-end).
& "D:\Projects\Maljan\external\ik_llama.cpp\build\bin\Release\llama-server.exe" `
  -m "D:\Projects\Maljan\models\Qwen3.6-35B-A3B-IQ3_K_R4.gguf" `
  -ngl 99 `
  --n-cpu-moe 36 `
  -fa on `
  -c 16384 `
  -ctk q8_0 `
  --jinja `
  --alias qwen3.6-35b-a3b `
  --host 127.0.0.1 `
  --port 8080
