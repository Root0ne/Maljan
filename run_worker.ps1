$env:PYTHONPATH="src;apps/api"
uv run arq app.worker.analysis_worker.WorkerSettings
