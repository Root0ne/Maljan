# Fuzz harnesses

Each `fuzz_*.py` here is an [atheris](https://pypi.org/project/atheris/)
harness for a reader that takes untrusted input: a sandbox report, a model's
answer, a sample's bytes. A harness states the reader's contract in its
docstring (what it may raise, and that it answers otherwise), and the fuzzer
reports any input that breaks it.

| Harness | Reader | Input it stands for |
|---|---|---|
| `fuzz_safe_json.py` | `core.safe_json.loads` / `dumps` | a sandbox report or stored ledger body |
| `fuzz_model_json.py` | `utils.json_cleaner` | the JSON in a model's answer |
| `fuzz_findings_block.py` | `agents.findings_block` | an analyst's fenced findings block |
| `fuzz_pe_image.py` | `tools.pe_image.parse` | a PE sample |
| `fuzz_documents.py` | `tools.binary.document_info`, `archive_list` | an archive, OLE2, OOXML or PDF sample |

## In CI

ClusterFuzzLite builds the harnesses from `.clusterfuzzlite/` and runs them
(`.github/workflows/cflite.yml`): a few minutes on every pull request that
touches the code, and a longer batch run every night. A crash fails the pull
request's fuzzing job and is reported with the input that reproduces it.

## Locally

```bash
uv run --with atheris python fuzz/fuzz_safe_json.py -max_total_time=60
```

Any libFuzzer flag works after the harness (`-runs=`, `-max_len=`, a corpus
directory). A crashing input is written to `crash-<sha1>` in the working
directory; rerun it with `python fuzz/fuzz_safe_json.py crash-<sha1>`.
