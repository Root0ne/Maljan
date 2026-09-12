# knowledge-mcp

Reference lookups over stdio MCP: MITRE ATT&CK, the API-behaviour catalog, the
LOLBin table, and retrieval over the vendored family fingerprints and prior
cases. Delegates to `maljan.tools.knowledge`.

Launched by `maljan.core.config._builtin_servers()` as the `knowledge` server —
`sys.executable services/knowledge-mcp/server.py`, cwd `services/knowledge-mcp`,
no environment variables passed through. It is registered with `agents: []` and
reaches every built-in analyst and the judge through the `ToolRef`s in their
definitions, so the definition's tool list is the only binding.

## Tools

| tool | arguments |
| --- | --- |
| `resolve_technique` | `text`, `k=5`, `domain=""` |
| `attck_lookup` | `technique_id` |
| `attck_validate` | `ids` |
| `api_capability` | `api_names` |
| `lolbin_lookup` | `command_lines` |
| `family_lookup` | `query`, `k=5` |
| `similar_cases` | `text`, `k=5` |

`resolve_technique` reports two numbers per candidate. `score` is the semantic
ranking, which orders candidates well but crowds every value near 0.7 whether
the match is right or not; `score_gate` is the TF-IDF alignment, which ranks
worse but scores near zero for unrelated evidence — threshold on `score_gate`.

## Indices and degradation

Indices are built on the first call that needs them and kept warm for the
process lifetime: the ATT&CK bundle is tens of megabytes and the embedding
model takes seconds to load.

`family_lookup` and `similar_cases` need the embedding model and a vendored
catalog (`data/family_fingerprints_v1.json`, `data/attck_case_corpus_v1.json`).
Without either they answer an empty list and a `reason` — never an error the
caller has to interpret, and never an exception.
