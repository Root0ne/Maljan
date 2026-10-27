# yarax-mcp

YARA-X over MCP: the operator's own YARA rule files, matched against any file.
One tool around `yr scan`, in an image of its own with YARA-X 1.21.0
(BSD-3-Clause), the release's Linux build, checked against the release's
sha256 and the binary's own. The shared plumbing is `../cli-sidecar`.

The rules are the operator's: every `*.yar` and `*.yara` file under the
directories `YARA_X_RULES` lists (the image reads `/data/rules`, which compose
mounts read-only from `data/yara-x-rules`, or from `YARA_X_RULES_DIR`). They
are compiled on each call, so a rule file changed on the host is read by the
next call. With no rule file there, every call answers `missing_dependency`
and says where the rules go. The platform's shipped rule corpus stays with its
own `yara_scan` (the analysis sidecar): this server adds the operator's native
rule sets beside it, not a second scan of the same rules.

Shipped as the built-in server block `yarax`, switched off, reached at
`http://yarax-mcp:8093/mcp` under the compose profile `yarax`.

## Tools

| tool | arguments | answer |
| --- | --- | --- |
| `yarax_scan` | `path`, `ignore_invalid_rules=true`, `string_chars=120` | `engine`, `engine_version`, `rule_files`, `rules_not_compiled`, `matches` (one row per rule that matched: `rule`, `meta`, `tags`, `strings` with `identifier`, `offset`, `match`), `match_count` |
| `capabilities` | | the capability manifest |

`ignore_invalid_rules` skips a rule YARA-X cannot compile (a rule written for
another engine's extensions) and names it in `rules_not_compiled`; off, one
such rule fails the call. `string_chars` bounds how much of each matching
string yr prints.

The platform declares `yarax_scan` of kind `signature_rules`, its rows at
`/matches/*` with the value `rule` and each string's `offset`, and the
technique ids a rule's metadata names (`attck`, `technique_id`). Its matches
corroborate as the YARA layer, one layer with `yara_scan`'s, never a second
independent one. The triage pack's `yarax_scan` step runs it on every sample,
right after `yara_scan`.
