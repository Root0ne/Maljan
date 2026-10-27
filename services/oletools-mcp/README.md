# oletools-mcp

oletools over MCP: the VBA and XLM macros, indicators, embedded objects and
DDE links of Office and RTF documents. Five tools, each one report of
`ole_report.py` over oletools 0.60.2 (BSD-2-Clause), in an image of its own
whose Python packages are pinned by hash (`requirements.txt`). The shared
plumbing is `../cli-sidecar`: each report runs as a program of its own, in a
process group of its own and under `TOOL_TIMEOUT_SECONDS`.

oletools reads the document. No macro runs: olevba decompresses and scans the
VBA source as text, MacroRaptor matches keywords in it, and the XLM emulator
olevba would call where it is installed is neither installed nor allowed
(Excel 4 macro sheets are read by olevba's own BIFF parser). A document
encrypted with one of Office's default passwords is decrypted in memory for
`ole_vba` and `ole_macro_risk`; nothing is written to disk.

Shipped as the built-in server block `oletools`, switched off, reached at
`http://oletools-mcp:8094/mcp` under the compose profile `oletools`.

## Tools

Every tool takes `path`.

| tool | arguments | answer |
| --- | --- | --- |
| `ole_vba` | `deobfuscate=false` | `container_type`, `encrypted`, `has_vba`, `has_xlm`, `vba_stomping`, `macros` (`container`, `stream`, `module`, `source`), `xlm_macros`, `indicators` (`type`, `keyword`, `description`) and their counts |
| `ole_macro_risk` | | `has_vba`, `suspicious`, `flags` (`AWX`), `autoexec`, `write`, `execute`, `matches` (`flag`, `keyword`) |
| `ole_indicators` | | `indicators` (`id`, `name`, `value`, `risk`, `description`), `indicator_count` |
| `rtf_objects` | | `objects` (`index`, `start`, `end`, `is_ole`, `format_id`, `class_name`, `data_size`, `is_package`, `filename`, `source_path`, `temp_path`, `clsid`, `clsid_description`, `payload_sha256`), `object_count` |
| `office_dde` | `field_filter=exclude_blacklisted` | `encrypted`, `links` (`text`), `link_count` |
| `capabilities` | | the capability manifest |

`ole_vba` on an RTF, and `rtf_objects` on anything but RTF, answer
`unsupported_format`. The triage pack runs `ole_vba` on an OLE or OOXML
sample, `office_dde` on an OLE, OOXML or RTF sample and `rtf_objects` on an
RTF sample, each by the format the router gave it.
