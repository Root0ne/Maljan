# webcrack-mcp

webcrack over MCP: a JavaScript dropper unminified, unpacked and deobfuscated,
never run. One tool around `deobfuscate.mjs`, which hands the file to webcrack
2.16.0 (MIT) on Node.js 22, in an image of its own: Node.js is the release's
Linux build checked against its published sha256, and webcrack and every
package it needs are pinned by integrity hash (`package-lock.json`) and
installed with `npm ci --ignore-scripts`. The shared plumbing is
`../cli-sidecar`.

webcrack parses the script and rewrites its syntax tree. It would evaluate an
obfuscator's string-decoder functions in a sandbox it is handed; none is
handed (and the sandbox's module is removed from the image), so nothing of the
script runs and those decoder calls stay as written. webcrack unflattens
control flow and removes dead code only within that step, so a script guarded
by an obfuscator-style string array keeps both as they are.

A JavaScript file is read whole. A file that opens with markup (an HTA, a
Windows Script File) is read for its `<script>` blocks: each block in
JavaScript or JScript is rewritten, and a block in another language (VBScript)
is listed as it is. A script encoded with JScript.Encode (`#@~^`), or one
webcrack cannot parse as JavaScript, is left unread on its row (`error`); the
call answers `unsupported_format` only when no script was read. Each row's
`start` and `end` are byte offsets of its text in the file.

Shipped as the built-in server block `webcrack`, switched off, reached at
`http://webcrack-mcp:8095/mcp` under the compose profile `webcrack`.

## Tools

| tool | arguments | answer |
| --- | --- | --- |
| `js_deobfuscate` | `path`, `deobfuscate=true`, `unminify=true`, `unpack=true`, `mangle=false` | `scripts` (one row per script: `index`, `language`, `start`, `end`, `deobfuscated`, `changed`, `code`, `bundle` with its `modules`, or `error`), `script_count`, `deobfuscated_count` |
| `capabilities` | | the capability manifest |

The platform declares `js_deobfuscate` of kind `deobfuscated_script`, its rows
at `/scripts/*`. The triage pack's `js_deobfuscate` step runs it on a sample
the router gave the format `js`, `hta` or `wsf`.
