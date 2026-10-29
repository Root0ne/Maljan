# jadx-mcp

JADX over MCP: the classes of an Android package or dex file, and Java source
decompiled from them. Tools around JADX 1.5.6's command-line decompiler
(Apache-2.0), in an image of its own on the Eclipse Temurin 21 Java runtime,
both checked against the sha256 their releases publish. The shared plumbing is
`../cli-sidecar`.

JADX reads the dex bytecode and writes Java source; it loads no class of the
sample into a virtual machine, so nothing of the sample runs. The manifest,
permissions, components, signing certificates and dex strings of an APK stay
with the analysis server's `apk_info` (androguard): this server adds the code,
not a second reading of the manifest.

What JADX is handed is held to that. The file is given to it under a name of
this server's choosing, `input.apk` or `input.dex` by the file's own first
bytes (a link in the call's scratch directory), so no name an uploader wrote
picks which of JADX's inputs reads it. Every input plugin but the dex reader is
switched off (no smali assembler, no Java class, XAPK, APKS, APKM or AAB
loader, no mapping file), no configuration file is read, resources are not
decoded, and a dex file whose checksum does not match is read as it is. Its
temporary files and home are the call's scratch directory, and it writes no
comment of its own into the code (none names the scratch path), so one file
answers the same each time. Its heap is half the container's memory and its
`/tmp` a tmpfs sized below the rest (`JADX_TMPFS_SIZE`, 1536m, beside
`JADX_MEM_LIMIT` 4g).

Shipped as the built-in server block `jadx`, switched off, reached at
`http://jadx-mcp:8097/mcp` under the compose profile `jadx`, and offered to the
Android static analyst and the reverser.

## Tools

Every tool takes `path`.

| tool | arguments | answer |
| --- | --- | --- |
| `android_classes` | `package=""` | `classes` (`name`, `inner`, `field_count`, `methods` with `name`, `signature`, `dex_offset`; `alias` where JADX renamed the class), `class_count`, `decompilation_errors` |
| `android_decompile_class` | `class_name` | `language`, `class_name`, `source`, `decompilation_errors` |
| `capabilities` | | the capability manifest |

`package` keeps the classes under one package (`com.example.app`).
`android_classes` decompiles the whole package to index it, so a large APK
takes a while; `android_decompile_class` decompiles the one class (and its inner
classes). `decompilation_errors` is how many places JADX said it could not
decompile; the code carries its comment there. The triage pack takes
`android_classes` as a step by its kind (`type_list`), on an APK or dex
sample, the formats it declares.
