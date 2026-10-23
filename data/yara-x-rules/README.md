# yara-x-rules

The operator's own YARA rule files for the YARA-X sidecar (`yarax-mcp`,
compose profile `yarax`), which mounts this directory read-only at
`/data/rules` (or the directory `YARA_X_RULES_DIR` names instead). Every
`*.yar` and `*.yara` file here, in any subdirectory, is compiled and matched
on each `yarax_scan` call; nothing else here is read. None is shipped: with no
rule file here, the sidecar's tool answers `missing_dependency` and says so.

The platform's own rule corpus (`data/yara_ttp_rules.yaml`) is not read here;
it stays with the analysis sidecar's `yara_scan`.
