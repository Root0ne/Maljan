# The paper

The published evaluation was produced from the git tag `paper-2026-09`. The
evaluation harness, the corpus fixtures and the paper scripts live at that tag
under `tests/evaluation/` and `scripts/paper/`, together with the CI gate, the
byte-identity prompt goldens and the `make paper` targets that kept them
reproducible; check the tag out to re-run any of it. The current line no longer
carries them, because the architecture is moving to tool-driven agents and the
byte-for-byte pins on the paper's default profile would hold that move back. The
citation still stands on the tagged tree, not on `main`.
