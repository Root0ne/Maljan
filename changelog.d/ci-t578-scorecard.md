### Added

- **The readers of untrusted input are fuzzed.** Atheris harnesses under `fuzz/` cover the sandbox-report JSON reader, the reader that takes JSON out of a model's answer, the analyst findings block, the PE reader and the archive and document readers. ClusterFuzzLite builds them from `.clusterfuzzlite/` and runs them for five minutes on every pull request that touches the code, and for an hour every night.
- **Releases are built, signed and attested by a workflow.** A pushed `v*` tag builds the sdist and the wheel and the compose stack's images, pushes the images to `ghcr.io/root0ne/malspark-*`, signs every artefact with cosign keyless, attests its SLSA build provenance, and attaches the Python artefacts, their signatures, a `SHA256SUMS` and the provenance to the tag's GitHub release. `RELEASING.md` describes the process and how to verify a release.

### Documentation

- **An answer sheet for the OpenSSF Best Practices passing badge.** `docs/bestpractices-answers.md` gives, for each passing criterion, the answer that is true of the repository today, the justification and the evidence URL, and says what is still missing where the answer is not Met.
