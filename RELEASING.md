# Releasing

A release is a `v*` tag on `main`. Pushing the tag runs
[`.github/workflows/release.yml`](.github/workflows/release.yml), which builds,
signs and attests everything the release ships. Nothing is published by hand.

## What a release ships

| Artefact | Where | Signed | Provenance |
|---|---|---|---|
| sdist and wheel | the GitHub release | `<file>.sigstore.json` beside each (cosign keyless) | `malspark-<tag>.intoto.jsonl` on the release, and GitHub's attestation store |
| `SHA256SUMS` | the GitHub release | through the files it lists | |
| container images `ghcr.io/root0ne/malspark-<name>` | GitHub Container Registry, tagged `<version>` and `<major>.<minor>` | cosign keyless, signature in the registry | GitHub attestation, pushed to the registry |

The images are the ones the compose stack builds: `backend`, `frontend`,
`minio`, and the tool sidecars `die-mcp`, `goresym-mcp`, `ilspy-mcp`,
`jadx-mcp`, `oletools-mcp`, `unblob-mcp`, `webcrack-mcp` and `yarax-mcp`. The
`frontend` image bakes compose's default `NEXT_PUBLIC_*` values (the API on
`localhost:8000`, authentication on); a deployment that needs other values
builds the console itself.

Every signature is keyless: the signing certificate is issued by Sigstore to
the release workflow's GitHub OIDC identity and the signature is recorded in
the Rekor transparency log. There is no signing key to hold or rotate.

## Steps

1. On `dev`, set the version in `pyproject.toml` (`[project] version`), fold
   the changelog fragments (`python scripts/changelog/fold.py`) and turn
   *Unreleased* in `CHANGELOG.md` into the version's heading with the date.
   Merge that through a pull request like any other change.
2. Promote `dev` to `main` through the promotion pull request.
3. Tag the promotion commit on `main` and push the tag:

   ```bash
   git switch main && git pull --ff-only
   git tag -a v1.2.3 -m "v1.2.3"
   git push origin v1.2.3
   ```

   With a signing key configured in git, `git tag -s` signs the tag as well.
   The workflow refuses a tag that does not name the version in
   `pyproject.toml`.
4. Wait for the Release workflow to go green. If the tag had no release yet,
   it leaves a draft release with the artefacts attached and notes generated
   from the merged pull requests.
5. Edit the draft's notes to the version's `CHANGELOG.md` section and publish
   it.
6. The first time an image name is pushed, its package on GitHub is private:
   set each `malspark-*` package to public under the account's *Packages*
   and link it to the repository.

A failed run is rerun from the Actions tab; the artefacts are replaced on the
release (`--clobber`) and the images re-pushed under the same tags. A tag that
shipped something wrong is not moved: release the fix as the next version.

## Verifying a release

The wheel or sdist against its provenance and its signature:

```bash
gh attestation verify malspark-1.2.3-py3-none-any.whl --repo Root0ne/Malspark

cosign verify-blob malspark-1.2.3-py3-none-any.whl \
  --bundle malspark-1.2.3-py3-none-any.whl.sigstore.json \
  --certificate-identity "https://github.com/Root0ne/Malspark/.github/workflows/release.yml@refs/tags/v1.2.3" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

An image:

```bash
gh attestation verify oci://ghcr.io/root0ne/malspark-backend:1.2.3 --repo Root0ne/Malspark

cosign verify ghcr.io/root0ne/malspark-backend:1.2.3 \
  --certificate-identity "https://github.com/Root0ne/Malspark/.github/workflows/release.yml@refs/tags/v1.2.3" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```
