### Fixed

- **What an installation stored under the product's previous name is read after the upgrade, never dropped (T-579).** An audit of every store found five places the rename had left unread, each now read through a fallback built from the previous-name constant:
  - A browser session opened before the upgrade is kept. A token minted under the previous default issuer and audience is accepted while the deployment keeps the shipped defaults, and still needs the same signing secret; an operator's own issuer and audience are the only ones accepted. The refresh cookie under the previous name is read when the current one is absent, and logout clears both. A reuse grace record written under the previous fingerprint label still matches its client.
  - A sample mirror directory an earlier worker created, marked with the previous marker, is still the worker's own. A previous-name marker that is not the worker's is refused, as before.
  - The orphan sweep also reads a job heartbeat written under the previous prefix, so a job an earlier worker is still running during the upgrade is not failed as abandoned.
  - On a native install, the ATT&CK cache an earlier release left under `~/.cache` is read and kept there when there is no cache under the new name and `MALSPARK_ATTCK_CACHE` is unset; the log names it. A FLOSS build the earlier installer wrote is found after the new path, and still has to be the pinned build.
  - The analysis page reads the light or dark choice a reader made before the rename when nothing is stored under the current key.
