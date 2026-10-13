"""A composite settings map whose entries each carry one credential, stored apart.

A composite catalog leaf (a map of named entries) is stored as one
*non-secret* JSONB row, so a credential left inside an entry would sit in the
database in clear text beside values the UI echoes back. The credential is
therefore split out on the way in and folded back on the way out:
:meth:`NestedSecretMap.split` returns the map to store and the credentials to
encrypt, ``SettingsService.save`` writes one ``is_secret`` row per entry, and
:meth:`NestedSecretMap.merge` puts them back when the effective overrides are
assembled. The composite row never holds a credential; what an operator sees
is always the mask (:meth:`NestedSecretMap.masked`), and the mask coming back
in an unchanged edit means "unchanged" rather than a credential whose literal
characters are ten asterisks.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.services.server_map import TOKEN_MASK


@dataclass(frozen=True)
class NestedSecretMap:
    """One composite leaf (``key``) whose entries each hold a credential under ``field``."""

    key: str
    field: str

    @property
    def suffix(self) -> str:
        return f".{self.field}"

    def row_key(self, name: str) -> str:
        """The settings key one entry's credential is stored under.

        Shaped like a catalog key without being one: the catalog is a static
        list and cannot contain a name an operator invents at runtime, so
        ``SettingsService`` writes these rows itself rather than through
        ``check_keys``. Nothing else in the system may write a key of this shape.
        """
        return f"{self.key}.{name}{self.suffix}"

    def split(
        self, value: Any, *, stored: dict[str, Any] | None = None
    ) -> tuple[Any, dict[str, str | None]]:
        """Separate the per-entry credentials from the map that gets stored.

        The second element is an *instruction set*, not a state: an entry
        appears in it only when something has to happen to its row. A
        non-empty string means "store this"; ``None`` (from an explicit
        ``null`` or an empty string) means "delete the row"; the mask means
        "leave it alone", and so does an entry that never mentions the field.

        ``stored`` is the map as it stands (the effective one, with any
        encrypted row already merged back in). It exists for one rule: the
        composite must never lose a credential that was never stored anywhere
        else. A credential still sitting in the composite in clear, which an
        import document omitting the field would otherwise strip on the way
        past, is carried into the instruction set instead, so the save writes
        the encrypted row the strip assumes exists.
        """
        if not isinstance(value, dict):
            return value, {}
        cleaned: dict[str, Any] = {}
        secrets: dict[str, str | None] = {}
        for name, entry in value.items():
            if not isinstance(entry, dict):
                cleaned[name] = entry
                continue
            cleaned[name] = {k: v for k, v in entry.items() if k != self.field}
            secret = entry.get(self.field)
            if self.field not in entry or secret == TOKEN_MASK:
                carried = self._stored_secret(stored, name)
                if carried is not None:
                    secrets[str(name)] = carried
                continue
            secrets[str(name)] = str(secret) if secret else None
        return cleaned, secrets

    def _stored_secret(self, stored: dict[str, Any] | None, name: str) -> str | None:
        entry = (stored or {}).get(name)
        if not isinstance(entry, dict):
            return None
        secret = entry.get(self.field)
        if isinstance(secret, str) and secret and secret != TOKEN_MASK:
            return secret
        return None

    def merge(self, overrides: dict[str, Any]) -> dict[str, Any]:
        """Fold the per-entry credential rows back into the map, and drop them.

        Done here rather than by letting both key shapes reach ``nest()``: that
        function walks a flat mapping in iteration order, so the composite
        arriving after one of its credential rows would overwrite the
        credential instead of merging with it. Making the merge explicit makes
        it order-independent.
        """
        prefix = f"{self.key}."
        rows = [k for k in overrides if k.startswith(prefix) and k.endswith(self.suffix)]
        out = {k: v for k, v in overrides.items() if k not in rows}
        composite = out.get(self.key)
        if not isinstance(composite, dict):
            return out
        merged = {name: dict(entry) for name, entry in composite.items() if isinstance(entry, dict)}
        # A mask carried inside the composite is a placeholder, never a credential.
        for entry in merged.values():
            if entry.get(self.field) == TOKEN_MASK:
                entry.pop(self.field, None)
        for key in rows:
            name = key[len(prefix) : -len(self.suffix)]
            if name in merged:
                merged[name][self.field] = overrides[key]
            # A row whose entry is gone is simply dropped: ``save`` deletes
            # these, and a stale one must never resurrect an entry.
        out[self.key] = merged
        return out

    def masked(self, stored_map: dict[str, Any], rows: dict[str, Any]) -> dict[str, Any]:
        """The map as the UI may see it: every credential a mask, never a value."""
        out: dict[str, Any] = {}
        for name, entry in stored_map.items():
            if not isinstance(entry, dict):
                out[name] = entry
                continue
            shown = {k: v for k, v in entry.items() if k != self.field}
            shown[self.field] = TOKEN_MASK if self.row_key(name) in rows else None
            out[name] = shown
        return out
