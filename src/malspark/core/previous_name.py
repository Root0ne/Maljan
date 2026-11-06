"""The name the product had before it was Malspark, where data written under it is still read.

The rename (T-576) changed every name an operator sees. A few values could not
change with it, because data an earlier release wrote is bound to them; each
is built from :data:`PREVIOUS_NAME` here, so the old name is spelt in one place
and ``tests/unit/test_no_previous_name_remains.py`` holds every other tracked
file to the new one:

- the domain tags and HKDF purpose labels of the hash chains and signatures
  (``app.services.audit_chain``, ``app.services.ledger_chain``,
  ``app.services.job_package``): a stored chain, seal or package verifies only
  under the tag it was written with;
- the capture directory an earlier release wrote
  (``malspark.tools.staging.LEGACY_CAPTURE_DIR_NAME``), which the sweep still
  reaches;
- every versioned format and schema label an earlier release wrote
  (``<name>-settings/3``, ``<name>-job-package/2``, ``<name>-evidence-bundle/1``,
  a data file's ``<name>-.../v1``): a reader takes it as the same version under
  the current name (:func:`under_current_name`), and a writer writes the
  current name;
- the job package signature key label an earlier release signed under, which
  a verification still derives beside the current one;
- the identifiers other stores already hold: the namespace of each MISP
  attribute's uuid (``malspark.reporting.misp``), the STIX producer identity's
  id (``stix_renderer.PRODUCER_IDENTITY_ID``) and the prefix of the settings
  repair markers (``app.services.settings_service.MARKER_PREFIX``);
- the tag of an analyst's findings block and the custom properties of a judge
  answer stored before the rename, which a replay still reads;
- the STIX custom properties a stored bundle carries, which the bundle
  endpoint reads under the current names.

Nothing new is written under this name except where a value above must stay
what it was. ``scripts/upgrade/rename-volumes-and-env.sh`` and
``docs/upgrade-from-previous-name.md`` carry an existing deployment across.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from typing import Any

PREVIOUS_NAME = "maljan"
CURRENT_NAME = "malspark"

_PREVIOUS_PREFIX = f"{PREVIOUS_NAME}-"
_CURRENT_PREFIX = f"{CURRENT_NAME}-"


def under_current_name(label: object) -> object:
    """A format or schema label an earlier release wrote, as that version under the current name.

    ``<previous>-settings/3`` reads as ``malspark-settings/3``; a label under the
    current name, any other string and a non-string are returned as they are,
    so a reader compares the result with its own constants and refuses what
    it refused before.
    """
    if isinstance(label, str) and label.startswith(_PREVIOUS_PREFIX):
        return _CURRENT_PREFIX + label[len(_PREVIOUS_PREFIX) :]
    return label


def previous_group(group: str) -> str | None:
    """The entry-point group ``group`` was named before the rename; ``None`` for no such.

    ``malspark.memory_backends`` was ``<previous>.memory_backends``: a plugin
    package built before the rename still declares itself there.
    """
    prefix = f"{CURRENT_NAME}."
    return f"{PREVIOUS_NAME}.{group[len(prefix) :]}" if group.startswith(prefix) else None


def previous_environment_names(environ: Mapping[str, str] | None = None) -> list[str]:
    """The names of the environment variables set under the previous prefix, sorted.

    Nothing reads them any more: each moved to ``MALSPARK_`` with the rename.
    Only names are returned, never a value.
    """
    prefix = f"{PREVIOUS_NAME.upper()}_"
    return sorted(
        name for name in (os.environ if environ is None else environ) if name.startswith(prefix)
    )


def warn_previous_environment(
    log: Any = None, environ: Mapping[str, str] | None = None
) -> list[str]:
    """Warn, once at start, of every variable still set under the previous prefix, by name.

    The API, the worker and the sidecars that import the platform call it as
    they start. A variable set outside ``docker/.env`` (a shell profile, a unit
    file) that the upgrade script could not rename is otherwise silently not
    read. The value is never logged.
    """
    names = previous_environment_names(environ)
    if names:
        log = logging.getLogger(CURRENT_NAME) if log is None else log
        current = f"{CURRENT_NAME.upper()}_"
        log.warning(
            "Environment variables under the product's previous name are set and not read: "
            "%s. Rename each to its %s name.",
            ", ".join(names),
            current,
        )
    return names
