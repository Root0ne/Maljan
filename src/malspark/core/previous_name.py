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
- the settings export format and the job package format an earlier release
  wrote, which an import and a verification still read;
- the STIX custom properties a stored bundle carries, which the bundle
  endpoint reads under the current names.

Nothing new is written under this name except where a value above must stay
what it was. ``scripts/upgrade/rename-volumes-and-env.sh`` and
``docs/upgrade-from-previous-name.md`` carry an existing deployment across.
"""

from __future__ import annotations

PREVIOUS_NAME = "maljan"
