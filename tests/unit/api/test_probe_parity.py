"""Every probe the catalog can name is wired up, and nothing extra is silent.

Two things could drift apart without a test noticing: a catalog leaf naming a
``probe`` id ``PROBES`` does not have (a broken "Test" button), and
``_INPUTS["rest"]`` falling behind the ``core.sandbox.rest.*`` leaves Task 13
actually added (a probe that quietly ignores a staged field). ``mcp`` is the
one probe id with no catalog leaf of its own -- the key it addresses comes
from the ``?server=`` query parameter, not from a settings leaf -- so it, and
its two back-compat aliases, are named explicitly rather than discovered.
"""

from __future__ import annotations

from app.services.settings_catalog_api import full_catalog
from app.services.settings_probes import _INPUTS, PROBES

# ``capa``/``cape`` are one release's back-compat aliases for
# ``capa_yara``/``cape2`` (see ``PROBES``'s own comments); a stored annotation
# may still name the older id. ``mcp`` addresses one key of ``core.mcp.servers``
# rather than a catalog leaf, so no leaf's ``probe`` field ever names it.
_ALIASES = {"capa": "capa_yara", "cape": "cape2"}
_NO_CATALOG_LEAF = {"mcp"}


def test_probes_cover_every_id_the_catalog_names_and_nothing_unnamed_but_the_known_extras():
    catalog_probe_ids = {e.probe for e in full_catalog() if e.probe}
    assert set(PROBES) == catalog_probe_ids | set(_ALIASES) | _NO_CATALOG_LEAF


def test_rest_inputs_cover_the_rest_leaves_the_probe_actually_reads():
    """Every ``core.sandbox.rest.*`` leaf the mapping/status/report path uses.

    ``submit.*`` (only touched when a job actually submits, not on a
    connection test), ``status.done_values``/``status.failed_values`` and
    ``report.pcap_path`` are real Task 13 leaves that a live run needs but a
    "Test" click does not -- the REST probe checks reachability and the
    mapping, not a submission it never makes.
    """
    rest_leaves = {e.key for e in full_catalog() if e.key.startswith("core.sandbox.rest.")}
    not_probed = {
        "core.sandbox.rest.submit.method",
        "core.sandbox.rest.submit.path",
        "core.sandbox.rest.submit.file_field",
        "core.sandbox.rest.submit.task_id_path",
        "core.sandbox.rest.submit.extra_fields",
        "core.sandbox.rest.status.done_values",
        "core.sandbox.rest.status.failed_values",
        "core.sandbox.rest.report.pcap_path",
    }
    assert set(_INPUTS["rest"]) == rest_leaves - not_probed


def test_mcp_inputs_are_empty_by_design():
    """The server key comes from the route's query parameter, not a leaf."""
    assert _INPUTS["mcp"] == {}
