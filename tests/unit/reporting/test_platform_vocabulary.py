"""One vocabulary, agreed on by every table that reads it.

Five tables have to name the same platforms — the file-type map that emits
them, the MITRE translation, the Sigma product set, the FP linter's
incompatible terms, and the web's labels. Nothing checked that they agreed, so
a platform added to one and forgotten in another would silently strip rules or
render a bare slug.
"""

from __future__ import annotations

import re
from pathlib import Path

from maljan.analysis.sigma_layer import _OS_PRODUCTS
from maljan.extractors.sample_identity import PLATFORM_BY_FILE_TYPE
from maljan.memory.attck_loader import MITRE_PLATFORM_MAP
from maljan.qa.fp_linter import _PLATFORM_INCOMPATIBLE_TERMS
from maljan.reporting.models import KNOWN_PLATFORMS

_WEB_TYPES = (
    Path(__file__).resolve().parents[3] / "apps" / "web" / "src" / "types" / "malware-report.ts"
)


def test_the_vocabulary_itself_is_what_the_docs_promise() -> None:
    assert KNOWN_PLATFORMS == (
        "windows",
        "linux",
        "macos",
        "android",
        "ios",
        "multi",
        "unknown",
    )


def test_every_file_type_maps_to_a_known_platform() -> None:
    assert set(PLATFORM_BY_FILE_TYPE.values()) <= set(KNOWN_PLATFORMS)


def test_the_mitre_translation_covers_the_whole_vocabulary() -> None:
    assert set(MITRE_PLATFORM_MAP) == set(KNOWN_PLATFORMS)


def test_the_sigma_product_set_is_the_single_os_platforms() -> None:
    # "multi" and "unknown" are not products a Sigma rule declares.
    assert _OS_PRODUCTS == set(KNOWN_PLATFORMS) - {"multi", "unknown"}


def test_the_fp_linter_knows_only_platforms_from_the_vocabulary() -> None:
    assert set(_PLATFORM_INCOMPATIBLE_TERMS) <= set(KNOWN_PLATFORMS)


def test_the_web_labels_every_platform_the_backend_emits() -> None:
    source = _WEB_TYPES.read_text(encoding="utf-8")
    block = source.split("PLATFORM_LABELS: Record<string, string> = {", 1)[1].split("};", 1)[0]
    labelled = set(re.findall(r"^\s*(\w+):", block, re.MULTILINE))
    assert labelled == set(KNOWN_PLATFORMS), (
        "the web PLATFORM_LABELS record and KNOWN_PLATFORMS have drifted apart; "
        f"labelled={sorted(labelled)} known={sorted(KNOWN_PLATFORMS)}"
    )
