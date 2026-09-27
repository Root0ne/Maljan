"""A sandbox URL whose host is an address answers as that address does.

The sandbox saw a request to ``http://<address>/gate.php``, and the address's
row said the sandbox did not attribute the flow to the sample's process tree,
or that the address is a public DNS resolver. The address was refused and the
URL on it published — into STIX, ``/iocs`` and the YARA and Suricata drafts.
The URL now takes its address's facts: an unattributed address's URL waits for
the judge, and a resolver's URL is never published.

The addresses are routable ones the reference run never reached; a
documentation address is refused by the address rule before attribution is
asked.
"""

from __future__ import annotations

from typing import Any

from maljan.reporting.builder import build_consolidated_iocs
from maljan.reporting.detection_signatures import build_detection_rules
from maljan.reporting.models import (
    FileHashes,
    MalwareReport,
    NetworkIOCs,
    NetworkIP,
    NetworkURL,
    SampleIdentity,
)
from maljan.reporting.renderers.stix_renderer import (
    ExtendedSTIXRenderer,
    emulation_kwargs,
    indicator_publish_reason,
)
from maljan.schemas.stix_models import Bundle

CONTACT = "185.199.111.20"
RESOLVER = "9.9.9.9"


def _report(address: str, url: str, tree: bool | None) -> MalwareReport:
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        malware_category="loader",
        overall_confidence=0.9,
        network=NetworkIOCs(
            ips=[
                NetworkIP(
                    address=address,
                    source="sandbox",
                    sample_process_tree=tree,
                    public_resolver=address == RESOLVER,
                )
            ],
            urls=[NetworkURL(url=url, source="sandbox")],
        ),
    )
    exported = ExtendedSTIXRenderer().render(report, Bundle.model_validate({"objects": []}))
    report.stix_bundle_extended = exported.model_dump(mode="json")
    report.consolidated_iocs = build_consolidated_iocs(report)
    return report


def _surfaces(report: MalwareReport, url: str) -> dict[str, Any]:
    (row,) = [r for r in report.consolidated_iocs if r.value == url]
    rules = build_detection_rules(report)
    return {
        "table": row.published,
        "feed": indicator_publish_reason(
            "url", url, "sandbox", None, **emulation_kwargs(report, "url", url)
        ),
        "stix": url in str(report.stix_bundle_extended),
        "yara": any(url in rule.body for rule in rules if rule.kind == "yara"),
        "suricata": any(url in rule.body for rule in rules if rule.kind == "suricata"),
    }


class TestAnUnattributedAddress:
    URL = f"http://{CONTACT}/gate.php"

    def test_its_url_is_refused_everywhere_with_the_address_s_reason(self) -> None:
        said = _surfaces(_report(CONTACT, self.URL, False), self.URL)

        assert said["table"].startswith(
            "no: the sandbox report attributes its flows to a process outside"
        )
        assert said["feed"] is None
        assert not (said["stix"] or said["yara"] or said["suricata"])

    def test_an_attributed_address_s_url_is_published(self) -> None:
        said = _surfaces(_report(CONTACT, self.URL, True), self.URL)

        assert said["table"] == "yes"
        assert said["feed"] is not None
        assert said["stix"]


class TestAPublicResolver:
    URL = f"https://{RESOLVER}/dns-query"

    def test_its_url_is_never_published(self) -> None:
        said = _surfaces(_report(RESOLVER, self.URL, True), self.URL)

        assert said["table"].startswith("no: ")
        assert "public DNS resolver" in said["table"]
        assert said["feed"] is None
        assert not (said["stix"] or said["yara"] or said["suricata"])
