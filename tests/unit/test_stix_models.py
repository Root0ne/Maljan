"""Tests for STIX 2.1 Pydantic models."""

from maljan.schemas.stix_models import (
    AttackPattern,
    Bundle,
    Indicator,
    Malware,
    Relationship,
)


class TestSTIXModels:
    def test_indicator_creation(self) -> None:
        indicator = Indicator(
            name="Suspicious beacon",
            pattern="[network-traffic:dst_ref.type = 'ipv4-addr']",
        )
        assert indicator.type == "indicator"
        assert indicator.id.startswith("indicator--")
        assert indicator.pattern_type == "stix"
        assert "malicious-activity" in indicator.indicator_types

    def test_malware_creation(self) -> None:
        malware = Malware(
            name="TestTrojan",
            description="A test trojan sample",
            is_family=False,
            malware_types=["trojan"],
        )
        assert malware.type == "malware"
        assert malware.id.startswith("malware--")
        assert malware.name == "TestTrojan"

    def test_relationship_creation(self) -> None:
        rel = Relationship(
            relationship_type="indicates",
            source_ref="indicator--abc",
            target_ref="malware--def",
        )
        assert rel.type == "relationship"
        assert rel.relationship_type == "indicates"

    def test_attack_pattern_creation(self) -> None:
        ap = AttackPattern(
            name="Process Injection",
            description="T1055",
            external_references=[
                {
                    "source_name": "mitre-attack",
                    "external_id": "T1055",
                    "url": "https://attack.mitre.org/techniques/T1055",
                }
            ],
        )
        assert ap.type == "attack-pattern"
        assert ap.external_references[0]["external_id"] == "T1055"

    def test_bundle_creation_with_objects(self) -> None:
        malware = Malware(name="EvilBot", malware_types=["bot"])
        indicator = Indicator(name="C2 Beacon", pattern="[ipv4-addr:value = '1.2.3.4']")
        bundle = Bundle(objects=[malware, indicator])
        assert bundle.type == "bundle"
        assert bundle.id.startswith("bundle--")
        assert len(bundle.objects) == 2

    def test_bundle_empty(self) -> None:
        bundle = Bundle(objects=[])
        assert len(bundle.objects) == 0

    def test_bundle_serialization_roundtrip(self) -> None:
        malware = Malware(name="TestMalware", malware_types=["ransomware"])
        ap = AttackPattern(name="T1027 Obfuscation")
        rel = Relationship(
            relationship_type="uses",
            source_ref=malware.id,
            target_ref=ap.id,
        )
        bundle = Bundle(objects=[malware, ap, rel])
        data = bundle.model_dump()
        assert data["type"] == "bundle"
        assert len(data["objects"]) == 3

    def test_unique_ids(self) -> None:
        m1 = Malware(name="A")
        m2 = Malware(name="B")
        assert m1.id != m2.id
