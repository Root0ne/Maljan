"""Tests for Parser implementations (unchanged imports)."""

from maljan.parsers.dynamic_parser import DynamicParser
from maljan.parsers.network_parser import NetworkParser
from maljan.parsers.static_parser import StaticParser


class TestStaticParser:
    """Tests for the StaticParser refinement engine."""

    def setup_method(self) -> None:
        self.parser = StaticParser()

    def test_valid_static_data(self) -> None:
        data = [
            {
                "file": "test.exe",
                "decompiled_summary": "CryptAcquireContext, CreateRemoteThread found.",
                "strings": ["http://evil.com/c2", "Software\\Microsoft\\Windows\\Run"],
                "pe_header": {
                    "entry_point": "0x401000",
                    "sections": [".text", ".rdata"],
                },
            }
        ]
        result = self.parser.parse(data)
        assert "test.exe" in result
        assert "0x401000" in result
        assert "http://evil.com/c2" in result

    def test_empty_list_returns_invalid(self) -> None:
        result = self.parser.parse([])
        assert "Invalid" in result

    def test_non_list_returns_invalid(self) -> None:
        result = self.parser.parse({"unexpected": True})
        assert "Invalid" in result

    def test_missing_fields_handled_gracefully(self) -> None:
        data = [{"file": "minimal.exe"}]
        result = self.parser.parse(data)
        assert "minimal.exe" in result
        assert "N/A" in result


class TestDynamicParser:
    """Tests for the DynamicParser refinement engine."""

    def setup_method(self) -> None:
        self.parser = DynamicParser()

    def test_valid_sandbox_data(self) -> None:
        data = {
            "behavior": {
                "generic": [
                    {"category": "persistence", "description": "Sets Run key."},
                    {"category": "evasion", "description": "Injects into explorer.exe."},
                ],
                "apistats": {
                    "1234": {
                        "RegSetValueExW": 3,
                        "CreateRemoteThread": 1,
                        "NtReadFile": 100,
                    }
                },
            }
        }
        result = self.parser.parse(data)
        assert "persistence" in result.lower()
        assert "RegSetValueExW" in result
        assert "CreateRemoteThread" in result
        assert "NtReadFile" not in result

    def test_the_observation_is_reported_without_a_severity_of_its_own(self) -> None:
        """A keyword table in a formatter deciding what is "HIGH" was a verdict
        the analyst then read back as evidence."""
        data = {
            "behavior": {
                "generic": [{"category": "injection", "description": "Code injection detected."}],
                "apistats": {},
            }
        }
        result = self.parser.parse(data)
        assert "Code injection detected." in result
        assert "HIGH" not in result
        assert "Severity" not in result

    def test_invalid_data_returns_message(self) -> None:
        result = self.parser.parse("not_a_dict")
        assert "Invalid" in result

    def test_notable_api_filter(self) -> None:
        parser = DynamicParser()
        assert parser._is_notable_api("CreateRemoteThread") is True
        assert parser._is_notable_api("WriteProcessMemory") is True
        assert parser._is_notable_api("NtReadFile") is False
        assert parser._is_notable_api("GetProcAddress") is False

    # --- Network indicators tests (Phase 2) ---

    def test_network_indicators_in_output(self) -> None:
        """DynamicParser should include network indicators from sandbox report."""
        data = {
            "behavior": {
                "generic": [{"category": "network", "description": "C2 communication"}],
                "apistats": {"1234": {"HttpSendRequest": 5}},
            },
            "network": {
                "dns": [{"request": "evil-c2.com"}],
                "http": [{"host": "evil-c2.com", "uri": "/cmd", "status": 200}],
                "tcp": [{"dst": "185.220.101.5", "dport": 443}],
                "hosts": ["185.220.101.5"],
                "domains": ["evil-c2.com"],
            },
        }
        result = self.parser.parse(data)
        assert "Network Indicators" in result
        assert "evil-c2.com" in result
        assert "185.220.101.5" in result
        assert "443" in result

    def test_network_indicators_empty(self) -> None:
        """An empty sandbox report is stated as an observation, not as a table.

        What it means — evasion, a platform mismatch, an empty file — is the
        analyst's reading. The parser naming a technique here would be this
        formatter deciding the finding.
        """
        data = {
            "behavior": {"generic": [], "apistats": {}},
            "network": {},
        }
        result = self.parser.parse(data)
        assert "SANDBOX COMPLETED WITH ZERO OBSERVED EVENTS" in result
        assert "T1497" not in result


class TestNetworkParser:
    """Tests for the NetworkParser refinement engine."""

    def setup_method(self) -> None:
        self.parser = NetworkParser()

    def test_valid_network_data(self) -> None:
        data = [
            {
                "service": "dns",
                "id.resp_h": "8.8.8.8",
                "id.resp_p": 53,
                "query": "malware-c2.example",
            },
            {
                "service": "ssl",
                "id.resp_h": "185.199.110.153",
                "id.resp_p": 443,
                "resp_bytes": 1024,
            },
        ]
        result = self.parser.parse(data)
        assert "malware-c2.example" in result
        assert "185.199.110.153" in result

    def test_the_query_is_listed_without_a_verdict_beside_it(self) -> None:
        """The parser formats. Whether a domain looks generated is a finding,
        and the report's own network block carries it, scored once."""
        data = [
            {
                "service": "dns",
                "id.resp_h": "9.9.9.9",
                "id.resp_p": 53,
                "query": "kq3x9zjptlvbq.top",
            }
        ]
        result = self.parser.parse(data)
        assert "kq3x9zjptlvbq.top" in result
        assert "Suspicious" not in result

    def test_invalid_data_returns_message(self) -> None:
        result = self.parser.parse("not a dict or list")
        assert "Invalid" in result

    def test_dict_parsed_as_sandbox(self) -> None:
        """Dict input maps to the CAPEv2-style sandbox network parser."""
        result = self.parser.parse({"not": "a list"})
        assert "Network Traffic Intelligence (Sandbox)" in result

    def test_empty_list_handled(self) -> None:
        result = self.parser.parse([])
        assert "No significant events" in result

    # --- Sandbox dict format tests (CAPEv2 / dict shape) ---

    def test_sandbox_network_format(self) -> None:
        """NetworkParser should support the CAPEv2 sandbox dict shape."""
        data = {
            "dns": [
                {"request": "evil-c2.com", "answers": ["185.220.101.5"]},
                {"request": "google.com", "answers": ["8.8.8.8"]},
            ],
            "http": [
                {"host": "evil-c2.com", "uri": "/cmd", "method": "POST", "status": 200},
            ],
            "tcp": [
                {"dst": "185.220.101.5", "dport": 443, "src": "10.0.0.5"},
            ],
            "hosts": ["185.220.101.5", "8.8.8.8"],
            "domains": ["evil-c2.com", "google.com"],
        }
        result = self.parser.parse(data)
        assert "Network Traffic Intelligence (Sandbox)" in result
        assert "evil-c2.com" in result
        assert "185.220.101.5" in result
        assert "POST /cmd" in result
        assert "443" in result

    def test_sandbox_network_empty(self) -> None:
        """Sandbox dict with empty fields should not crash."""
        data = {"dns": [], "http": [], "tcp": [], "hosts": [], "domains": []}
        result = self.parser.parse(data)
        assert "Network Traffic Intelligence (Sandbox)" in result
