from typing import Any

from maljan.parsers.base_parser import BaseParser
from maljan.parsers.registry import register_parser


@register_parser("network")
class NetworkParser(BaseParser):
    """Zeek (Bro) & C2 Network Log Refinement Engine."""

    def parse(self, raw_data: Any) -> str:
        """Sifts through network JSON logs for C2 and exfiltration indicators.

        Supports two shapes:
          * dict — CAPEv2 ``network`` block (dns/http/tcp/hosts/domains keys)
          * list — Zeek (Bro) connection log
        """
        if isinstance(raw_data, dict):
            return self._parse_sandbox_network(raw_data)
        if isinstance(raw_data, list):
            return self._parse_zeek_network(raw_data)
        return "Invalid network log format."

    @staticmethod
    def _host_ctx(meta: dict[str, Any]) -> str:
        """One-line ASN / country context for a CAPE ``hosts`` entry."""
        asn = " ".join(str(x) for x in (meta.get("asn"), meta.get("asn_name")) if x).strip()
        country = str(meta.get("country_name") or "").strip()
        parts = []
        if asn and asn.lower() != "unknown":
            parts.append(f"AS {asn}")
        if country and country.lower() != "unknown":
            parts.append(country)
        return " / ".join(parts) if parts else "—"

    def _parse_sandbox_network(self, raw_data: dict[str, Any]) -> str:
        """Parse a sandbox ``network`` dict (CAPEv2 shape).

        Surfaces the FULL CAPE network picture for the analyst: DNS, HTTP, TCP
        and UDP flows (annotated with each destination's ASN/country from the
        ``hosts`` block), contacted hosts (IP/ASN/country/ports) and domains,
        the raw PCAP path (so the analyst's PCAP MCP can deep-inspect it), and a
        pointer to the per-IOC VirusTotal permalinks carried in the structured
        report.
        """
        dns_rows: list[list[str]] = []
        http_rows: list[list[str]] = []
        tcp_rows: list[list[str]] = []
        udp_rows: list[list[str]] = []
        host_rows: list[list[str]] = []

        # Host metadata (ip -> asn/country/ports) to annotate the flow tables.
        host_meta: dict[str, dict[str, Any]] = {}
        for h in raw_data.get("hosts", []):
            if isinstance(h, dict) and h.get("ip"):
                host_meta[str(h["ip"])] = h

        # DNS
        for entry in raw_data.get("dns", []):
            if not isinstance(entry, dict):
                continue
            query = entry.get("request", entry.get("query", "N/A"))
            answers = entry.get("answers") or []
            ans = answers[0] if answers else "N/A"
            if isinstance(ans, dict):
                ans = ans.get("data") or ans.get("ip") or "N/A"
            is_dga = self._is_suspicious_dns(str(query))
            dns_rows.append([str(query), str(ans), "[Suspicious]" if is_dga else "Normal"])

        # HTTP
        for entry in raw_data.get("http", []):
            if not isinstance(entry, dict):
                continue
            host = entry.get("host", "N/A")
            uri = entry.get("uri", entry.get("path", "/"))
            method = entry.get("method", "GET")
            http_rows.append([str(host), f"{method} {uri}", str(entry.get("status", "?"))])

        # TCP / UDP flows — dedupe by (dst, port) and drop internal/multicast
        # noise (guest-resolver DNS to 192.168.x:53, SSDP/WS-Discovery to
        # 239.255.255.250). A single detonation emits dozens of identical
        # internal-resolver rows that would drown the real C2 surface; the DNS
        # table already carries the queries and the hosts table the endpoints.
        # ``_is_emittable_ip`` is the same public/routable filter used for IOC
        # emission, so the flow tables and the report agree on what's "external".
        from maljan.extractors.network_extractor import _is_emittable_ip

        seen_tcp: set[tuple[str, str]] = set()
        for entry in raw_data.get("tcp", []):
            if not isinstance(entry, dict):
                continue
            dst = str(entry.get("dst", "")).strip()
            port = str(entry.get("dport", "?"))
            if not _is_emittable_ip(dst) or (dst, port) in seen_tcp:
                continue
            seen_tcp.add((dst, port))
            tcp_rows.append([dst, port, self._host_ctx(host_meta.get(dst, {}))])
        seen_udp: set[tuple[str, str]] = set()
        for entry in raw_data.get("udp", []):
            if not isinstance(entry, dict):
                continue
            dst = str(entry.get("dst", "")).strip()
            port = str(entry.get("dport", "?"))
            if not _is_emittable_ip(dst) or (dst, port) in seen_udp:
                continue
            seen_udp.add((dst, port))
            udp_rows.append([dst, port, self._host_ctx(host_meta.get(dst, {}))])

        # Contacted hosts (ip / ASN+country / ports)
        for h in raw_data.get("hosts", []):
            if isinstance(h, dict):
                ip = str(h.get("ip") or h.get("address") or "N/A")
                ports = ",".join(str(p) for p in (h.get("ports") or [])) or "—"
                host_rows.append([ip, self._host_ctx(h), ports])
            elif isinstance(h, str):
                host_rows.append([h, "—", "—"])

        # Domains
        for domain in raw_data.get("domains", []):
            name = domain.get("domain") if isinstance(domain, dict) else domain
            if not name:
                continue
            is_dga = self._is_suspicious_dns(str(name))
            host_rows.append([str(name), "domain", "[Suspicious]" if is_dga else "Normal"])

        dns_table = self._format_as_table(
            headers=["Target Domain", "IP Address", "Evaluation"], rows=dns_rows
        )
        http_table = self._format_as_table(headers=["Host", "Request", "Status"], rows=http_rows)
        flow_hdr = ["Destination", "Port", "ASN / Country"]
        tcp_table = self._format_as_table(headers=flow_hdr, rows=tcp_rows)
        udp_table = self._format_as_table(headers=flow_hdr, rows=udp_rows)
        host_table = self._format_as_table(
            headers=["Host/Domain", "ASN / Country", "Ports"], rows=host_rows
        )

        # Deterministic FULL-PCAP analysis folded in as text. We read every
        # packet once (maljan.analysis.pcap_summary) and inject beaconing /
        # byte-volume / TLS-SNI intelligence the structured block can't express,
        # instead of relying on the LLM to iteratively call PCAP MCP tools (it
        # skips them to stay in its time budget — live task 9: tool_calls=0).
        # Note we deliberately do NOT emit the raw ``.pcap`` path here so the
        # analyst reasons on this summary directly rather than re-entering the
        # slow, budget-starving MCP tool loop.
        extras = ""
        pcap = raw_data.get("pcap_local_path")
        if isinstance(pcap, str) and pcap:
            from maljan.analysis.pcap_summary import summarize_pcap

            summary = summarize_pcap(pcap)
            if summary:
                extras += "\n\n" + summary
        extras += (
            "\n\n#### Reputation:\nEvery public IP/domain above carries a VirusTotal "
            "permalink in the structured report "
            "(``network.ips[].reputation.virustotal_url`` / "
            "``network.domains[].reputation.virustotal_url``) — pivot for third-party verdicts."
        )

        return (
            "### Network Traffic Intelligence (Sandbox)\n\n"
            "#### DNS Exfiltration & DGA Analysis:\n"
            f"{dns_table}\n\n"
            "#### HTTP Requests:\n"
            f"{http_table}\n\n"
            "#### TCP Connections:\n"
            f"{tcp_table}\n\n"
            "#### UDP Connections:\n"
            f"{udp_table}\n\n"
            "#### Contacted Hosts & Domains:\n"
            f"{host_table}"
            f"{extras}"
        )

    def _parse_zeek_network(self, raw_data: list[Any]) -> str:
        """Parse Zeek (Bro) network log format."""
        dns_rows: list[list[str]] = []
        conn_rows: list[list[str]] = []

        for entry in raw_data:
            service = entry.get("service", "N/A")
            ip = entry.get("id.resp_h", "N/A")
            port = entry.get("id.resp_p", "N/A")

            if service == "dns":
                query = entry.get("query", "N/A")
                is_dga = self._is_suspicious_dns(query)
                dns_rows.append([query, ip, "[Suspicious]" if is_dga else "Normal"])

            elif service in ["ssl", "http"]:
                conn_rows.append([f"{ip}:{port}", service, str(entry.get("resp_bytes", 0))])

        dns_table = self._format_as_table(
            headers=["Target Domain", "IP Address", "Evaluation"], rows=dns_rows
        )
        conn_table = self._format_as_table(
            headers=["Endpoint", "Protocol", "Bytes Recv"], rows=conn_rows
        )

        return (
            "### Network Traffic Intelligence (Zeek Summarized)\n\n"
            "#### DNS Exfiltration & DGA Analysis:\n"
            f"{dns_table}\n\n"
            "#### C2 Connectivity Beaconing:\n"
            f"{conn_table}"
        )

    def _is_suspicious_dns(self, query: str) -> bool:
        """Flag suspicious domains (DGA / homograph / C2-infra tokens).

        Delegates to the canonical scorer in ``network_extractor`` so the
        ``[Suspicious]`` markers in this LLM-facing text summary agree with the
        structured ``MalwareReport.network`` verdicts (single source of truth),
        instead of the old ``len > 25`` proof-of-concept heuristic.
        """
        from maljan.extractors.network_extractor import _assess_domain

        return _assess_domain(query).suspicious
