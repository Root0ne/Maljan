"""Malware artifact parsing and refinement layer.

Parsers transform raw tool output (Ghidra JSON, CAPEv2 sandbox reports,
Zeek network logs) into noise-filtered Markdown summaries suitable for
LLM consumption. Each parser is registered via @register_parser.
"""
