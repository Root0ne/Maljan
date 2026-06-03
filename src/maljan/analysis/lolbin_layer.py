"""Deterministic LOLBin signed-binary-proxy-execution detection (Layer 0).

Flags **suspicious** use of the common living-off-the-land binaries
``regsvr32`` / ``rundll32`` / ``mshta`` from process command lines and emits an
``AgentISR`` carrying the matching MITRE ATT&CK technique:

  * ``regsvr32`` -> T1218.010
  * ``rundll32`` -> T1218.011
  * ``mshta``    -> T1218.005

These binaries are ubiquitous and overwhelmingly benign, so detection requires a
*suspicious indicator* (remote URL, scriptlet, script protocol, ordinal export,
or a payload under a user-writable directory) — never mere presence. This is the
execution counterpart to COM-hijack persistence (T1546.015): ``regsvr32`` /
``rundll32`` are the canonical COM-payload launchers.

Mirrors the Sigma/YARA Layer-0 pattern: produces a deterministic
``AgentISR(domain="dynamic", revision_round=0)`` consumed by the TTP cascade.
"""

from __future__ import annotations

import re
from typing import Any

from maljan.core.logger import logger
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

# A remote/script indicator turns an otherwise-benign LOLBin invocation into a
# signed-proxy-execution signal (squiblydoo, scriptlet COM, HTA download, ...).
_REMOTE_OR_SCRIPT = re.compile(r"https?://|javascript:|vbscript:|scrobj\.dll", re.IGNORECASE)

# Payload staged under a user-writable location (vs a legitimate System32 DLL).
_USER_WRITABLE_PATH = re.compile(
    r"\\(?:temp|tmp|appdata|programdata|users\\public|windows\\temp)\\|%temp%|%appdata%|%programdata%",
    re.IGNORECASE,
)

# rundll32 calling an exported ordinal (``,#1``) is a known evasion shape.
_ORDINAL_EXPORT = re.compile(r",\s*#\d+")

# Per-binary technique mapping.
_REGSVR32_TID = "T1218.010"
_RUNDLL32_TID = "T1218.011"
_MSHTA_TID = "T1218.005"

_CONFIDENCE = 0.78
_MAX_CMD_LEN = 160


def _truncate(text: str, limit: int = _MAX_CMD_LEN) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _dll_in_user_path(cmd_lower: str) -> bool:
    return ".dll" in cmd_lower and bool(_USER_WRITABLE_PATH.search(cmd_lower))


def classify_lolbin(command_line: str) -> tuple[str, str] | None:
    """Return ``(technique_id, binary)`` when ``command_line`` is a suspicious
    LOLBin invocation, else ``None``. Pure function — trivially testable.
    """
    low = command_line.lower()

    if "regsvr32" in low:
        # squiblydoo (/i: scriptlet), remote/scriptlet, or a DLL from a
        # user-writable path. A bare ``regsvr32 /s C:\\Windows\\System32\\x.dll``
        # is benign and intentionally not flagged.
        if "/i:" in low or _REMOTE_OR_SCRIPT.search(low) or _dll_in_user_path(low):
            return _REGSVR32_TID, "regsvr32"

    if "rundll32" in low:
        if (
            _REMOTE_OR_SCRIPT.search(low)
            or "mshtml,runhtmlapplication" in low.replace(" ", "")
            or _ORDINAL_EXPORT.search(low)
            or _dll_in_user_path(low)
        ):
            return _RUNDLL32_TID, "rundll32"

    if "mshta" in low:
        # mshta is rarely benign in malware analysis; flag remote/script payloads
        # and local .hta staged in a user-writable path.
        if _REMOTE_OR_SCRIPT.search(low) or (".hta" in low and _USER_WRITABLE_PATH.search(low)):
            return _MSHTA_TID, "mshta"

    return None


def _iter_command_lines(sandbox_report: dict[str, Any]) -> list[str]:
    behavior = sandbox_report.get("behavior") or {}
    procs = behavior.get("processes") if isinstance(behavior, dict) else None
    out: list[str] = []
    if isinstance(procs, list):
        for proc in procs:
            if not isinstance(proc, dict):
                continue
            cmd = str(proc.get("command_line") or proc.get("cmd") or "").strip()
            if cmd:
                out.append(cmd)
    return out


def build_lolbin_isr(sandbox_report: dict[str, Any] | None) -> AgentISR | None:
    """Scan process command lines for suspicious LOLBin execution and return a
    deterministic ``AgentISR`` (domain ``"dynamic"``), or ``None`` when nothing
    qualifies. Windows-only: claims carry ``rule_platforms=["windows"]`` so the
    cascade drops them for non-Windows samples.
    """
    if not isinstance(sandbox_report, dict):
        return None

    claims: list[ClaimEvidence] = []
    seen: set[tuple[str, str]] = set()
    for cmd in _iter_command_lines(sandbox_report):
        hit = classify_lolbin(cmd)
        if hit is None:
            continue
        tid, binary = hit
        key = (tid, cmd.lower()[:120])
        if key in seen:
            continue
        seen.add(key)
        claims.append(
            ClaimEvidence(
                claim=f"LOLBin signed-proxy execution via {binary}: {_truncate(cmd)}",
                evidence_ref=f"lolbin: command_line='{_truncate(cmd)}'",
                confidence=_CONFIDENCE,
                technique_id=tid,
                rule_platforms=["windows"],
            )
        )

    if not claims:
        return None
    logger.info(
        "LOLBin Layer 0: %d suspicious invocation(s) -> cascade domain='dynamic'.",
        len(claims),
    )
    return AgentISR(
        agent_id="lolbin",
        domain="dynamic",
        claims=claims,
        dissent_items=[],
        revision_round=0,
    )
