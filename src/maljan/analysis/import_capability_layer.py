"""Deterministic import-capability detection (Layer 0).

2026-07 audit (round 2): after the round-1 fix stopped YARA/Sigma from scanning
analyst prose, the pipeline swung to *under*-reporting — a sample's strongest
real signal could go unmapped. The audited MFC sample is a WS2_32 network client
that resolves and connects to a hard-coded domain (``888kafa.com``), yet no
ATT&CK technique was mapped because the YARA byte-rule corpus has no
network-client rule.

The PE extractor already classifies imports deterministically
(``pe_extractor._SUSPICIOUS_IMPORTS`` → category), but that classification never
became a TTP. This layer closes the gap: it turns the *already-grounded* import
categories (+ static-string IOCs) into ATT&CK techniques, mirroring the
Sigma/YARA/LOLBin Layer-0 pattern. Every claim is anchored in a real import
and/or a real IOC — no prose, no hallucination — and confidences are capped so a
lone import signal corroborates but never drives the verdict alone.

Produces a deterministic ``AgentISR(domain="static", revision_round=0)`` consumed
by the TTP cascade.
"""

from __future__ import annotations

from typing import Any

from maljan.core.logger import logger
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

# Confidence ceiling for a single deterministic import signal. Capped below the
# YARA floor (0.70) so it corroborates other layers but can't solo-drive a
# verdict; the cascade boosts it on cross-layer agreement.
_CONF_BASE = 0.45
_CONF_WITH_IOC = 0.60

# Injection APIs that must be *actually imported* to claim T1055 (never inferred
# from prose). Subset of pe_extractor._SUSPICIOUS_IMPORTS "process_injection".
_INJECTION_FUNCS = frozenset(
    {
        "WriteProcessMemory",
        "VirtualAllocEx",
        "CreateRemoteThread",
        "NtCreateThreadEx",
        "RtlCreateUserThread",
        "QueueUserAPC",
        "SetWindowsHookEx",
    }
)

# Crypto APIs whose presence suggests encryption-for-impact / encrypted channel.
_CRYPTO_ENCRYPT_FUNCS = frozenset({"CryptEncrypt", "BCryptEncrypt", "CryptGenKey"})

_MAX_EVIDENCE = 4


def _imports_by_category(static: Any) -> dict[str, list[tuple[str, str]]]:
    """Return {category: [(dll, function), ...]} for suspicious imports."""
    out: dict[str, list[tuple[str, str]]] = {}
    for imp in getattr(static, "imports", None) or []:
        if not getattr(imp, "is_suspicious", False):
            continue
        cat = getattr(imp, "category", None)
        if not cat:
            continue
        out.setdefault(cat, []).append(
            (str(getattr(imp, "dll", "")), str(getattr(imp, "function", "")))
        )
    return out


def _net_iocs(static: Any) -> list[tuple[str, str]]:
    """Return [(kind, value), ...] for domain/ip/url static-string IOCs."""
    out: list[tuple[str, str]] = []
    for s in getattr(static, "interesting_strings", None) or []:
        kind = getattr(s, "kind", None)
        if kind in {"domain", "ip", "url"}:
            out.append((str(kind), str(getattr(s, "value", ""))))
    return out


def build_import_capability_isr(static: Any) -> AgentISR | None:
    """Map deterministically-classified imports (+ static IOCs) to ATT&CK TTPs.

    Returns an ``AgentISR(domain="static")`` or ``None`` when nothing qualifies.
    ``static`` is the report's ``StaticAnalysis`` (may be ``None``).
    """
    if static is None:
        return None

    by_cat = _imports_by_category(static)
    if not by_cat:
        return None
    net_iocs = _net_iocs(static)
    claims: list[ClaimEvidence] = []

    # --- T1071 Application Layer Protocol (C2) --------------------------------
    net_imports = by_cat.get("network") or []
    if net_imports:
        evidence = [f"import:{dll}!{fn}" for dll, fn in net_imports[:_MAX_EVIDENCE]]
        evidence += [f"string:{kind}:{val[:80]}" for kind, val in net_iocs[:2]]
        has_ioc = bool(net_iocs)
        endpoint = f" to {net_iocs[0][1]}" if has_ioc else ""
        claims.append(
            ClaimEvidence(
                claim=(
                    "Network client capability from imported socket/HTTP APIs"
                    f"{endpoint} (deterministic import evidence)."
                ),
                evidence_ref="; ".join(evidence),
                confidence=_CONF_WITH_IOC if has_ioc else _CONF_BASE,
                technique_id="T1071",
                # T1055 and T1486 below already declared this; T1071 did not, so
                # it fell through to the cascade's MITRE-catalog lookup instead of
                # answering the platform question directly.
                rule_platforms=["windows"],
            )
        )

    # --- T1055 Process Injection (only if the APIs are actually imported) ------
    inj = [(dll, fn) for dll, fn in by_cat.get("process_injection", []) if fn in _INJECTION_FUNCS]
    if inj:
        claims.append(
            ClaimEvidence(
                claim="Process-injection APIs present in the import table.",
                evidence_ref="; ".join(f"import:{dll}!{fn}" for dll, fn in inj[:_MAX_EVIDENCE]),
                confidence=_CONF_BASE,
                technique_id="T1055",
                rule_platforms=["windows"],
            )
        )

    # --- T1486 Data Encrypted for Impact (crypto encryption APIs) -------------
    crypto = [(dll, fn) for dll, fn in by_cat.get("crypto", []) if fn in _CRYPTO_ENCRYPT_FUNCS]
    if crypto:
        claims.append(
            ClaimEvidence(
                claim="Cryptographic encryption APIs present in the import table.",
                evidence_ref="; ".join(f"import:{dll}!{fn}" for dll, fn in crypto[:_MAX_EVIDENCE]),
                confidence=_CONF_BASE,
                technique_id="T1486",
                rule_platforms=["windows"],
            )
        )

    if not claims:
        return None
    logger.info(
        "Import-capability Layer 0: %d technique(s) grounded in imports -> "
        "cascade domain='static'.",
        len(claims),
    )
    return AgentISR(
        agent_id="import_capability",
        domain="static",
        claims=claims,
        dissent_items=[],
        revision_round=0,
    )
