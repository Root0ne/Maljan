"""PE/ELF static analysis loader using pefile and filetype.

Extracts structural metadata from Windows PE files:
  - File type detection (PE32, PE32+, DLL, etc.)
  - Entry point, image base, subsystem
  - Section headers (name, virtual size, raw size, entropy hints)
  - Import table (DLLs and their imported functions)
  - Export table (exported symbols)
  - Resource strings (possible C2 URLs, mutexes, registry keys)

Graceful degradation:
  - If pefile is not installed, returns basic file stats only.
  - If filetype is not available, falls back to header-byte detection.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from maljan.core.logger import logger


def _detect_file_type(path: Path) -> str:
    """Detect file type using filetype or fallback to header bytes."""
    try:
        import filetype  # type: ignore[import-untyped]

        kind = filetype.guess(str(path))
        if kind is not None:
            return f"{kind.extension.upper()} ({kind.mime})"
        # Fallback: check first bytes for PE/ELF signature
        with path.open("rb") as f:
            header = f.read(4)
        if header[:2] == b"MZ":
            return "PE executable (Windows)"
        if header[:4] == b"\x7fELF":
            return "ELF executable (Linux)"
        return f"Unknown (first bytes: {header.hex()})"
    except Exception:
        return "Unknown (cannot detect)"


class PELoader:
    """Loads and parses PE file metadata for static malware analysis."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.file_type = _detect_file_type(self.path)
        self._pe: Any | None = None

    def _load_pe(self) -> Any | None:
        """Lazy-load pefile object."""
        if self._pe is not None:
            return self._pe
        try:
            import pefile  # type: ignore[import-untyped]

            self._pe = pefile.PE(str(self.path))
            return self._pe
        except ImportError:
            logger.warning("pefile not installed. PE parsing disabled.")
            return None
        except Exception as exc:
            logger.warning("Failed to parse PE file: %s", exc)
            return None

    def _get_imports(self) -> list[dict[str, Any]]:
        """Extract imported DLLs and functions."""
        pe = self._load_pe()
        if not pe:
            return []
        imports: list[dict[str, Any]] = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8", errors="ignore") if entry.dll else "unknown"
                funcs = []
                for imp in entry.imports:
                    name = (
                        imp.name.decode("utf-8", errors="ignore")
                        if imp.name
                        else f"ord_{imp.ordinal}"
                    )
                    funcs.append(name)
                imports.append({"dll": dll_name, "functions": funcs})
        return imports

    def _get_exports(self) -> list[str]:
        """Extract exported function names."""
        pe = self._load_pe()
        if not pe:
            return []
        exports: list[str] = []
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                name = (
                    exp.name.decode("utf-8", errors="ignore")
                    if exp.name
                    else f"ord_{exp.ordinal}"
                )
                exports.append(name)
        return exports

    def _get_sections(self) -> list[dict[str, Any]]:
        """Extract section headers."""
        pe = self._load_pe()
        if not pe:
            return []
        sections: list[dict[str, Any]] = []
        for section in pe.sections:
            name = section.Name.decode("utf-8", errors="ignore").strip("\x00")
            entropy = section.get_entropy()
            sections.append(
                {
                    "name": name,
                    "virtual_address": hex(section.VirtualAddress),
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData,
                    "entropy": round(entropy, 2),
                    "characteristics": hex(section.Characteristics),
                }
            )
        return sections

    def _get_strings(self, min_length: int = 4) -> list[str]:
        """Extract ASCII/Unicode strings from the file."""
        strings: list[str] = []
        try:
            with self.path.open("rb") as f:
                data = f.read()
            # Simple ASCII string extraction
            current = bytearray()
            for byte in data:
                if 32 <= byte <= 126:
                    current.append(byte)
                else:
                    if len(current) >= min_length:
                        strings.append(current.decode("ascii", errors="ignore"))
                    current = bytearray()
            if len(current) >= min_length:
                strings.append(current.decode("ascii", errors="ignore"))
        except Exception as exc:
            logger.warning("String extraction failed: %s", exc)
        # Filter for interesting strings (URLs, registry keys, IPs)
        interesting: list[str] = []
        for s in strings:
            lower = s.lower()
            if any(
                kw in lower
                for kw in [
                    "http",
                    "https",
                    "ftp",
                    "regedit",
                    "hklm",
                    "hkcu",
                    "mutex",
                    "cmd.exe",
                    "powershell",
                    "dll",
                    "exe",
                ]
            ):
                interesting.append(s)
        return interesting[:50]  # cap at 50 interesting strings

    def parse(self) -> dict[str, Any]:
        """Return full PE analysis dict."""
        pe = self._load_pe()
        result: dict[str, Any] = {
            "file_path": str(self.path),
            "file_size": self.path.stat().st_size,
            "file_type": self.file_type,
        }

        result["strings"] = self._get_strings()
        if pe:
            result["entry_point"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            result["image_base"] = hex(pe.OPTIONAL_HEADER.ImageBase)
            result["subsystem"] = pe.OPTIONAL_HEADER.Subsystem
            result["sections"] = self._get_sections()
            result["imports"] = self._get_imports()
            result["exports"] = self._get_exports()
        else:
            result["entry_point"] = "N/A (pefile unavailable)"
            result["image_base"] = "N/A"
            result["subsystem"] = "N/A"
            result["sections"] = []
            result["imports"] = []
            result["exports"] = []

        return result

    def to_markdown(self) -> str:
        """Convert parse result to markdown for LLM consumption."""
        data = self.parse()
        lines: list[str] = [
            "### Static PE Analysis\n",
            f"**File:** {data['file_path']}",
            f"**Size:** {data['file_size']} bytes",
            f"**Type:** {data['file_type']}",
            f"**Entry Point:** {data['entry_point']}",
            f"**Image Base:** {data['image_base']}",
            f"**Subsystem:** {data['subsystem']}",
            "",
            "#### Sections",
        ]
        for section in data["sections"]:
            lines.append(
                f"- `{section['name']}`: VA={section['virtual_address']}, "
                f"VS={section['virtual_size']}, RS={section['raw_size']}, "
                f"Entropy={section['entropy']}"
            )
        if not data["sections"]:
            lines.append("- (no sections parsed)")

        lines.extend(["", "#### Imports"])
        for imp in data["imports"][:10]:
            funcs = ", ".join(imp["functions"][:5])
            if len(imp["functions"]) > 5:
                funcs += f", ... ({len(imp['functions'])} total)"
            lines.append(f"- `{imp['dll']}`: {funcs}")
        if not data["imports"]:
            lines.append("- (no imports parsed)")

        lines.extend(["", "#### Exports"])
        for exp in data["exports"][:10]:
            lines.append(f"- `{exp}`")
        if not data["exports"]:
            lines.append("- (no exports)")

        lines.extend(["", "#### Interesting Strings"])
        for s in data["strings"][:20]:
            lines.append(f"- `{s}`")
        if not data["strings"]:
            lines.append("- (no interesting strings)")

        return "\n".join(lines)
