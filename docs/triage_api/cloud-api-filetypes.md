# Triage Cloud API - File Types

Source: https://tria.ge/docs/cloud-api/filetypes/
Mirrored: 2026-05-23

---

# Supported Filetypes

In a default Recorded Future: Sandbox setup, the following file types are supported:

Executables:

- DLL, EXE, MSI

Documents:

- CHM, HTA, IQY, Office 2003, Office 2007+, OpenOffice, PDF, RTF, SLK, SWF, HTML

Scripting:

- BAT, PS1, JS (JScript), JSE, VBE, PL, VBS, WSF

macOS:

- APP, DMG, ELF, mach-O, PKG, SCPT, SH

Android:

- APK, DEX

Linux (ARM, ARM64, MIPS, PowerPC, x86, x86_64):

- ELF, SH

Images:

- SVG

Other:

- JAR, LNK, URL, JNLP

Archives (for unpacking):

- 7z, ACE, BZ2, CAB, DAA, EML, GZIP, IMG, ISO, LZ, LZH, MSG, PKZIP, RAR, TAR, TNEF, VBN, VHD, XAR, XZ, ZIP

**Note**: SVG is supported for static analysis only. **Note**: Archive file formats are supported for static analysis. Supported file types extracted from an archive may be selected for further behavioural analysis.

## Scripts

Scripts which depend on third-party commands (or cmdlets) may not execute correctly. This can be resolved by having the script install the required dependencies at runtime.

# Applicable filetypes for QR code analysis

Images:

- PNG, JPG / JPEG

**Note**: QR code extraction occurs in the static analysis stage and is limited to extracting URLs from images. It will not function for QR codes present in behavioural analysis (e.g. a QR code displayed in a web browser in behavioural analysis).

# Additional filetypes

The sandbox may accept additional formats to those described above. Support for these file formats is considered "best effort" and may not perform as expected.

# Filetypes on our TODO List

We're always working on new static and behavioral analysis components. If you think we should add support for a common file type that is not listed above, or that does not behave as expected, just reach out and let us know!
