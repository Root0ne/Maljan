"""The caps on the bytes each channel delivers into Maljan, declared once.

A module with no imports, so a reader that only needs the numbers (the
capture reader, in a sidecar) does not load the providers package to learn
them. ``providers/sandbox/limits.py`` and the API's settings catalog take
their values from here.
"""

# A sandbox's answer: a report, or a capture streamed to disk.
MAX_RESPONSE_BYTES = 64 * 1024 * 1024

# The default size a sample upload may reach (the API's ``upload_max_bytes``).
SAMPLE_UPLOAD_MAX_BYTES = 100 * 1024 * 1024
