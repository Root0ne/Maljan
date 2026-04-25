"""Memory and intelligence retrieval subsystem for Maljan.

Modules:
  - attck_loader: Downloads and parses MITRE ATT&CK STIX 2.1 bundle.
  - attck_index:  In-memory TF-IDF index over ATT&CK technique descriptions.
  - attck_validator: Validates proposed TTP IDs against the authoritative ATT&CK dataset.
"""
