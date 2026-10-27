### Security

- **The webcrack sidecar runs Node.js 22.23.4.** It is the security release of 2026-10-20. The image checks the official Linux build against the sha256 in that release's SHASUMS256.txt, whose signature was verified against the Node.js release key. webcrack and its packages are unchanged. No run changes.
