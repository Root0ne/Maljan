# Highlights

Submitted to *Computers & Security* as a separate file, not as part of the
manuscript. Elsevier asks for three to five bullets, each at most 85 characters
including spaces. The count is in brackets after each line and is checked by
`make paper-check`.

Every number here is one the paper derives; none is rounded differently than the
body rounds it, because a highlight that disagrees with the table it summarises
is the same defect as a hand-typed numeral.

## Measuring What an LLM Adds to Malware-to-ATT&CK Technique Mapping

- Several model calls beat one judge by 0.054 F1; their negotiation adds nothing. [79]
- A decoding flag outweighs every architecture and parameter count measured. [74]
- Composing ranking and gating backends beats choosing, on two external corpora. [78]
- The full pipeline sits 0.003 F1 from the no-LLM sandbox it is built on. [71]
- Seven instrument defects returned plausible results; 2,744 tests caught none. [77]

## Where each comes from

| # | Section | Facts |
| :- | :- | :- |
| 1 | 3.3, Table 5 | `cape-negotiated-delta` +0.0537, `cape-mechanism-delta` +0.0005 |
| 2 | 3.4, Table 6 | `reasoning-flag-worth-low` 0.34 to `reasoning-flag-worth-high` 0.45 |
| 3 | 3.2, Table 4 | `mapping-tram2-hybrid-gate`, `mapping-annoctr-hybrid-gate` |
| 4 | 3.1, Table 3 | `h2h-delta` +0.0030, at a resolution of `h2h-mde` 0.085 |
| 5 | 3.7, Table 9 | `test-count` 2,744 |

Bullet 4 states a difference the design could not resolve, and says so in the
paper. It is here rather than a larger-sounding line because the comparison it
names is the one the paper argues every F1 in this literature needs, and a
highlight that reported the pipeline's absolute F1 without it would be the thing
the paper is against.
