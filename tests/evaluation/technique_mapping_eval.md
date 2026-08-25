# Technique-mapping evaluation: TF-IDF vs semantic vs hybrid (TRAM2)

- Test set: TRAM2 single_label (human-labeled threat-report sentences), independent of the ATT&CK build corpus.
- Sample: 4913 (sentence, technique_id) pairs.
- embedding backend: REAL fastembed BGE (related=0.696 vs unrelated=0.568)
- Hybrid = semantic search() ranking + TF-IDF validate_and_score() gate (ranking equals semantic by construction).

| backend | top-1 | top-3 | MRR | correct-score | wrong-top1-score | gate sep |
|---|---|---|---|---|---|---|
| TF-IDF | 0.205 | 0.329 | 0.274 | 0.309 | 0.224 | +0.085 |
| semantic | 0.230 | 0.392 | 0.319 | 0.713 | 0.694 | +0.019 |
| hybrid | 0.230 | 0.392 | 0.319 | 0.242 | 0.127 | +0.115 |

- `gate sep` = mean correct-score minus mean wrong-top1-score; higher is a cleaner alignment gate (better at flagging a wrong top-1).
- Ranking delta (semantic/hybrid - tfidf): top-1 +0.025, top-3 +0.063, MRR +0.044.
