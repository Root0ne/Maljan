# E.2 — negotiated consensus vs single agent, equal token budget

- Total output budget B = 2400 per sample per arm; `negotiated`/`noise` split it
  across K channel analysts **plus the mediator**, so the mediator is not free.
- Evidence is split into heterogeneous channels (static / dynamic / network) and never
  names a technique id — the metric is accuracy against the fixture ground truth.
- `noise` is Bertalanič & Fortuna's stochastic control: one analyst gets another
  sample's evidence. If `noise` scores like `negotiated`, the negotiation is
  aggregating rather than reconciling.

## Generation completeness

| arm | completed | lost | calls/generation |
|---|---|---|---|
| single | 25/25 | 0 | 1 |
| negotiated | 25/25 | 0 | 4 |
| noise | 25/25 | 0 | 4 |

Loss is equal across arms; the marginal tables are directly comparable.

## single  (n=25, calls/sample=1)

| metric | mean | 95% bootstrap CI |
|---|---|---|
| precision | 0.413 | [0.352, 0.475] |
| recall | 0.416 | [0.352, 0.480] |
| F1 | 0.414 | [0.352, 0.474] |
| invalid technique-id rate | 0.077 | [0.040, 0.120] |
| techniques predicted | 5.04 | [4.92, 5.16] |
| output tokens (est.) | 325 | [310, 343] |

## negotiated  (n=25, calls/sample=4)

| metric | mean | 95% bootstrap CI |
|---|---|---|
| precision | 0.370 | [0.326, 0.414] |
| recall | 0.432 | [0.384, 0.488] |
| F1 | 0.398 | [0.350, 0.445] |
| invalid technique-id rate | 0.061 | [0.020, 0.109] |
| techniques predicted | 5.88 | [5.60, 6.16] |
| output tokens (est.) | 1039 | [977, 1111] |

## noise  (n=25, calls/sample=4)

| metric | mean | 95% bootstrap CI |
|---|---|---|
| precision | 0.326 | [0.284, 0.368] |
| recall | 0.352 | [0.312, 0.384] |
| F1 | 0.337 | [0.298, 0.371] |
| invalid technique-id rate | 0.028 | [0.007, 0.056] |
| techniques predicted | 5.60 | [5.28, 5.92] |
| output tokens (est.) | 1027 | [968, 1094] |

## Paired comparisons

### negotiated - single  (paired, n=25)

- mean F1 delta **-0.016**, 95% CI [-0.084, +0.050] — **CI includes 0 — no separation**
- sign test: negotiated wins 10, single wins 11, ties 4

### negotiated - noise  (paired, n=25)

- mean F1 delta **+0.061**, 95% CI [+0.012, +0.110] — CI excludes 0
- sign test: negotiated wins 13, noise wins 7, ties 5
