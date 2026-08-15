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
| single | 24/24 | 0 | 1 |
| negotiated | 24/24 | 0 | 4 |
| noise | 24/24 | 0 | 4 |

Loss is equal across arms; the marginal tables are directly comparable.

## single  (n=24 rows over 24 samples, calls/sample=1)

| metric | mean | 95% bootstrap CI |
|---|---|---|
| precision | 0.203 | [0.148, 0.259] |
| recall | 0.070 | [0.050, 0.093] |
| F1 | 0.097 | [0.070, 0.124] |
| F1 (sub-techniques collapsed to parents) | 0.223 | [0.187, 0.257] |
| invalid technique-id rate | 0.059 | [0.032, 0.087] |
| techniques predicted | 9.38 | [8.17, 10.54] |
| output tokens (est.) | 1666 | [1258, 2112] |

## negotiated  (n=24 rows over 24 samples, calls/sample=4)

| metric | mean | 95% bootstrap CI |
|---|---|---|
| precision | 0.240 | [0.189, 0.289] |
| recall | 0.127 | [0.096, 0.164] |
| F1 | 0.150 | [0.122, 0.181] |
| F1 (sub-techniques collapsed to parents) | 0.250 | [0.214, 0.286] |
| invalid technique-id rate | 0.042 | [0.021, 0.063] |
| techniques predicted | 13.42 | [11.54, 15.21] |
| output tokens (est.) | 4600 | [3840, 5408] |

## noise  (n=24 rows over 24 samples, calls/sample=4)

| metric | mean | 95% bootstrap CI |
|---|---|---|
| precision | 0.222 | [0.171, 0.271] |
| recall | 0.123 | [0.091, 0.157] |
| F1 | 0.150 | [0.115, 0.184] |
| F1 (sub-techniques collapsed to parents) | 0.266 | [0.225, 0.304] |
| invalid technique-id rate | 0.083 | [0.052, 0.119] |
| techniques predicted | 13.46 | [12.17, 14.75] |
| output tokens (est.) | 3933 | [3470, 4488] |

## Paired comparisons

### negotiated - single  (paired, n=24 rows over 24 samples)

- mean F1 delta **+0.054**, 95% cluster CI [+0.036, +0.071] — CI excludes 0
- sampled cluster sign-flip p = 0.0000 (the smallest this design can reach is 0.0000)
- minimum detectable effect at 80% power: 0.027 F1 — the observed effect is above this design's resolution
- ICC 1.000, design effect 1.00, effective n 24.0
- sign test: negotiated wins 19, single wins 1, ties 4

### negotiated - noise  (paired, n=24 rows over 24 samples)

- mean F1 delta **+0.000**, 95% cluster CI [-0.029, +0.031] — **CI includes 0 — no separation**
- sampled cluster sign-flip p = 0.9754 (the smallest this design can reach is 0.0000)
- minimum detectable effect at 80% power: 0.046 F1 — **the observed effect is below this design's resolution**
- ICC 1.000, design effect 1.00, effective n 24.0
- sign test: negotiated wins 13, noise wins 10, ties 1
