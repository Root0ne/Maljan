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
| single | 1/1 | 0 | 1 |
| negotiated | 1/1 | 0 | 4 |
| noise | 1/1 | 0 | 4 |

Loss is equal across arms; the marginal tables are directly comparable.

## single  (n=1 rows over 1 samples, calls/sample=1)

| metric | mean | 95% bootstrap CI |
|---|---|---|
| precision | 0.111 | [0.000, 0.000] |
| recall | 0.048 | [0.000, 0.000] |
| F1 | 0.067 | [0.000, 0.000] |
| invalid technique-id rate | 0.111 | [0.000, 0.000] |
| techniques predicted | 9.00 | [0.00, 0.00] |
| output tokens (est.) | 1055 | [0, 0] |

## negotiated  (n=1 rows over 1 samples, calls/sample=4)

| metric | mean | 95% bootstrap CI |
|---|---|---|
| precision | 0.000 | [0.000, 0.000] |
| recall | 0.000 | [0.000, 0.000] |
| F1 | 0.000 | [0.000, 0.000] |
| invalid technique-id rate | 0.077 | [0.000, 0.000] |
| techniques predicted | 13.00 | [0.00, 0.00] |
| output tokens (est.) | 2797 | [0, 0] |

## noise  (n=1 rows over 1 samples, calls/sample=4)

| metric | mean | 95% bootstrap CI |
|---|---|---|
| precision | 0.000 | [0.000, 0.000] |
| recall | 0.000 | [0.000, 0.000] |
| F1 | 0.000 | [0.000, 0.000] |
| invalid technique-id rate | 0.154 | [0.000, 0.000] |
| techniques predicted | 13.00 | [0.00, 0.00] |
| output tokens (est.) | 3665 | [0, 0] |

## Paired comparisons

### negotiated - single

_insufficient paired observations_

### negotiated - noise

_insufficient paired observations_
