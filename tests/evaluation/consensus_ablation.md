# E.2 — negotiated consensus vs single agent, equal token budget

- Total output budget B = 1200 per sample per arm; `negotiated`/`noise` split it
  across K channel analysts **plus the mediator**, so the mediator is not free.
- Evidence is split into heterogeneous channels (static / dynamic / network) and never
  names a technique id — the metric is accuracy against the fixture ground truth.
- `noise` is Bertalanič & Fortuna's stochastic control: one analyst gets another
  sample's evidence. If `noise` scores like `negotiated`, the negotiation is
  aggregating rather than reconciling.

## single  (n=1, calls/sample=1)

| metric | mean | 95% bootstrap CI |
|---|---|---|
| precision | 0.600 | [0.000, 0.000] |
| recall | 0.600 | [0.000, 0.000] |
| F1 | 0.600 | [0.000, 0.000] |
| invalid technique-id rate | 0.000 | [0.000, 0.000] |
| techniques predicted | 5.00 | [0.00, 0.00] |
| output tokens (est.) | 305 | [0, 0] |

## negotiated  (n=1, calls/sample=4)

| metric | mean | 95% bootstrap CI |
|---|---|---|
| precision | 0.400 | [0.000, 0.000] |
| recall | 0.400 | [0.000, 0.000] |
| F1 | 0.400 | [0.000, 0.000] |
| invalid technique-id rate | 0.000 | [0.000, 0.000] |
| techniques predicted | 5.00 | [0.00, 0.00] |
| output tokens (est.) | 904 | [0, 0] |

## noise  (n=1, calls/sample=4)

| metric | mean | 95% bootstrap CI |
|---|---|---|
| precision | 0.286 | [0.000, 0.000] |
| recall | 0.400 | [0.000, 0.000] |
| F1 | 0.333 | [0.000, 0.000] |
| invalid technique-id rate | 0.000 | [0.000, 0.000] |
| techniques predicted | 7.00 | [0.00, 0.00] |
| output tokens (est.) | 1042 | [0, 0] |

## Paired comparisons

### negotiated - single

_insufficient paired observations_

### negotiated - noise

_insufficient paired observations_
