# C2b — cascade weight sensitivity with the dynamic layer in play

97 samples assembled from 97 archived reports; 94 carried at least one dynamic source.

| source | samples where it produced a claim |
|---|---|
| `sigma_layer` | 94/97 |
| `yara_layer` | 88/97 |
| `import_capability` | 54/97 |
| `tool_artifact` | 1/97 |

## How many domains see each technique

§1.10 measured **87.9% single-domain** over three static sources and named the sandbox as
the missing ingredient. Recomputed here with six sources:

| exactly one domain | **796** (89.9%) |
|---|---|
| two domains | 89 |
| three or more | 0 |

## Perturbing the eleven constants

| perturbation | top-10 changed | corroborated set changed | net delta |
|---|---|---|---|
| `flat_0.5_all_layers` | 27/97 (27.8%) | **0/97** | +0 |
| `inverted_yara_network` | 28/97 (28.9%) | **0/97** | +0 |
| `compressed_toward_0.5_x0.25` | 24/97 (24.7%) | **0/97** | +0 |
| `stretched_from_0.5_x1.75` | 12/97 (12.4%) | **0/97** | +0 |
| `yara_demoted_0.90_to_0.45` | 24/97 (24.7%) | **0/97** | +0 |

**The corroborated set still moves on 0.0%, and now the reason is exhausted.** §1.10
left open whether its null came from having only two effective domains; that
explanation is now spent — `sigma_layer` supplies a third on most of the cohort and
nothing changes. `is_corroborated` is `len(contributing_layers) >= 2` and never
consults `LAYER_WEIGHTS`, so the eleven constants cannot move it by construction, and
the corpus was never what was hiding that.

Taken with §3.27.1 the cascade is inert twice over. Its agreement flag is unreachable
by its own weights. And its technique set — the one thing that *is* read downstream —
reaches the artefact through a reconciliation step that restores whatever the judge
omitted, so the judge cannot subtract from it and, across 80 arms, added nothing.
