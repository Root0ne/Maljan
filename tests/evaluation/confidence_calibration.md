# B2 — does verbal confidence predict correctness?

`arXiv:2606.29490` finds reported confidence tracks readiness to commit rather than
correctness — on MCQ and open-ended QA. This is the **extension** to structured,
evidence-cited claims, which that suite did not cover.

- **4 claim(s) carried no technique id or no confidence** and are
  excluded from every number below. They are counted rather than dropped silently:
  omitting them would bias the sample toward claims the model was willing to name.
- AUC is reported as `—` rather than 0.5 when a class is empty.

## All channels  (n=210 claims, 78 correct / 132 wrong)

| metric | value |
|---|---|
| **AUC** (does confidence rank correctness?) | **0.550** |
| **separation** (mean correct − mean wrong) | **+0.014** |
| accuracy | 0.371 |
| mean stated confidence | 0.984 [0.977, 0.990] |
| overconfidence (stated − actual) | +0.613 |
| ECE (5 bins) | 0.613 |
| Brier | 0.604 |

| confidence bin | observed accuracy | n |
|---|---|---|
| [0.8, 1.0) | 0.371 | 210 |

**The reported confidence barely ranks correctness (AUC 0.550).** This
replicates `arXiv:2606.29490` in a setting it did not test — structured,
evidence-cited claims — and it justifies every deterministic gate downstream:
a number that does not separate right from wrong cannot be the thing the
cascade trusts. Converges with §1.10, where the cascade weights moved the
corroborated set on 0.0% of samples.

## Channel: static  (n=56 claims, 14 correct / 42 wrong)

| metric | value |
|---|---|
| **AUC** (does confidence rank correctness?) | **0.648** |
| **separation** (mean correct − mean wrong) | **+0.043** |
| accuracy | 0.250 |
| mean stated confidence | 0.961 [0.943, 0.977] |
| overconfidence (stated − actual) | +0.711 |
| ECE (5 bins) | 0.711 |
| Brier | 0.681 |

| confidence bin | observed accuracy | n |
|---|---|---|
| [0.8, 1.0) | 0.250 | 56 |

## Channel: dynamic  (n=84 claims, 51 correct / 33 wrong)

| metric | value |
|---|---|
| **AUC** (does confidence rank correctness?) | **0.500** |
| **separation** (mean correct − mean wrong) | **+0.000** |
| accuracy | 0.607 |
| mean stated confidence | 1.000 [1.000, 1.000] |
| overconfidence (stated − actual) | +0.393 |
| ECE (5 bins) | 0.393 |
| Brier | 0.393 |

| confidence bin | observed accuracy | n |
|---|---|---|
| [0.8, 1.0) | 0.607 | 84 |

## Channel: network  (n=70 claims, 13 correct / 57 wrong)

| metric | value |
|---|---|
| **AUC** (does confidence rank correctness?) | **0.428** |
| **separation** (mean correct − mean wrong) | **-0.022** |
| accuracy | 0.186 |
| mean stated confidence | 0.984 [0.971, 0.994] |
| overconfidence (stated − actual) | +0.798 |
| ECE (5 bins) | 0.798 |
| Brier | 0.797 |

| confidence bin | observed accuracy | n |
|---|---|---|
| [0.8, 1.0) | 0.186 | 70 |
