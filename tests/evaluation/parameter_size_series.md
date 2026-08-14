# C6 — does F1 track parameter count on this task?

Same five fixtures, same `single`-arm prompt, same 2,400-token output budget.
The arms differ in the model and in nothing else we control.

| arm | model | total | active | mean F1 | n |
|---|---|---|---|---|---|
| local | Qwen3.6-35B-A3B (IQ3_K_R4) | 35B | 3B | 0.4136 | 25 |
| default | nvidia/nemotron-3-super-120b-a12b:free | 120B | 12B | 0.4162 | 25 |

**Incomplete: 2 of 4 arms have scores.** The correlation is not
computed — a rho over the arms that happened to finish would describe which
endpoints answered, not which models are larger.
