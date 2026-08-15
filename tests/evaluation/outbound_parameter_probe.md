# Does the server act on what we send it?

Each parameter checked by behaviour, not by a response field — a server that
ignores a parameter does not report having done so.

| parameter | observation | verdict |
|---|---|---|
| `temperature` | 1 distinct of 3 at 0.0, 3 of 3 at 2.0 | **honoured** |
| `max_completion_tokens only` | 2805 tokens for a cap of 48 | **IGNORED** |
| `+ max_tokens/n_predict` | 48 tokens for a cap of 48 | **honoured** |
| `enable_thinking=False` | 47-char answer | **honoured** |

`temperature` is the one this probe was written for. E6's M5 argument turns on it:
*a language model at temperature 0, asked 32 times, does not usually agree with itself*
— the sentence that identified a constant as a missed tell. It had never been measured.
