"""A long run of backslashes before a quote is written out in one pass.

The question an analyst asks reaches the pack's quoting, so a text made
of many backslashes must not cost time in the square of its length.
"""

from __future__ import annotations

import time

from maljan.utils.written_forms import quoted_backslashes_written_out


def test_every_backslash_before_a_quote_is_written_out() -> None:
    assert quoted_backslashes_written_out('a\\\\"b') == 'a\\x5c\\x5c"b'
    assert quoted_backslashes_written_out('x\\"y\\z') == 'x\\x5c"y\\z'
    assert quoted_backslashes_written_out("no quote \\\\") == "no quote \\\\"


def test_a_long_run_with_no_quote_after_it_grows_linearly() -> None:
    def spent(n: int) -> float:
        text = '"' + "\\" * n
        best = float("inf")
        for _ in range(3):
            started = time.perf_counter()
            quoted_backslashes_written_out(text)
            best = min(best, time.perf_counter() - started)
        return best

    small, large = spent(5_000), spent(40_000)
    # Eight times the run: linear is about 8x, a rescan from every backslash about 64x.
    assert large < small * 24 + 0.01, (small, large)
