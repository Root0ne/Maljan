"""Where one indicator value ends in the evidence, and where it only seems to.

``whole_value_in`` is the corroboration question's reading of the run's own
evidence: does this value appear there as a value, rather than as a slice of
something longer the run recorded. It treated ``.`` and ``:`` as value
characters at both ends, so a mailbox at the end of a sentence and a host
written after ``mailto:`` were reported as appearing nowhere — and the row was
withheld from the bundle with a sentence saying nothing corroborates it.

Both directions are pinned here, because the fix is only worth having if the
slice it was protecting against is still refused.
"""

from __future__ import annotations

from maljan.agents._indicator_denylists import whole_value_in

MAILBOX = "operator@example.org"
HOST = "gate.example.org"


class TestTheValueIsFound:
    def test_at_the_end_of_a_sentence(self) -> None:
        assert whole_value_in(MAILBOX, f"the dropper mailed {MAILBOX}.")

    def test_before_a_colon_that_introduces_a_list(self) -> None:
        assert whole_value_in(HOST, f"{HOST}: 185.220.101.1")

    def test_before_a_comma_in_a_list(self) -> None:
        assert whole_value_in(HOST, f"{HOST}, a.example.org")

    def test_after_a_scheme(self) -> None:
        assert whole_value_in(MAILBOX, f"the link was mailto:{MAILBOX}")

    def test_after_a_scheme_and_before_a_full_stop(self) -> None:
        assert whole_value_in(HOST, f"it resolved ssh:{HOST}.")

    def test_between_two_characters_no_value_is_written_with(self) -> None:
        assert whole_value_in(HOST, f"the sandbox reached {HOST} on port 443")


class TestTheSliceIsNotFound:
    def test_the_tail_of_an_address_is_not_an_address(self) -> None:
        assert not whole_value_in("168.1.1", "the host was 192.168.1.1")

    def test_a_longer_name_does_not_contain_the_shorter_one(self) -> None:
        assert not whole_value_in(HOST, f"{HOST}.tr was resolved")

    def test_a_prefix_of_a_digest_is_not_the_digest(self) -> None:
        digest = "a" * 32

        assert not whole_value_in(digest[:16], f"md5 {digest}")

    def test_a_name_written_inside_a_longer_token_is_not_found(self) -> None:
        assert not whole_value_in(HOST, f"xn--{HOST}")

    def test_a_scheme_shaped_tail_of_a_longer_token_does_not_open_a_value(self) -> None:
        """The colon after ``5`` of ``10.0.0.5:`` closes a port, not a scheme."""
        assert not whole_value_in("8080", "the sandbox reached 10.0.0.5:80801")

    def test_nothing_is_found_for_an_empty_value(self) -> None:
        assert not whole_value_in("", "anything at all")
