"""``maljan.tools.arguments`` reads one pair of quotes off a search argument, and says so."""

from __future__ import annotations

from maljan.tools import arguments


class TestUnquoted:
    def test_one_matching_pair_of_each_quote_comes_off(self) -> None:
        for wrapped in ('"CreateMutex"', "'CreateMutex'", "`CreateMutex`", '  "CreateMutex" '):
            assert arguments.unquoted(wrapped) == "CreateMutex", wrapped

    def test_a_value_that_is_not_one_enclosed_value_is_left_as_written(self) -> None:
        for kept in ('""CreateMutex""', '"a" or "b"', "'it's'"):
            assert arguments.unquoted(kept) == kept, kept

    def test_the_other_quote_characters_inside_are_part_of_the_value(self) -> None:
        assert arguments.unquoted('"it\'s"') == "it's"

    def test_whitespace_inside_the_quotes_is_part_of_the_value(self) -> None:
        assert arguments.unquoted('" Mutex "') == " Mutex "

    def test_a_value_without_a_surrounding_pair_is_passed_through_exactly(self) -> None:
        for kept in (" CreateMutex", '"CreateMutex', "re:^Create.*$", "it's", '"a" or "b', ""):
            assert arguments.unquoted(kept) == kept, kept


class TestReadUnquoted:
    def test_only_the_named_arguments_are_read(self) -> None:
        read = arguments.read_unquoted({"pattern": '"x"', "text": '"y"'}, ("pattern",))

        assert read.values == {"pattern": "x", "text": '"y"'}
        assert read.read_as == {"pattern": "x"}

    def test_each_string_of_a_list_is_read(self) -> None:
        read = arguments.read_unquoted({"ids": ['"T1055"', "T1027", 7]}, ("ids",))

        assert read.values == {"ids": ["T1055", "T1027", 7]}
        assert read.read_as == {"ids": ["T1055", "T1027", 7]}

    def test_nothing_read_differently_is_nothing_recorded(self) -> None:
        read = arguments.read_unquoted({"pattern": "x", "limit": 5}, ("pattern", "absent"))

        assert read.read_as == {}
        assert read.values == {"pattern": "x", "limit": 5}


class TestTheRecord:
    def test_read_as_leads_a_dict_answer(self) -> None:
        answer = arguments.with_read_as({"strings": [1, 2]}, {"pattern": "x"})

        assert next(iter(answer)) == arguments.READ_AS_KEY
        assert answer == {"read_as": {"pattern": "x"}, "strings": [1, 2]}

    def test_an_answer_with_nothing_repaired_is_untouched(self) -> None:
        original = {"strings": []}

        assert arguments.with_read_as(original, {}) is original

    def test_a_text_answer_is_left_as_text(self) -> None:
        assert arguments.with_read_as("Hash abc not found.", {"file_hash": "abc"}) == (
            "Hash abc not found."
        )

    def test_the_description_names_the_arguments_once(self) -> None:
        @arguments.says_unquoted("query", "text")
        def tool() -> None:
            """Look something up."""

        assert tool.__doc__ is not None
        assert tool.__doc__.startswith("Look something up.")
        assert "``query``, ``text`` as the raw text or pattern itself, unquoted" in tool.__doc__
