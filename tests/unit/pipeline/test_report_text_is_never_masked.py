"""Report text keeps the evidence's words and never an operator credential.

A local run's report printed "T1134 Access Token ***" in its validation
findings, and its events masked a family name: the finding rows that the
report prints went through the event scrub, the label rule took the word after
"Token" for a secret, and the length rule took a family name with a
capitalised compound piece for a key.

With the operator's configured values registered, a finding row is no longer
run through the event scrub's shape rules. Every operator credential is still
kept out of it: each configured value by value, a short one as a whole word, a
URL's userinfo, and a query value whose key names a credential. A token in a
URL's username slot and a short URL password are registered too. With nothing
registered, or a registration that failed, a row is held to the whole scrub as
before. In events, an ATT&CK name with a label word in it is kept on an exact
match only, a slash-joined family name with a capitalised compound piece is
kept away from a credential label, and every credential shape is masked
everywhere else, after every label, and across a row's bound.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from maljan.pipeline import events as ev
from maljan.pipeline.events import safe_finding_value, scrub, scrub_keeping_layout
from maljan.pipeline.validation import ValidationTally, Violation
from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity
from maljan.reporting.renderers.markdown import MarkdownRenderer
from tests.credential_shapes import password, prefixed_key
from tests.unit.pipeline.test_live_event_schema import _every_key_shape

TECHNIQUE = "T1134 Access Token Manipulation"
# An invented family name of the shape that was masked: three pieces joined by
# slashes, 24 characters, one piece a capitalised compound.
FAMILY = "Rivulet/NorthWind/Calder"


@pytest.fixture(autouse=True)
def _no_configured_values() -> Iterator[None]:
    ev.forget_secret_values()
    yield
    ev.forget_secret_values()


LABELS = ("Access Token ", "Bearer ", "Authorization: ", "api_key=", "password=", "token ")


class TestTheEventScrubReadsAFamilyNameAsAName:
    def test_a_family_name_with_a_compound_piece_is_kept(self) -> None:
        assert len(FAMILY) >= 24
        assert scrub(f"associated with the {FAMILY} family") == (
            f"associated with the {FAMILY} family"
        )
        assert scrub_keeping_layout(f"Claim 1: the {FAMILY} family") == (
            f"Claim 1: the {FAMILY} family"
        )

    def test_a_family_shaped_value_after_a_credential_label_is_masked(self) -> None:
        for label in LABELS:
            assert FAMILY not in scrub(f"{label}{FAMILY}"), label

    def test_an_attck_name_with_a_label_word_is_kept_on_an_exact_match(self) -> None:
        assert scrub(f"carries TECHNIQUE {TECHNIQUE}, and") == f"carries TECHNIQUE {TECHNIQUE}, and"
        assert scrub("T1134.001 Token Impersonation/Theft") == "T1134.001 Token Impersonation/Theft"

    def test_the_exact_name_keeps_its_exemption_before_sentence_punctuation(self) -> None:
        for end in (".", ",", ";", ":", "!", "?"):
            text = f"It carries {TECHNIQUE}{end} More follows."
            assert scrub(text) == text, end

    def test_anything_else_after_a_label_is_masked(self) -> None:
        assert scrub("Access Token Manipulations") == "Access Token ***"
        assert scrub("Refresh Token Manipulation") == "Refresh Token ***"
        assert scrub("Access token manipulation") == "Access token ***"
        assert scrub("Bearer Manipulation") == "Bearer ***"
        assert scrub("Basic Abcdefgh") == "Basic ***"

    def test_every_key_shape_is_masked_after_every_label(self) -> None:
        for key in _every_key_shape():
            for label in LABELS:
                for text in (f"{label}{key}", f"the header {label}{key} was sent"):
                    assert key not in scrub(text), (label, key)
                    assert key not in scrub_keeping_layout(text), (label, key)

    def test_a_lowercase_password_after_a_label_is_still_masked(self) -> None:
        for length in (4, 8, 12, 30):
            secret = password(length)
            for label in ("token ", "Bearer ", "Basic "):
                assert secret not in scrub(f"{label}{secret}"), (label, secret)

    def test_every_key_shape_is_still_masked_alone_and_in_a_sentence(self) -> None:
        for key in _every_key_shape():
            assert key not in scrub(key), key
            assert key not in scrub(f"the analyst quoted {key} as the key"), key

    def test_runs_that_are_not_a_family_name_are_still_keys(self) -> None:
        for key in (
            "Ab3dEf9h/Kl2nOp4r/St6vWx8z",
            "AbCdEfGhIjKl/MnOpQrStUvWx",
            "Rivulet/NorthWindAlphaBeta/Calder",
        ):
            assert key not in scrub(f"value {key}"), key


def _registered(*values: str, scope: str = "job") -> None:
    """The worker's registration of the configured values, as each job makes it."""
    ev.remember_secret_values(list(values), scope=scope)


def _published(row: str) -> str:
    """A row as an event carries it: through the publisher's scrub."""
    from app.worker.analysis_worker import scrubbed

    return str(scrubbed({"message": row})["message"])


class TestAFindingRowKeepsTheEvidenceWords:
    def test_the_row_keeps_the_catalogue_name(self) -> None:
        _registered()
        assert safe_finding_value(TECHNIQUE) == TECHNIQUE

    def test_the_row_keeps_a_credential_shape_the_evidence_holds(self) -> None:
        _registered()
        key = prefixed_key("ghs_", 36)
        assert safe_finding_value(f"the string {key}") == f"the string {key}"
        assert key not in _published(safe_finding_value(f"the string {key}"))

    def test_the_row_keeps_a_url_and_a_path_as_written(self) -> None:
        _registered()
        value = "http://gate.example.com/live/?id=1 C:\\Users\\op\\x.exe"
        assert safe_finding_value(value) == value

    def test_the_row_is_still_bounded(self) -> None:
        _registered()
        bounded = safe_finding_value("word " * 200)
        assert len(bounded) <= ev.FINDING_VALUE_LIMIT + 1
        assert bounded.endswith(ev.CUT_MARK)

    def test_a_bound_never_splits_a_digest(self) -> None:
        _registered()
        digest = "ab" * 32
        assert digest in safe_finding_value("x " * 90 + digest + " tail " * 20)


class TestNoOperatorCredentialReachesARow:
    """The reviewer's probes: four configured URLs echoed into a row, and dev's pinned case."""

    @staticmethod
    def _configured(url: str) -> None:
        from maljan.core.settings_catalog import configured_secret_values

        _registered(*configured_secret_values({"tool_servers": [{"url": url}]}))

    def test_a_long_url_password(self) -> None:
        secret = password(12, variant=1)
        url = f"https://operator:{secret}@sandbox.example/api"
        self._configured(url)

        row = safe_finding_value(f"the indicator names {url}")

        assert secret not in row and "operator" not in row

    def test_a_short_url_password(self) -> None:
        secret = password(6, variant=2)
        url = f"https://operator:{secret}@sandbox.example/api"
        self._configured(url)

        row = safe_finding_value(f"the indicator names {url}; it says {secret} too")

        assert secret not in row

    def test_a_token_in_the_username_slot(self) -> None:
        token = prefixed_key("ghp_", 36)
        url = f"https://{token}@mcp.example/sse"
        self._configured(url)

        row = safe_finding_value(f"the indicator names {url}, and {token} alone")

        assert token not in row

    def test_a_credential_named_query_value(self) -> None:
        for key in ("api_key", "apikey", "access_token", "token", "key"):
            ev.forget_secret_values()
            secret = password(16, variant=4)
            url = f"https://mcp.example/sse?{key}={secret}&mode=x"
            self._configured(url)

            row = safe_finding_value(f"the indicator names {url}, and {secret} alone")

            assert secret not in row, key
            assert "mode=x" in row, key

    def test_a_credential_named_fragment_value(self) -> None:
        for key in ("access_token", "token", "api_key", "key"):
            ev.forget_secret_values()
            secret = password(16, variant=6)
            url = f"https://idp.example/cb#{key}={secret}&state=keep"
            self._configured(url)

            row = safe_finding_value(f"the indicator names {url}, and {secret} alone")

            assert secret not in row, key
            assert "state=keep" in row, key

    def test_a_fragment_token_in_a_foreign_url_is_removed_from_the_row(self) -> None:
        _registered()
        secret = password(16, variant=7)

        row = safe_finding_value(f"echoed https://idp.example/cb#access_token={secret}")

        assert secret not in row

    def test_dev_s_pinned_userinfo_case(self) -> None:
        _registered()
        secret = prefixed_key("ghs_")
        url = f"http://operator:{secret}@evil.example.com/a?token={secret}"

        row = safe_finding_value(f"[url:value = '{url}']")

        assert secret not in row and "operator" not in row
        assert "evil.example.com/a" in row

    def test_a_configured_value_is_kept_out(self) -> None:
        configured = password(16, variant=3)
        _registered(configured)

        assert configured not in safe_finding_value(f"echoed {configured} back")


class TestAPlainUsernameIsNoSecret:
    """A configured URL's username without a password is a credential only by its shape."""

    URLS = (
        "postgresql+asyncpg://administrator@db.internal/maljan",
        "redis://default@redis:6379/0",
        "http://analyst@ghidra.internal:8080",
        "ssh://git@github.com/org/repo",
    )

    def test_an_ordinary_username_is_not_registered(self) -> None:
        from maljan.core.settings_catalog import configured_secret_values

        found = configured_secret_values({"servers": [{"url": url} for url in self.URLS]})

        assert not {"administrator", "default", "analyst", "git"} & found

    def test_events_and_rows_keep_the_words(self) -> None:
        from maljan.core.settings_catalog import configured_secret_values

        _registered(*configured_secret_values({"servers": [{"url": url} for url in self.URLS]}))

        assert scrub("the administrator logged on") == "the administrator logged on"
        row = safe_finding_value("the analyst said the git default branch; administrator account")
        assert row == "the analyst said the git default branch; administrator account"

    def test_rows_still_lose_the_userinfo(self) -> None:
        _registered()
        row = safe_finding_value(f"see {self.URLS[2]}/api")

        assert "analyst@" not in row and "***@ghidra.internal:8080/api" in row

    def test_a_token_in_the_username_slot_is_still_registered(self) -> None:
        from maljan.core.settings_catalog import configured_secret_values

        token = prefixed_key("ghp_", 36)
        assert token in configured_secret_values({"url": f"https://{token}@mcp.example/sse"})


def _configured_urls() -> list[str]:
    """Every userinfo shape a configured URL takes: a user, a token, short and long passwords."""
    return [
        "postgresql+asyncpg://administrator@db.internal/maljan",
        "ssh://" + "git" + "@github.example/org/repo",
        f"https://{prefixed_key('ghp_', 36)}@mcp.example/sse",
        f"https://u:{password(3)}@sandbox.example/api",
        f"https://operator:{password(6, variant=1)}@sandbox.example/api",
        f"https://operator:{password(24, variant=2)}@sandbox.example/api",
    ]


def _userinfo(url: str) -> str:
    from urllib.parse import urlsplit

    return urlsplit(url).netloc.rsplit("@", 1)[0]


class TestUserinfoIsRemovedWhereverAURLStands:
    """The userinfo of a URL is removed by its position, registered or not."""

    def test_in_events_with_nothing_registered(self) -> None:
        for url in _configured_urls():
            for text in (f"see {url} now", f'{{"url": "{url}"}}'):
                for scrubbed in (scrub(text), scrub_keeping_layout(text)):
                    assert f"{_userinfo(url)}@" not in scrubbed, (url, scrubbed)

    def test_in_rows_in_both_modes(self) -> None:
        for registered in (False, True):
            ev.forget_secret_values()
            if registered:
                from maljan.core.settings_catalog import configured_secret_values

                _registered(
                    *configured_secret_values({"servers": [{"url": u} for u in _configured_urls()]})
                )
            for url in _configured_urls():
                row = safe_finding_value(f"the indicator names {url}")
                assert f"{_userinfo(url)}@" not in row, (registered, url, row)
                assert f"{_userinfo(url)}@" not in _published(row), (registered, url)

    def test_a_word_standing_alone_is_kept_in_events(self) -> None:
        from maljan.core.settings_catalog import configured_secret_values

        _registered(
            *configured_secret_values({"servers": [{"url": u} for u in _configured_urls()]})
        )

        assert scrub("the administrator logged on") == "the administrator logged on"


class TestEveryValueDevMaskedIsStillMasked:
    """Dev registered a configured URL's password; every value it masked is masked here too."""

    @staticmethod
    def _dev_registered(urls: list[str]) -> set[str]:
        from urllib.parse import urlsplit

        return {urlsplit(url).password for url in urls if urlsplit(url).password}

    def test_registration_is_a_superset_of_dev_s(self) -> None:
        from maljan.core.settings_catalog import configured_secret_values

        urls = _configured_urls()
        branch = configured_secret_values({"servers": [{"url": u} for u in urls]})

        assert self._dev_registered(urls) <= branch

    def test_each_value_dev_masked_is_masked_in_events_and_rows(self) -> None:
        from maljan.core.settings_catalog import configured_secret_values

        urls = _configured_urls()
        _registered(*configured_secret_values({"servers": [{"url": u} for u in urls]}))
        for value in self._dev_registered(urls):
            if len(value) < ev.CONFIGURED_SECRET_FLOOR:
                # Dev masked a value under the floor nowhere by value; its URL
                # position is covered by the userinfo tests above.
                continue
            assert value not in scrub(f"echoed {value} alone"), value
            assert value not in safe_finding_value(f"echoed {value} alone"), value


class TestAFailedRegistrationFallsBackToTheWholeScrub:
    def test_nothing_registered_holds_a_row_to_the_scrub(self) -> None:
        key = prefixed_key("ghs_", 36)
        assert safe_finding_value(f"the string {key}") == "the string ***"

    def test_a_failed_scope_holds_a_row_to_the_scrub(self) -> None:
        _registered()
        ev.secret_registration_failed("process")
        key = prefixed_key("ghs_", 36)

        assert safe_finding_value(f"the string {key}") == "the string ***"

    def test_registering_the_scope_again_lifts_it(self) -> None:
        ev.secret_registration_failed("job")
        _registered()

        assert safe_finding_value(TECHNIQUE) == TECHNIQUE

    def test_the_worker_records_a_failed_registration(self) -> None:
        from unittest.mock import patch

        from app.worker import analysis_worker

        _registered(scope="process")
        with patch(
            "maljan.core.settings_catalog.configured_secret_values",
            side_effect=RuntimeError("unreadable"),
        ):
            analysis_worker.remember_configured_secrets(object())

        key = prefixed_key("ghs_", 36)
        assert safe_finding_value(f"the string {key}") == "the string ***"


class TestNoKeyHeadCrossesTheBound:
    def test_every_shape_across_the_cut_leaves_no_fragment_in_the_event(self) -> None:
        for registered in (True, False):
            ev.forget_secret_values()
            if registered:
                _registered()
            for key in _every_key_shape():
                for pad in range(ev.FINDING_VALUE_LIMIT - len(key) - 2, ev.FINDING_VALUE_LIMIT + 2):
                    if pad < 1:
                        continue
                    text = "w" * (pad - 1) + " " + key + " tail of the row"
                    published = _published(safe_finding_value(text))
                    assert not any(key[at : at + 8] in published for at in range(len(key) - 7)), (
                        registered,
                        pad,
                        key,
                        published,
                    )


class TestTheReportMatchesTheEvidence:
    def test_the_printed_finding_carries_the_technique_name_whole(self) -> None:
        _registered()
        tally = ValidationTally()
        tally.record_unresolved(
            "triage",
            [
                Violation(
                    code="attck.claim_does_not_describe",
                    message=f"CLAIM 'x' carries TECHNIQUE {safe_finding_value(TECHNIQUE)}, and …",
                )
            ],
        )
        report = MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
            verdict="Malware",
            run_summary={"validation": tally.to_dict()},
        )

        text = MarkdownRenderer().render(report)

        assert f"TECHNIQUE {TECHNIQUE}, and" in text
        assert "***" not in text
