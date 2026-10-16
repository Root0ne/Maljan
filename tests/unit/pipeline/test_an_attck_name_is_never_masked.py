"""An ATT&CK technique or tactic name is never masked, and every secret still is.

A judge message carried ``Token Impersonation`` and the event scrub printed
``Token ***``: the label rule masks what follows ``Bearer``, ``Basic`` and
``token`` unless the two are a vendored ATT&CK name, and it matched only the
whole name ``Token Impersonation/Theft``. A slash in an ATT&CK name joins
alternatives, so each alternative is that name too. An id of the vendored table
after a label (``Make and Impersonate Token (T1134.003)``) is never a
credential, and a technique name that is one token and stands as a whole run
(``SyncAppvPublishingServer``) is a name, not a key.

Every rule is matched as written and against the vendored table alone; what
follows a name that ends with a label word is read by the label rule as before
(``Application Access Token <value>`` reads as a credential), and every key
shape after every label is masked as it was.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from maljan.pipeline import events as ev
from maljan.pipeline.events import safe_finding_value, scrub, scrub_keeping_layout
from tests.credential_shapes import password
from tests.unit.pipeline.test_live_event_schema import _every_key_shape

ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(autouse=True)
def _no_configured_values() -> Iterator[None]:
    ev.forget_secret_values()
    yield
    ev.forget_secret_values()


def _vendored() -> list[tuple[str, str]]:
    """Every (name, id) of the vendored table: its techniques, then its tactics."""
    table = json.loads((ROOT / "data" / "attck_techniques.json").read_text(encoding="utf-8"))
    pairs = [
        (str(row["name"]), key)
        for key, row in table.items()
        if not key.startswith("_") and isinstance(row, dict) and row.get("name")
    ]
    for tactics in table["_tactics"].values():
        pairs += [(str(t["name"]), str(t["id"])) for t in tactics.values()]
    return pairs


def _every_reading(text: str) -> list[str]:
    """The text as an event, a laid-out event and a finding row in both modes carry it."""
    readings = [scrub(text), scrub_keeping_layout(text), safe_finding_value(text)]
    ev.remember_secret_values(["an-operator-value-of-this-job-1234"], scope="job")
    try:
        readings.append(safe_finding_value(text))
    finally:
        ev.forget_secret_values()
    return readings


class TestTheNameAJudgeWrote:
    @pytest.mark.parametrize(
        "text",
        [
            "Token Impersonation",
            "T1134.001 Token Impersonation",
            "It uses Token Impersonation (T1134.001) to raise its privileges.",
            "Token Impersonation.",
            "Token Impersonation, then",
            "Token Theft",
            "Token Impersonation/Theft",
            "Access Token Manipulation",
        ],
    )
    def test_the_technique_name_is_kept_whole(self, text: str) -> None:
        for reading in _every_reading(text):
            assert reading == text

    @pytest.mark.parametrize(
        "text",
        [
            "Token Impersonations",
            "Token Theftx",
            "token impersonation",
            "Access token manipulation",
            "Refresh Token Impersonation/Theft/Abuse",
        ],
    )
    def test_a_word_the_name_does_not_have_is_still_masked(self, text: str) -> None:
        assert ev._REDACTED in scrub(text)


class TestEveryVendoredName:
    def test_no_word_of_any_technique_or_tactic_name_is_masked(self) -> None:
        pairs = _vendored()
        assert len(pairs) > 900
        for name, technique_id in pairs:
            holds_a_path = re.search(r"(?:^|\s)/\w", name) is not None
            for text in (
                name,
                f"{name} ({technique_id})",
                f"{technique_id} {name}.",
                f"It uses {name}, then stops.",
            ):
                for reading in _every_reading(text):
                    assert ev._REDACTED not in reading, (text, reading)
                    if holds_a_path:
                        # The path rule shortens a path to its last segment
                        # wherever it stands; it masks nothing.
                        words = [w for w in name.split() if "/" not in w]
                        assert all(w in reading for w in words), (text, reading)
                    else:
                        assert name in reading, (text, reading)

    def test_an_id_after_a_label_is_never_a_credential(self) -> None:
        for text in (
            "Make and Impersonate Token (T1134.003)",
            "Create Process with Token (T1134.002)",
            "Visual Basic (T1059.005)",
            "Application Access Token [T1550.001]",
            "Bearer TA0005",
        ):
            assert scrub(text) == text

    def test_an_id_the_table_does_not_hold_is_read_as_any_value(self) -> None:
        assert scrub("Visual Basic (T0000)") == "Visual Basic ***)"
        assert scrub("Bearer T1134.0019") == "Bearer ***"

    def test_a_one_token_name_is_kept_alone_and_read_as_before_when_joined(self) -> None:
        name = "SyncAppvPublishingServer"
        assert scrub(name) == name
        assert scrub(f"It ran {name} (T1216.002).") == f"It ran {name} (T1216.002)."
        for key in _every_key_shape():
            for joined in (f"{name}/{key}", f"{key}/{name}", f"{name}+{key}"):
                assert key not in scrub(joined), joined

    def test_a_one_token_name_after_a_credential_label_is_the_credential(self) -> None:
        """As a family name is read: after ``password=`` the run is the secret, whatever it says."""
        name = "SyncAppvPublishingServer"
        for text in (
            f"password={name}",
            f"api_key: {name}",
            f'secret="{name}"',
            f"the session cookie {name} was sent",
            f"token {name}",
        ):
            assert name not in scrub(text), text
            assert name not in safe_finding_value(text), text


class TestEverySecretIsStillMasked:
    LABELS = (
        "Token ",
        "token ",
        "Bearer ",
        "Basic ",
        "Access Token ",
        "access token ",
        "Application Access Token ",
        "Steal Application Access Token ",
        "Make and Impersonate Token ",
        "Create Process with Token ",
        "Visual Basic ",
        "Token Impersonation/",
        "T1134.001 Token ",
    )

    def test_every_key_shape_after_every_attck_label(self) -> None:
        for key in _every_key_shape():
            for label in self.LABELS:
                for text in (f"{label}{key}", f"the header {label}{key} was sent"):
                    for reading in _every_reading(text)[:3]:
                        assert key not in reading, (label, key)

    def test_a_short_password_after_every_attck_label(self) -> None:
        for length in (4, 8, 12, 30):
            secret = password(length)
            for label in self.LABELS:
                assert secret not in scrub(f"{label}{secret}"), (label, secret)
                assert secret not in scrub(f"{label}({secret})"), (label, secret)


def test_a_hostile_line_of_names_and_labels_is_read_in_linear_time() -> None:
    piece = (
        "Token Impersonation Token Theft Token T1134.003 Access Token Manipulation "
        "SyncAppvPublishingServer Visual Basic (T1059.005) token x Bearer y "
    )

    def took(copies: int) -> float:
        text = piece * copies
        started = time.perf_counter()
        scrub(text)
        return time.perf_counter() - started

    small, large = took(500), took(5000)
    assert large < 20, large
    assert large < 50 * max(small, 0.01), (small, large)
