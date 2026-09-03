import pytest
from cryptography.fernet import Fernet

from maljan.core import settings_secrets as box


@pytest.fixture
def key(monkeypatch):
    k = Fernet.generate_key().decode()
    monkeypatch.setenv("SETTINGS_ENCRYPTION_KEY", k)
    return k


def test_round_trip(key):
    stored = box.encrypt("sk-live-1234")
    assert stored.startswith(box.PREFIX)
    assert box.is_encrypted(stored)
    assert box.decrypt(stored) == "sk-live-1234"


def test_hint_is_last_four_and_never_more():
    assert box.hint("sk-live-1234") == "1234"
    assert box.hint("ab") == ""


def test_unavailable_without_key(monkeypatch):
    monkeypatch.delenv("SETTINGS_ENCRYPTION_KEY", raising=False)
    assert box.is_available() is False
    with pytest.raises(box.SecretsUnavailable):
        box.encrypt("x")


def test_decrypt_rejects_foreign_token(key, monkeypatch):
    stored = box.encrypt("x")
    monkeypatch.setenv("SETTINGS_ENCRYPTION_KEY", Fernet.generate_key().decode())
    with pytest.raises(box.SecretsUnavailable):
        box.decrypt(stored)


def test_plain_values_are_not_encrypted():
    assert box.is_encrypted("http://localhost:8080") is False
    assert box.is_encrypted(42) is False
