from app.config import settings  # noqa: E402


def test_cors_allows_credentials_and_never_wildcards_origins():
    # Cookies (Set-Cookie / credentialed fetches) require an explicit origin
    # allowlist — a browser refuses to honour "*" together with
    # allow_credentials=True, and if it didn't, this would let any origin
    # read the HttpOnly refresh cookie's responses.
    assert "*" not in settings.cors_origins
    assert settings.cors_origins, "an empty allowlist would be a silent lock-out, not a control"
