"""Tests for services.connections.google.

Outbound HTTP is intercepted with ``responses`` and Google's signing key is
replaced with the suite's own, so nothing here reaches the network.
"""

import time

import jwt
import pytest
import responses
from freezegun import freeze_time

import services.connections.google as google
from services.connections.google import (
    GOOGLE_CLIENT_ID,
    GOOGLE_ISSUER,
    GOOGLE_TOKEN_ENDPOINT,
    exchange_code_for_id_token,
    prepare_redirect_to_oauth_server,
    verify_google_id_token,
)
from utility.redis.cache import cache_get


class TestPrepareRedirectToOauthServer:
    def test_returns_an_opaque_state_value(self):
        state = prepare_redirect_to_oauth_server({"client_id": "client_x"})
        assert isinstance(state, str)
        assert state

    def test_caches_the_request_under_the_state(self):
        # The federated leg carries no other way home; the original OAuth request
        # has to be recoverable from the state Google echoes back.
        request = {"client_id": "client_x", "redirect_uri": "https://app.test/cb"}
        state = prepare_redirect_to_oauth_server(request)
        assert cache_get(state) == {"resource_owner": request}

    def test_each_call_gets_a_distinct_state(self):
        states = {prepare_redirect_to_oauth_server({}) for _ in range(100)}
        assert len(states) == 100

    def test_state_entry_expires(self, fake_redis):
        state = prepare_redirect_to_oauth_server({})
        assert 0 < fake_redis.ttl(state) <= 1000


class TestExchangeCodeForIdToken:
    @responses.activate
    def test_returns_the_id_token_from_a_successful_exchange(self):
        responses.post(GOOGLE_TOKEN_ENDPOINT, json={"id_token": "the.id.token"})
        assert exchange_code_for_id_token("auth-code") == "the.id.token"

    @responses.activate
    def test_posts_the_code_and_client_credentials(self):
        responses.post(GOOGLE_TOKEN_ENDPOINT, json={"id_token": "t"})
        exchange_code_for_id_token("auth-code")

        body = responses.calls[0].request.body
        assert "code=auth-code" in body
        assert "grant_type=authorization_code" in body
        assert "client_secret=" in body

    @responses.activate
    def test_raises_when_google_returns_a_non_json_body(self):
        responses.post(GOOGLE_TOKEN_ENDPOINT, body="upstream exploded", status=500)
        with pytest.raises(ValueError, match="Google token exchange failed"):
            exchange_code_for_id_token("auth-code")

    @responses.activate
    def test_raises_when_the_response_has_no_id_token(self):
        # An OAuth error document parses as JSON but carries no token; the
        # KeyError documents that this path is currently unhandled.
        responses.post(GOOGLE_TOKEN_ENDPOINT, json={"error": "invalid_grant"})
        with pytest.raises(KeyError):
            exchange_code_for_id_token("auth-code")


class TestVerifyGoogleIdToken:
    """Google's JWKS lookup is replaced with the suite's own key.

    ``_jwks_client`` is module-level and would otherwise fetch Google's real
    certificates, so the signing key it resolves is swapped for the local one and
    tokens are minted with the matching private key.
    """

    @pytest.fixture
    def google_signed(self, monkeypatch, signing_key):
        class _StubKey:
            key = signing_key["public"]

        monkeypatch.setattr(
            google._jwks_client,
            "get_signing_key_from_jwt",
            lambda token: _StubKey(),
        )

        def _mint(**overrides):
            now = int(time.time())
            claims = {
                "iss": GOOGLE_ISSUER,
                "aud": GOOGLE_CLIENT_ID,
                "sub": "1234567890",
                "email": "person@gmail.com",
                "email_verified": True,
                "iat": now,
                "exp": now + 3600,
            }
            claims.update(overrides)
            return jwt.encode(claims, signing_key["private"], algorithm="RS256")

        return _mint

    def test_accepts_a_well_formed_google_token(self, google_signed):
        claims = verify_google_id_token(google_signed())
        assert claims["sub"] == "1234567890"
        assert claims["email"] == "person@gmail.com"

    def test_rejects_a_token_for_a_different_audience(self, google_signed):
        # Guards against a token minted for another Google client being replayed
        # at this authorization server.
        with pytest.raises(jwt.InvalidAudienceError):
            verify_google_id_token(google_signed(aud="some-other-client-id"))

    def test_rejects_a_token_from_a_different_issuer(self, google_signed):
        with pytest.raises(jwt.InvalidIssuerError):
            verify_google_id_token(google_signed(iss="https://evil.test"))

    def test_rejects_an_expired_token(self, google_signed):
        now = int(time.time())
        with pytest.raises(jwt.ExpiredSignatureError):
            verify_google_id_token(google_signed(iat=now - 7200, exp=now - 3600))

    def test_rejects_a_token_issued_in_the_future(self, google_signed):
        """An iat ahead of now suggests a replayed or forged assertion.

        PyJWT validates iat during ``jwt.decode`` and raises
        ``ImmatureSignatureError`` (a subclass of ``InvalidTokenError``) before
        control returns to ``verify_google_id_token``. The module's own
        ``if claims["iat"] > time.time()`` check therefore never executes - it is
        redundant with the library rather than load-bearing. It is harmless, but
        anyone reading it should know the library is what actually enforces this.
        """
        future = int(time.time()) + 600
        with pytest.raises(jwt.ImmatureSignatureError):
            verify_google_id_token(google_signed(iat=future, exp=future + 3600))

    def test_rejects_a_token_signed_with_the_wrong_key(self, monkeypatch, signing_key):
        class _StubKey:
            key = signing_key["public"]

        monkeypatch.setattr(
            google._jwks_client, "get_signing_key_from_jwt", lambda token: _StubKey()
        )
        now = int(time.time())
        forged = jwt.encode(
            {
                "iss": GOOGLE_ISSUER,
                "aud": GOOGLE_CLIENT_ID,
                "sub": "1",
                "iat": now,
                "exp": now + 3600,
            },
            "attacker-secret",
            algorithm="HS256",
        )
        with pytest.raises(jwt.InvalidTokenError):
            verify_google_id_token(forged)

    def test_a_token_valid_now_becomes_invalid_later(self, google_signed):
        with freeze_time("2026-01-01 00:00:00"):
            token = google_signed()
            assert verify_google_id_token(token)["sub"] == "1234567890"
        with freeze_time("2026-01-01 02:00:00"):
            with pytest.raises(jwt.ExpiredSignatureError):
                verify_google_id_token(token)
