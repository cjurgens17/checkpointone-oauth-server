"""Tests for services.tokens.access_token."""

import jwt
import pytest
from freezegun import freeze_time

import services.tokens.access_token as access_token_module
from services.tokens.access_token import (
    ACCESS_TOKEN_TTL_SECONDS,
    ISSUER,
    create_access_token,
    create_confidential_client_access_token,
)
from tests.factories import DEFAULT_AUDIENCE, make_user


@pytest.fixture
def user(monkeypatch):
    """Stub the subject lookup - create_access_token resolves sub via the database."""
    subject = make_user()
    monkeypatch.setattr(
        access_token_module, "get_user_from_sub", lambda sub: subject
    )
    return subject


class TestCreateAccessToken:
    def test_issues_a_token_carrying_the_required_claims(self, user, decode_token):
        token = create_access_token(
            {"sub": user.sub, "audience": DEFAULT_AUDIENCE, "scope": "openid email"}
        )
        claims = decode_token(token)

        assert claims["iss"] == ISSUER
        assert claims["aud"] == DEFAULT_AUDIENCE
        assert claims["sub"] == user.sub
        assert claims["scope"] == "openid email"
        assert claims["jti"]

    def test_subject_comes_from_the_stored_user_not_the_request(
        self, monkeypatch, decode_token
    ):
        # The caller-supplied sub is only a lookup key; the claim is taken from
        # the persisted user, so a forged sub cannot be echoed into a token.
        stored = make_user(sub="cp1|authoritative")
        monkeypatch.setattr(
            access_token_module, "get_user_from_sub", lambda sub: stored
        )
        token = create_access_token(
            {"sub": "cp1|attacker-supplied", "audience": DEFAULT_AUDIENCE}
        )
        assert decode_token(token)["sub"] == "cp1|authoritative"

    def test_expiry_is_the_configured_ttl_after_issuance(self, user, decode_token):
        with freeze_time("2026-01-01 00:00:00"):
            token = create_access_token(
                {"sub": user.sub, "audience": DEFAULT_AUDIENCE}
            )
            claims = decode_token(token)
        assert claims["exp"] - claims["iat"] == ACCESS_TOKEN_TTL_SECONDS

    def test_is_signed_with_rs256_and_advertises_the_key_id(self, user, signing_key):
        token = create_access_token({"sub": user.sub, "audience": DEFAULT_AUDIENCE})
        header = jwt.get_unverified_header(token)
        assert header["alg"] == "RS256"
        assert header["kid"] == signing_key["kid"]

    def test_verifies_against_the_published_public_key(self, user, signing_key):
        token = create_access_token({"sub": user.sub, "audience": DEFAULT_AUDIENCE})
        claims = jwt.decode(
            token,
            signing_key["public"],
            algorithms=["RS256"],
            audience=DEFAULT_AUDIENCE,
            issuer=ISSUER,
        )
        assert claims["sub"] == user.sub

    def test_each_token_gets_a_distinct_jti(self, user, decode_token):
        identifiers = {
            decode_token(
                create_access_token({"sub": user.sub, "audience": DEFAULT_AUDIENCE})
            )["jti"]
            for _ in range(20)
        }
        assert len(identifiers) == 20

    def test_a_tampered_token_fails_verification(self, user, signing_key):
        token = create_access_token({"sub": user.sub, "audience": DEFAULT_AUDIENCE})
        header, payload, signature = token.split(".")
        forged = f"{header}.{payload[:-4]}AAAA.{signature}"
        with pytest.raises(jwt.InvalidTokenError):
            jwt.decode(
                forged,
                signing_key["public"],
                algorithms=["RS256"],
                options={"verify_aud": False},
            )

    def test_an_expired_token_is_rejected(self, user, signing_key):
        with freeze_time("2026-01-01 00:00:00"):
            token = create_access_token(
                {"sub": user.sub, "audience": DEFAULT_AUDIENCE}
            )
        with freeze_time("2026-01-01 02:00:00"):
            with pytest.raises(jwt.ExpiredSignatureError):
                jwt.decode(
                    token,
                    signing_key["public"],
                    algorithms=["RS256"],
                    options={"verify_aud": False},
                )

    def test_missing_scope_is_emitted_as_null(self, user, decode_token):
        # client_metadata without a scope still produces a token; the claim is
        # present and null rather than omitted.
        token = create_access_token({"sub": user.sub, "audience": DEFAULT_AUDIENCE})
        assert decode_token(token)["scope"] is None

    def test_raises_when_the_subject_cannot_be_resolved(self, monkeypatch):
        monkeypatch.setattr(access_token_module, "get_user_from_sub", lambda sub: None)
        with pytest.raises(AttributeError):
            create_access_token({"sub": "cp1|missing", "audience": DEFAULT_AUDIENCE})


class TestCreateConfidentialClientAccessToken:
    def test_subject_is_the_client_id(self, decode_token):
        # A client_credentials token has no end user, so the client is the subject.
        token = create_confidential_client_access_token(
            {"client_id": "client_service", "audience": DEFAULT_AUDIENCE}
        )
        assert decode_token(token)["sub"] == "client_service"

    def test_scope_comes_from_the_permissions_key(self, decode_token):
        token = create_confidential_client_access_token(
            {
                "client_id": "client_service",
                "audience": DEFAULT_AUDIENCE,
                "permissions": "read:things write:things",
            }
        )
        assert decode_token(token)["scope"] == "read:things write:things"

    def test_does_not_touch_the_user_table(self, decode_token):
        # No get_user_from_sub stub is installed here; the database guard in
        # conftest would fail this test if the machine flow tried to look a
        # user up.
        token = create_confidential_client_access_token(
            {"client_id": "client_service", "audience": DEFAULT_AUDIENCE}
        )
        assert decode_token(token)["sub"] == "client_service"

    def test_carries_issuer_audience_and_lifetime(self, decode_token):
        with freeze_time("2026-01-01 00:00:00"):
            token = create_confidential_client_access_token(
                {"client_id": "client_service", "audience": DEFAULT_AUDIENCE}
            )
            claims = decode_token(token)
        assert claims["iss"] == ISSUER
        assert claims["aud"] == DEFAULT_AUDIENCE
        assert claims["exp"] - claims["iat"] == ACCESS_TOKEN_TTL_SECONDS

    def test_each_token_gets_a_distinct_jti(self, decode_token):
        identifiers = {
            decode_token(
                create_confidential_client_access_token(
                    {"client_id": "client_service", "audience": DEFAULT_AUDIENCE}
                )
            )["jti"]
            for _ in range(20)
        }
        assert len(identifiers) == 20
