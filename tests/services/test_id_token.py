"""Tests for services.tokens.id_token."""

import jwt
import pytest
from freezegun import freeze_time

from services.tokens.id_token import (
    ID_TOKEN_TTL_SECONDS,
    ISSUER,
    generate_id_token,
    merge_provider_claims,
    scope_requires_id_token,
    verify_id_token_on_logout,
)
from tests.factories import DEFAULT_CLIENT_ID


class TestScopeRequiresIdToken:
    @pytest.mark.parametrize(
        "scope", ["openid", "openid email", "email openid profile"]
    )
    def test_true_when_openid_is_requested(self, scope):
        assert scope_requires_id_token(scope) is True

    @pytest.mark.parametrize("scope", ["email profile", "", None, "openidfoo"])
    def test_false_otherwise(self, scope):
        # "openidfoo" must not match - the check is on whole scope tokens.
        assert scope_requires_id_token(scope) is False


class TestGenerateIdToken:
    def test_audience_is_the_client_id(self, decode_token):
        # An ID token is for the client, unlike an access token which targets an API.
        token = generate_id_token(
            {"client_id": DEFAULT_CLIENT_ID, "sub": "cp1|abc", "scope": "openid"}
        )
        assert decode_token(token)["aud"] == DEFAULT_CLIENT_ID

    def test_carries_the_required_oidc_claims(self, decode_token):
        with freeze_time("2026-01-01 00:00:00"):
            token = generate_id_token(
                {"client_id": DEFAULT_CLIENT_ID, "sub": "cp1|abc", "scope": "openid"}
            )
            claims = decode_token(token)
        assert claims["iss"] == ISSUER
        assert claims["sub"] == "cp1|abc"
        assert claims["exp"] - claims["iat"] == ID_TOKEN_TTL_SECONDS

    def test_email_scope_adds_email_claims(self, decode_token):
        token = generate_id_token(
            {
                "client_id": DEFAULT_CLIENT_ID,
                "sub": "cp1|abc",
                "scope": "openid email",
                "provider_claims": {
                    "email": "test@checkpointone.com",
                    "email_verified": True,
                    "name": "Should Not Appear",
                },
            }
        )
        claims = decode_token(token)
        assert claims["email"] == "test@checkpointone.com"
        assert claims["email_verified"] is True
        # profile was not requested, so its claims must not leak in.
        assert "name" not in claims

    def test_profile_scope_adds_profile_claims(self, decode_token):
        token = generate_id_token(
            {
                "client_id": DEFAULT_CLIENT_ID,
                "sub": "cp1|abc",
                "scope": "openid profile",
                "provider_claims": {"name": "Test Person", "picture": "https://img"},
            }
        )
        claims = decode_token(token)
        assert claims["name"] == "Test Person"
        assert claims["picture"] == "https://img"

    def test_claims_absent_from_the_provider_are_simply_omitted(self, decode_token):
        token = generate_id_token(
            {
                "client_id": DEFAULT_CLIENT_ID,
                "sub": "cp1|abc",
                "scope": "openid profile",
                "provider_claims": {"name": "Only Name"},
            }
        )
        claims = decode_token(token)
        assert claims["name"] == "Only Name"
        assert "picture" not in claims

    def test_missing_provider_claims_still_produces_a_valid_token(self, decode_token):
        token = generate_id_token(
            {"client_id": DEFAULT_CLIENT_ID, "sub": "cp1|abc", "scope": "openid email"}
        )
        assert decode_token(token)["sub"] == "cp1|abc"

    def test_is_signed_with_the_advertised_key(self, signing_key):
        token = generate_id_token(
            {"client_id": DEFAULT_CLIENT_ID, "sub": "cp1|abc", "scope": "openid"}
        )
        assert jwt.get_unverified_header(token)["kid"] == signing_key["kid"]
        claims = jwt.decode(
            token,
            signing_key["public"],
            algorithms=["RS256"],
            audience=DEFAULT_CLIENT_ID,
            issuer=ISSUER,
        )
        assert claims["sub"] == "cp1|abc"

    def test_raises_when_scope_is_missing(self):
        # generate_id_token does .split(" ") on the scope; documenting that a
        # caller must always supply one.
        with pytest.raises(AttributeError):
            generate_id_token({"client_id": DEFAULT_CLIENT_ID, "sub": "cp1|abc", "scope": None})


class TestVerifyIdTokenOnLogout:
    def _token(self, **overrides):
        metadata = {
            "client_id": DEFAULT_CLIENT_ID,
            "sub": "cp1|abc",
            "scope": "openid",
        }
        metadata.update(overrides)
        return generate_id_token(metadata)

    def test_accepts_a_token_this_server_issued(self):
        claims = verify_id_token_on_logout(self._token())
        assert claims["sub"] == "cp1|abc"
        assert claims["iss"] == ISSUER

    def test_accepts_an_expired_token(self):
        # RP-initiated logout deliberately tolerates expiry: the id_token_hint
        # identifies the session being ended, and a user logging out after their
        # token lapsed still needs the logout to work.
        with freeze_time("2026-01-01 00:00:00"):
            token = self._token()
        with freeze_time("2027-01-01 00:00:00"):
            assert verify_id_token_on_logout(token)["sub"] == "cp1|abc"

    def test_ignores_audience_so_any_registered_client_may_present_it(self):
        token = generate_id_token(
            {"client_id": "some-other-client", "sub": "cp1|abc", "scope": "openid"}
        )
        assert verify_id_token_on_logout(token)["aud"] == "some-other-client"

    def test_rejects_a_token_signed_by_someone_else(self):
        forged = jwt.encode(
            {"iss": ISSUER, "sub": "cp1|abc"}, "attacker-secret", algorithm="HS256"
        )
        with pytest.raises(jwt.InvalidTokenError):
            verify_id_token_on_logout(forged)

    def test_rejects_a_token_from_a_different_issuer(self):
        import utility.jwt_keys as keys

        token = jwt.encode(
            {"iss": "https://evil.test", "sub": "cp1|abc"},
            keys.JWT_PRIVATE_KEY,
            algorithm="RS256",
        )
        with pytest.raises(jwt.InvalidIssuerError):
            verify_id_token_on_logout(token)

    def test_rejects_a_tampered_payload(self):
        header, payload, signature = self._token().split(".")
        with pytest.raises(jwt.InvalidTokenError):
            verify_id_token_on_logout(f"{header}.{payload[:-4]}AAAA.{signature}")

    def test_rejects_malformed_input(self):
        with pytest.raises(jwt.InvalidTokenError):
            verify_id_token_on_logout("not-a-jwt")


class TestMergeProviderClaims:
    def test_requires_scope_to_be_a_list(self):
        # Matched on a fragment that survives fixing the "explicilty" typo in
        # the source message.
        with pytest.raises(TypeError, match="list of strings"):
            merge_provider_claims("openid email", {}, {})

    def test_returns_claims_untouched_without_openid(self):
        base = {"sub": "cp1|abc"}
        result = merge_provider_claims(["email"], base, {"email": "a@b.c"})
        assert result == {"sub": "cp1|abc"}

    def test_copies_only_the_claims_for_requested_scopes(self):
        provider = {
            "email": "a@b.c",
            "email_verified": True,
            "name": "Test",
            "phone_number": "+15555555555",
            "address": {"country": "US"},
        }
        result = merge_provider_claims(["openid", "email", "address"], {}, provider)
        assert result["email"] == "a@b.c"
        assert result["email_verified"] is True
        assert result["address"] == {"country": "US"}
        assert "name" not in result
        assert "phone_number" not in result

    def test_phone_scope_copies_phone_claims(self):
        result = merge_provider_claims(
            ["openid", "phone"],
            {},
            {"phone_number": "+15555555555", "phone_number_verified": False},
        )
        assert result["phone_number"] == "+15555555555"
        assert result["phone_number_verified"] is False

    def test_mutates_and_returns_the_same_dictionary(self):
        base = {"sub": "cp1|abc"}
        result = merge_provider_claims(["openid", "email"], base, {"email": "a@b.c"})
        assert result is base

    def test_falsey_provider_values_are_still_copied(self):
        # email_verified=False must survive; only absent keys are skipped.
        result = merge_provider_claims(
            ["openid", "email"], {}, {"email": "a@b.c", "email_verified": False}
        )
        assert result["email_verified"] is False
