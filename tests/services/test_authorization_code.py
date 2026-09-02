"""Tests for services.tokens.authorization_code - code issuance, redemption, PKCE."""

from datetime import datetime, timedelta, timezone

import pytest
from freezegun import freeze_time

from services.tokens.authorization_code import (
    AUTH_CODE_TTL_SECONDS,
    auth_code_expired,
    create_auth_code,
    redeem_auth_code,
    valid_code_challenge,
)
from tests.factories import authorization_code_metadata
from utility.helpers import hash_sha256
from utility.redis.cache import cache_get


class TestCreateAuthCode:
    def test_returns_an_opaque_code(self):
        code = create_auth_code({"client_id": "client_x"})
        assert isinstance(code, str)
        assert code

    def test_codes_do_not_repeat(self):
        assert len({create_auth_code({"client_id": "c"}) for _ in range(200)}) == 200

    def test_stores_the_payload_under_the_code(self):
        code = create_auth_code({"client_id": "client_x", "sub": "cp1|abc"})
        stored = cache_get(code)
        assert stored["client_id"] == "client_x"
        assert stored["sub"] == "cp1|abc"

    def test_adds_an_identifier_and_expiry(self):
        code = create_auth_code({"client_id": "client_x"})
        stored = cache_get(code)
        assert stored["id"]
        assert stored["expires_at"]

    def test_expiry_is_the_configured_ttl_ahead(self):
        with freeze_time("2026-01-01 00:00:00"):
            code = create_auth_code({"client_id": "client_x"})
            stored = cache_get(code)
        expires_at = datetime.fromisoformat(stored["expires_at"])
        assert expires_at == datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(
            seconds=AUTH_CODE_TTL_SECONDS
        )

    def test_the_cache_entry_itself_expires(self, fake_redis):
        code = create_auth_code({"client_id": "client_x"})
        assert 0 < fake_redis.ttl(code) <= AUTH_CODE_TTL_SECONDS

    def test_does_not_mutate_the_caller_payload(self):
        payload = {"client_id": "client_x"}
        create_auth_code(payload)
        assert payload == {"client_id": "client_x"}


class TestRedeemAuthCode:
    def test_returns_the_stored_payload(self):
        code = create_auth_code({"client_id": "client_x", "sub": "cp1|abc"})
        redeemed = redeem_auth_code(code)
        assert redeemed["client_id"] == "client_x"
        assert redeemed["sub"] == "cp1|abc"

    def test_a_code_can_only_be_redeemed_once(self):
        # Single use is the core defence for the authorization code grant; a
        # replayed code must yield nothing.
        code = create_auth_code({"client_id": "client_x"})
        assert redeem_auth_code(code) is not None
        assert redeem_auth_code(code) is None

    def test_unknown_code_returns_none(self):
        assert redeem_auth_code("never-issued") is None

    def test_redeeming_one_code_leaves_others_intact(self):
        first = create_auth_code({"client_id": "a"})
        second = create_auth_code({"client_id": "b"})
        redeem_auth_code(first)
        assert redeem_auth_code(second)["client_id"] == "b"


class TestAuthCodeExpired:
    def test_a_future_expiry_is_not_expired(self):
        metadata = {
            "expires_at": (
                datetime.now(timezone.utc) + timedelta(minutes=5)
            ).isoformat()
        }
        assert auth_code_expired(metadata) is False

    def test_a_past_expiry_is_expired(self):
        metadata = {
            "expires_at": (
                datetime.now(timezone.utc) - timedelta(seconds=1)
            ).isoformat()
        }
        assert auth_code_expired(metadata) is True

    def test_missing_expiry_is_treated_as_expired(self):
        # Fail closed: a payload without an expiry must not be honoured.
        assert auth_code_expired({}) is True
        assert auth_code_expired({"expires_at": None}) is True

    def test_a_code_expires_once_its_ttl_elapses(self):
        with freeze_time("2026-01-01 00:00:00"):
            code = create_auth_code({"client_id": "client_x"})
            metadata = cache_get(code)
            assert auth_code_expired(metadata) is False
        with freeze_time("2026-01-01 00:30:00"):
            assert auth_code_expired(metadata) is True


class TestValidCodeChallenge:
    VERIFIER = "test-code-verifier-value"

    def test_accepts_the_matching_verifier(self):
        assert (
            valid_code_challenge(self.VERIFIER, "S256", hash_sha256(self.VERIFIER))
            is True
        )

    def test_method_is_case_insensitive(self):
        assert (
            valid_code_challenge(self.VERIFIER, "s256", hash_sha256(self.VERIFIER))
            is True
        )

    def test_rejects_a_mismatched_verifier(self):
        assert (
            valid_code_challenge("wrong-verifier", "S256", hash_sha256(self.VERIFIER))
            is False
        )

    def test_rejects_the_plain_method(self):
        # Downgrading to plain would defeat PKCE, so it is refused even when the
        # challenge would otherwise match.
        assert valid_code_challenge(self.VERIFIER, "plain", self.VERIFIER) is False

    def test_rejects_an_empty_challenge(self):
        assert valid_code_challenge(self.VERIFIER, "S256", "") is False

    def test_metadata_from_the_factory_round_trips(self):
        metadata = authorization_code_metadata()
        assert (
            valid_code_challenge(
                self.VERIFIER,
                metadata["code_challenge_method"],
                metadata["code_challenge"],
            )
            is True
        )

    @pytest.mark.parametrize("method", [None, ""])
    def test_rejects_a_missing_method_even_with_a_correct_verifier(self, method):
        assert (
            valid_code_challenge(self.VERIFIER, method, hash_sha256(self.VERIFIER))
            is False
        )
