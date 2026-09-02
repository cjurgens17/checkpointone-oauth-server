"""Tests for services.tokens.refresh_token - opaque token minting and validity."""

from datetime import datetime, timedelta, timezone

import pytest

from services.tokens.refresh_token import (
    DEFAULT_REFRESH_TOKEN_ABSOLUTE_TTL,
    DEFAULT_REFRESH_TOKEN_IDLE_TIME,
    REFRESH_TOKEN_BYTE_LENGTH,
    generate_absolute_exp,
    generate_exp,
    generate_refresh_token_tag,
    hash_refresh_token,
    refresh_token_validity_metadata,
    scope_requires_refresh_token,
)
from tests.factories import make_refresh_token_record
from utility.constants import RevokeReason
from utility.helpers import hash_sha256


class TestGenerateRefreshTokenTag:
    def test_produces_a_url_safe_string(self):
        token = generate_refresh_token_tag()
        assert isinstance(token, str)
        # token_urlsafe emits roughly 4/3 characters per byte of entropy.
        assert len(token) >= REFRESH_TOKEN_BYTE_LENGTH

    def test_values_do_not_repeat(self):
        assert len({generate_refresh_token_tag() for _ in range(500)}) == 500


class TestHashRefreshToken:
    def test_is_sha256_of_the_token(self):
        assert hash_refresh_token("abc") == hash_sha256("abc")

    def test_is_deterministic_so_lookups_work(self):
        token = generate_refresh_token_tag()
        assert hash_refresh_token(token) == hash_refresh_token(token)

    def test_does_not_return_the_token_itself(self):
        # Only the hash is persisted, so a database read cannot recover the
        # bearer token.
        token = generate_refresh_token_tag()
        assert hash_refresh_token(token) != token


class TestScopeRequiresRefreshToken:
    @pytest.mark.parametrize(
        "scope", ["offline_access", "openid offline_access", "offline_access openid"]
    )
    def test_true_when_offline_access_requested(self, scope):
        assert scope_requires_refresh_token(scope) is True

    @pytest.mark.parametrize("scope", ["openid email", "", None, "offline_accessx"])
    def test_false_otherwise(self, scope):
        assert scope_requires_refresh_token(scope) is False


class TestExpiryGeneration:
    def test_idle_expiry_is_the_configured_offset(self):
        issued = datetime(2026, 1, 1, tzinfo=timezone.utc)
        assert generate_exp(issued) == issued + timedelta(
            seconds=DEFAULT_REFRESH_TOKEN_IDLE_TIME
        )

    def test_absolute_expiry_is_the_configured_offset(self):
        issued = datetime(2026, 1, 1, tzinfo=timezone.utc)
        assert generate_absolute_exp(issued) == issued + timedelta(
            seconds=DEFAULT_REFRESH_TOKEN_ABSOLUTE_TTL
        )

    def test_absolute_expiry_is_later_than_idle_expiry(self):
        issued = datetime(2026, 1, 1, tzinfo=timezone.utc)
        assert generate_absolute_exp(issued) > generate_exp(issued)


class TestRefreshTokenValidityMetadata:
    def test_a_fresh_token_is_valid(self):
        record = make_refresh_token_record()
        metadata = refresh_token_validity_metadata(record)
        assert metadata["valid"] is True
        assert metadata["already_used"] is False
        assert metadata["revoked"] is False
        assert metadata["expired"] is False

    def test_reports_the_family_so_reuse_can_revoke_the_chain(self):
        record = make_refresh_token_record()
        metadata = refresh_token_validity_metadata(record)
        assert metadata["family_id"] == record.family_id

    def test_a_used_token_is_not_valid(self):
        # This is the reuse signal that triggers family revocation.
        record = make_refresh_token_record(used_at=datetime.now(timezone.utc))
        metadata = refresh_token_validity_metadata(record)
        assert metadata["already_used"] is True
        assert metadata["valid"] is False

    def test_a_revoked_token_is_not_valid(self):
        record = make_refresh_token_record(
            revoked_at=datetime.now(timezone.utc),
            revoke_reason=RevokeReason.LOGOUT,
        )
        metadata = refresh_token_validity_metadata(record)
        assert metadata["revoked"] is True
        assert metadata["valid"] is False
        assert metadata["revoke_reason"] == RevokeReason.LOGOUT

    def test_idle_expiry_makes_a_token_invalid(self):
        issued = datetime.now(timezone.utc) - timedelta(days=30)
        record = make_refresh_token_record(
            iat=issued,
            exp=issued + timedelta(days=7),
            absolute_exp=issued + timedelta(days=90),
        )
        metadata = refresh_token_validity_metadata(record)
        assert metadata["expired"] is True
        assert metadata["valid"] is False

    def test_absolute_expiry_makes_a_token_invalid_even_when_recently_used(self):
        # A token kept alive by constant rotation must still die at the absolute
        # ceiling, which is the point of tracking absolute_exp separately.
        now = datetime.now(timezone.utc)
        record = make_refresh_token_record(
            exp=now + timedelta(days=7),
            absolute_exp=now - timedelta(seconds=1),
        )
        metadata = refresh_token_validity_metadata(record)
        assert metadata["expired"] is True
        assert metadata["valid"] is False

    def test_expiry_is_evaluated_against_a_supplied_clock(self):
        issued = datetime(2026, 1, 1, tzinfo=timezone.utc)
        record = make_refresh_token_record(
            iat=issued,
            exp=issued + timedelta(days=7),
            absolute_exp=issued + timedelta(days=14),
        )
        before = refresh_token_validity_metadata(record, issued + timedelta(days=1))
        after = refresh_token_validity_metadata(record, issued + timedelta(days=8))
        assert before["valid"] is True
        assert after["expired"] is True

    def test_expiry_boundary_is_inclusive(self):
        # now >= exp counts as expired, so a token is dead exactly at its expiry.
        issued = datetime(2026, 1, 1, tzinfo=timezone.utc)
        record = make_refresh_token_record(
            iat=issued,
            exp=issued + timedelta(days=7),
            absolute_exp=issued + timedelta(days=14),
        )
        at_expiry = refresh_token_validity_metadata(record, issued + timedelta(days=7))
        assert at_expiry["expired"] is True

    def test_a_token_can_be_used_revoked_and_expired_at_once(self):
        issued = datetime.now(timezone.utc) - timedelta(days=30)
        record = make_refresh_token_record(
            iat=issued,
            exp=issued + timedelta(days=7),
            absolute_exp=issued + timedelta(days=14),
            used_at=datetime.now(timezone.utc),
            revoked_at=datetime.now(timezone.utc),
            revoke_reason=RevokeReason.REUSE,
        )
        metadata = refresh_token_validity_metadata(record)
        assert metadata["already_used"] is True
        assert metadata["revoked"] is True
        assert metadata["expired"] is True
        assert metadata["valid"] is False
