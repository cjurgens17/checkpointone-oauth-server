"""Integration tests for repo.refresh_token.

Rotation and reuse-detection depend on real row updates and a real
``SELECT ... FOR UPDATE``, so these run against PostgreSQL.
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from repo.refresh_token import (
    create_refresh_token,
    get_refresh_token_from_token_hash,
    revoke_refresh_token,
    revoke_refresh_token_family,
    update_refresh_token_used_at,
)
from tests.factories import DEFAULT_AUDIENCE, DEFAULT_CLIENT_ID
from utility.constants import RevokeReason

pytestmark = pytest.mark.integration


def _create(seeded_user, **overrides):
    issued_at = overrides.pop("iat", datetime.now(timezone.utc))
    values = {
        "sub": seeded_user.sub,
        "token_hash": f"hash-{uuid.uuid4()}",
        "scope": "openid offline_access",
        "audience": DEFAULT_AUDIENCE,
        "client_id": DEFAULT_CLIENT_ID,
        "iat": issued_at,
        "exp": issued_at + timedelta(days=7),
        "absolute_exp": issued_at + timedelta(days=14),
        "family_id": uuid.uuid4(),
        "parent_id": None,
    }
    values.update(overrides)
    return create_refresh_token(**values)


class TestCreateRefreshToken:
    def test_persists_a_retrievable_token(self, seeded_user, seeded_application):
        created = _create(seeded_user, token_hash="known-hash")
        found = get_refresh_token_from_token_hash("known-hash")
        assert found is not None
        assert found.sub == seeded_user.sub
        assert found.scope == "openid offline_access"
        assert found.audience == DEFAULT_AUDIENCE

    def test_a_new_token_starts_unused_and_unrevoked(self, seeded_user, seeded_application):
        created = _create(seeded_user, token_hash="fresh")
        found = get_refresh_token_from_token_hash("fresh")
        assert found.used_at is None
        assert found.revoked_at is None
        assert found.revoke_reason is None

    def test_token_hash_is_unique(self, seeded_user, seeded_application):
        from sqlalchemy.exc import IntegrityError

        _create(seeded_user, token_hash="duplicate")
        with pytest.raises(IntegrityError):
            _create(seeded_user, token_hash="duplicate")

    def test_records_the_parent_for_a_rotated_token(self, seeded_user, seeded_application):
        parent = _create(seeded_user, token_hash="parent")
        child = _create(
            seeded_user,
            token_hash="child",
            family_id=parent.family_id,
            parent_id=parent.id,
        )
        found = get_refresh_token_from_token_hash("child")
        assert found.parent_id == parent.id
        assert found.family_id == parent.family_id

    def test_revoke_reason_is_constrained(self, database, seeded_user, seeded_application):
        from sqlalchemy.exc import IntegrityError

        created = _create(seeded_user, token_hash="constrained")
        with pytest.raises(IntegrityError):
            with database() as session:
                from sqlalchemy import update

                from models.refresh_token import RefreshToken

                session.execute(
                    update(RefreshToken)
                    .where(RefreshToken.id == created.id)
                    .values(revoke_reason="because_i_said_so")
                )
                session.commit()


class TestGetRefreshTokenFromTokenHash:
    def test_returns_none_for_an_unknown_hash(self, seeded_user, seeded_application):
        _create(seeded_user)
        assert get_refresh_token_from_token_hash("no-such-hash") is None

    @pytest.mark.parametrize("token_hash", ["", None])
    def test_short_circuits_on_empty_input(self, token_hash):
        assert get_refresh_token_from_token_hash(token_hash) is None


class TestUpdateRefreshTokenUsedAt:
    def test_marks_the_token_used(self, seeded_user, seeded_application):
        _create(seeded_user, token_hash="to-use")
        used_at = datetime.now(timezone.utc)
        update_refresh_token_used_at("to-use", used_at)
        assert get_refresh_token_from_token_hash("to-use").used_at is not None

    def test_defaults_to_now(self, seeded_user, seeded_application):
        _create(seeded_user, token_hash="to-use")
        update_refresh_token_used_at("to-use")
        assert get_refresh_token_from_token_hash("to-use").used_at is not None

    def test_returns_none_for_an_unknown_hash(self, seeded_user, seeded_application):
        assert update_refresh_token_used_at("no-such-hash") is None

    @pytest.mark.parametrize("token_hash", ["", None])
    def test_short_circuits_on_empty_input(self, token_hash):
        assert update_refresh_token_used_at(token_hash) is None

    def test_does_not_touch_other_tokens(self, seeded_user, seeded_application):
        _create(seeded_user, token_hash="target")
        _create(seeded_user, token_hash="bystander")
        update_refresh_token_used_at("target")
        assert get_refresh_token_from_token_hash("bystander").used_at is None


class TestRevokeRefreshToken:
    def test_records_the_revocation_and_reason(self, seeded_user, seeded_application):
        _create(seeded_user, token_hash="to-revoke")
        revoke_refresh_token("to-revoke", RevokeReason.ROTATE)
        found = get_refresh_token_from_token_hash("to-revoke")
        assert found.revoked_at is not None
        assert found.revoke_reason == RevokeReason.ROTATE

    @pytest.mark.parametrize(
        "reason",
        [
            RevokeReason.LOGOUT,
            RevokeReason.ADMIN,
            RevokeReason.PASSWORD_CHANGE,
            RevokeReason.REUSE,
            RevokeReason.ROTATE,
        ],
    )
    def test_every_declared_reason_is_accepted_by_the_constraint(
        self, seeded_user, seeded_application, reason
    ):
        _create(seeded_user, token_hash=f"revoke-{reason}")
        revoke_refresh_token(f"revoke-{reason}", reason)
        assert get_refresh_token_from_token_hash(f"revoke-{reason}").revoke_reason == reason

    def test_returns_none_for_an_unknown_hash(self, seeded_user, seeded_application):
        assert revoke_refresh_token("no-such-hash", RevokeReason.ADMIN) is None

    @pytest.mark.parametrize("token_hash", ["", None])
    def test_short_circuits_on_empty_input(self, token_hash):
        assert revoke_refresh_token(token_hash, RevokeReason.ADMIN) is None


class TestRevokeRefreshTokenFamily:
    def test_revokes_every_live_token_in_the_family(self, seeded_user, seeded_application):
        # The reuse response: one stolen token burns the whole chain.
        family = uuid.uuid4()
        for index in range(3):
            _create(seeded_user, token_hash=f"family-{index}", family_id=family)

        revoke_refresh_token_family(family, RevokeReason.REUSE)

        for index in range(3):
            found = get_refresh_token_from_token_hash(f"family-{index}")
            assert found.revoked_at is not None
            assert found.revoke_reason == RevokeReason.REUSE

    def test_leaves_other_families_alone(self, seeded_user, seeded_application):
        doomed = uuid.uuid4()
        untouched = uuid.uuid4()
        _create(seeded_user, token_hash="doomed", family_id=doomed)
        _create(seeded_user, token_hash="untouched", family_id=untouched)

        revoke_refresh_token_family(doomed, RevokeReason.REUSE)

        assert get_refresh_token_from_token_hash("untouched").revoked_at is None

    def test_does_not_overwrite_an_earlier_revocation_reason(
        self, seeded_user, seeded_application
    ):
        # The WHERE clause only touches rows with revoked_at IS NULL, so the
        # original reason for an already-revoked token survives.
        family = uuid.uuid4()
        _create(seeded_user, token_hash="already", family_id=family)
        _create(seeded_user, token_hash="live", family_id=family)
        revoke_refresh_token("already", RevokeReason.LOGOUT)

        revoke_refresh_token_family(family, RevokeReason.REUSE)

        assert get_refresh_token_from_token_hash("already").revoke_reason == RevokeReason.LOGOUT
        assert get_refresh_token_from_token_hash("live").revoke_reason == RevokeReason.REUSE

    def test_requires_a_family_id(self, seeded_user, seeded_application):
        # Without the guard this would revoke every row whose family_id is null.
        with pytest.raises(ValueError, match="family_id is required"):
            revoke_refresh_token_family(None, RevokeReason.REUSE)

    def test_an_unknown_family_is_a_no_op(self, seeded_user, seeded_application):
        _create(seeded_user, token_hash="bystander")
        revoke_refresh_token_family(uuid.uuid4(), RevokeReason.REUSE)
        assert get_refresh_token_from_token_hash("bystander").revoked_at is None


class TestRotationChain:
    def test_a_full_rotation_chain_can_be_revoked_at_once(
        self, seeded_user, seeded_application
    ):
        """Walks the lifecycle the token endpoint actually performs."""
        family = uuid.uuid4()
        first = _create(seeded_user, token_hash="gen-0", family_id=family)

        previous = first
        for generation in range(1, 4):
            update_refresh_token_used_at(f"gen-{generation - 1}")
            revoke_refresh_token(f"gen-{generation - 1}", RevokeReason.ROTATE)
            previous = _create(
                seeded_user,
                token_hash=f"gen-{generation}",
                family_id=family,
                parent_id=previous.id,
            )

        # Only the newest generation is still live.
        assert get_refresh_token_from_token_hash("gen-3").revoked_at is None
        assert get_refresh_token_from_token_hash("gen-2").revoke_reason == RevokeReason.ROTATE

        # Reuse of an old generation burns what remains.
        revoke_refresh_token_family(family, RevokeReason.REUSE)
        assert get_refresh_token_from_token_hash("gen-3").revoke_reason == RevokeReason.REUSE
