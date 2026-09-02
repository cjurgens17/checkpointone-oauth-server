"""Integration tests for repo.session.

The upsert here is the reason these tests need a real server: ``create_session``
uses PostgreSQL's ``INSERT ... ON CONFLICT (user_id) DO UPDATE``, so a user only
ever holds one session row and signing in again rotates it in place.
"""

from datetime import datetime, timedelta, timezone

import pytest

from repo.session import (
    create_session,
    delete_session,
    generate_session_expiration,
    generate_session_id,
    get_session_from_session_id,
)
from tests.factories import DEFAULT_AUDIENCE, DEFAULT_CLIENT_ID
from utility.constants import IdentityProvider

pytestmark = pytest.mark.integration


def _create(seeded_user, seeded_application, **overrides):
    values = {
        "user_id": seeded_user.user_id,
        "ttl": 3600,
        "client_id": seeded_application.client_id,
        "response_type": "code",
        "scope": "openid email",
        "connection": IdentityProvider.NATIVE,
        "audience": DEFAULT_AUDIENCE,
    }
    values.update(overrides)
    return create_session(**values)


class TestGenerators:
    def test_session_ids_do_not_repeat(self):
        assert len({generate_session_id() for _ in range(500)}) == 500

    def test_expiration_is_ttl_seconds_ahead(self):
        before = datetime.now(timezone.utc)
        expires = generate_session_expiration(3600)
        assert timedelta(minutes=59) < expires - before < timedelta(minutes=61)

    def test_expiration_is_timezone_aware(self):
        assert generate_session_expiration(60).tzinfo is not None


class TestCreateSession:
    def test_persists_a_retrievable_session(self, seeded_user, seeded_application):
        created = _create(seeded_user, seeded_application)
        found = get_session_from_session_id(created.session_id)
        assert found is not None
        assert found.user_id == seeded_user.user_id
        assert found.client_id == DEFAULT_CLIENT_ID
        assert found.scope == "openid email"
        assert found.audience == DEFAULT_AUDIENCE

    def test_sets_an_expiry_from_the_ttl(self, seeded_user, seeded_application):
        created = _create(seeded_user, seeded_application, ttl=60)
        assert created.expires_at > datetime.now(timezone.utc)
        assert created.expires_at < datetime.now(timezone.utc) + timedelta(minutes=2)

    def test_signing_in_again_replaces_the_session_row(
        self, seeded_user, seeded_application, database
    ):
        # One row per user: the ON CONFLICT target is user_id.
        first = _create(seeded_user, seeded_application)
        second = _create(seeded_user, seeded_application)

        assert first.session_id != second.session_id
        with database() as db:
            from sqlalchemy import func, select

            from models.session import Session

            count = db.scalar(select(func.count()).select_from(Session))
        assert count == 1

    def test_the_previous_session_id_stops_working(self, seeded_user, seeded_application):
        # This is what makes re-login invalidate the old cookie.
        first = _create(seeded_user, seeded_application)
        _create(seeded_user, seeded_application)
        assert get_session_from_session_id(first.session_id) is None

    def test_the_upsert_refreshes_every_mutable_column(
        self, seeded_user, seeded_application
    ):
        _create(
            seeded_user,
            seeded_application,
            scope="openid",
            connection=IdentityProvider.NATIVE,
            audience="https://api.first/resource",
        )
        second = _create(
            seeded_user,
            seeded_application,
            scope="openid email profile",
            connection=IdentityProvider.GOOGLE,
            audience="https://api.second/resource",
        )
        found = get_session_from_session_id(second.session_id)
        assert found.scope == "openid email profile"
        assert found.connection == IdentityProvider.GOOGLE
        assert found.audience == "https://api.second/resource"

    def test_the_upsert_extends_the_expiry(self, seeded_user, seeded_application):
        first = _create(seeded_user, seeded_application, ttl=60)
        second = _create(seeded_user, seeded_application, ttl=86400)
        assert second.expires_at > first.expires_at

    def test_audience_is_optional(self, seeded_user, seeded_application):
        created = _create(seeded_user, seeded_application, audience=None)
        assert get_session_from_session_id(created.session_id).audience is None

    def test_different_users_hold_separate_sessions(
        self, database, seeded_tenant, seeded_application, seeded_user
    ):
        from tests.factories import make_user

        other = make_user(
            email="other@checkpointone.com",
            sub="cp1|other",
            user_id="cp1|other",
            tenant_id=seeded_tenant.id,
        )
        with database() as db:
            db.add(other)
            db.commit()

        first = _create(seeded_user, seeded_application)
        second = _create(other, seeded_application)

        assert get_session_from_session_id(first.session_id) is not None
        assert get_session_from_session_id(second.session_id) is not None


class TestGetSessionFromSessionId:
    def test_returns_none_for_an_unknown_id(self, seeded_user, seeded_application):
        _create(seeded_user, seeded_application)
        assert get_session_from_session_id("no-such-session") is None

    @pytest.mark.parametrize("session_id", ["", None])
    def test_short_circuits_on_empty_input(self, session_id):
        assert get_session_from_session_id(session_id) is None

    def test_an_expired_session_is_still_returned(self, seeded_user, seeded_application):
        # The repo does not filter on expiry; services.is_valid_session applies
        # that rule. Pinned so the split in responsibility stays deliberate.
        created = _create(seeded_user, seeded_application, ttl=-10)
        assert get_session_from_session_id(created.session_id) is not None


class TestDeleteSession:
    def test_removes_the_session(self, seeded_user, seeded_application):
        created = _create(seeded_user, seeded_application)
        delete_session(created.session_id)
        assert get_session_from_session_id(created.session_id) is None

    def test_is_a_no_op_for_an_unknown_id(self, seeded_user, seeded_application):
        created = _create(seeded_user, seeded_application)
        delete_session("no-such-session")
        assert get_session_from_session_id(created.session_id) is not None

    def test_deleting_lets_a_fresh_session_be_created(
        self, seeded_user, seeded_application
    ):
        first = _create(seeded_user, seeded_application)
        delete_session(first.session_id)
        second = _create(seeded_user, seeded_application)
        assert get_session_from_session_id(second.session_id) is not None
