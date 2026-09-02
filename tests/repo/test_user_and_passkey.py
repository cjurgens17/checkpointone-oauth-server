"""Integration tests for repo.user and repo.passkey."""

import uuid

import pytest

from repo.passkey import user_has_passkey
from repo.user import (
    get_or_create_user_from_user_id,
    get_user_from_email,
    get_user_from_sub,
    get_user_from_user_id,
)
from tests.factories import make_user
from utility.constants import IdentityProvider

pytestmark = pytest.mark.integration


class TestUserLookups:
    def test_finds_a_user_by_email(self, seeded_user):
        found = get_user_from_email(seeded_user.email)
        assert found is not None
        assert found.user_id == seeded_user.user_id

    def test_finds_a_user_by_sub(self, seeded_user):
        assert get_user_from_sub(seeded_user.sub).email == seeded_user.email

    def test_finds_a_user_by_user_id(self, seeded_user):
        assert get_user_from_user_id(seeded_user.user_id).email == seeded_user.email

    @pytest.mark.parametrize(
        "lookup", [get_user_from_email, get_user_from_sub, get_user_from_user_id]
    )
    def test_returns_none_when_absent(self, seeded_user, lookup):
        assert lookup("does-not-exist") is None

    @pytest.mark.parametrize(
        "lookup", [get_user_from_email, get_user_from_sub, get_user_from_user_id]
    )
    @pytest.mark.parametrize("value", ["", None])
    def test_short_circuits_on_empty_input(self, lookup, value):
        assert lookup(value) is None

    def test_email_lookup_is_case_sensitive(self, seeded_user):
        # Documents current behaviour: the column has no case-insensitive
        # collation, so Test@... and test@... are different accounts. Worth
        # knowing before adding a second identity provider.
        assert get_user_from_email(seeded_user.email.upper()) is None

    def test_email_is_unique(self, database, seeded_user, seeded_tenant):
        from sqlalchemy.exc import IntegrityError

        duplicate = make_user(
            email=seeded_user.email,
            sub="cp1|different",
            user_id="cp1|different",
            tenant_id=seeded_tenant.id,
        )
        with pytest.raises(IntegrityError):
            with database() as session:
                session.add(duplicate)
                session.commit()

    def test_a_native_user_requires_a_password(self, database, seeded_tenant):
        # The CHECK constraint keeps a passwordless native account out of the
        # table, since authenticate_user would crash on it.
        from sqlalchemy.exc import IntegrityError

        from models.user import User

        with pytest.raises(IntegrityError):
            with database() as session:
                session.add(
                    User(
                        username="a@b.test",
                        email="a@b.test",
                        sub="cp1|nopassword",
                        user_id="cp1|nopassword",
                        connection=IdentityProvider.NATIVE,
                        password=None,
                        tenant_id=seeded_tenant.id,
                    )
                )
                session.commit()

    def test_a_federated_user_may_have_no_password(self, database, seeded_tenant):
        from models.user import User

        with database() as session:
            session.add(
                User(
                    username="octocat",
                    email="octocat@github.test",
                    sub="github|1",
                    user_id="github|1",
                    connection=IdentityProvider.GITHUB,
                    password=None,
                    tenant_id=seeded_tenant.id,
                )
            )
            session.commit()
        assert get_user_from_user_id("github|1") is not None

    def test_jsonb_address_round_trips(self, database, seeded_tenant):
        address = {"country": "US", "locality": "Denver", "postal_code": "80202"}
        with database() as session:
            session.add(
                make_user(
                    email="addr@test.com",
                    sub="cp1|addr",
                    user_id="cp1|addr",
                    address=address,
                    tenant_id=seeded_tenant.id,
                )
            )
            session.commit()
        assert get_user_from_user_id("cp1|addr").address == address


class TestGetOrCreateUserFromUserId:
    def _defaults(self, tenant_id, **overrides):
        values = {
            "username": "new@checkpointone.com",
            "email": "new@checkpointone.com",
            "email_verified": False,
            "connection": IdentityProvider.GOOGLE,
            "sub": "google-oauth2|123",
            "user_id": "google-oauth2|123",
            "tenant_id": tenant_id,
        }
        values.update(overrides)
        return values

    def test_creates_the_user_when_absent(self, seeded_tenant):
        created = get_or_create_user_from_user_id(
            "google-oauth2|123", self._defaults(seeded_tenant.id)
        )
        assert created.user_id == "google-oauth2|123"
        assert get_user_from_user_id("google-oauth2|123") is not None

    def test_returns_the_existing_user_without_creating_a_duplicate(
        self, seeded_tenant
    ):
        first = get_or_create_user_from_user_id(
            "google-oauth2|123", self._defaults(seeded_tenant.id)
        )
        second = get_or_create_user_from_user_id(
            "google-oauth2|123",
            self._defaults(seeded_tenant.id, email="changed@checkpointone.com"),
        )
        assert first.id == second.id

    def test_does_not_update_an_existing_user(self, seeded_tenant):
        # This is just-in-time provisioning: after the first sign-in the
        # resource server owns the profile, so later logins must not overwrite it.
        get_or_create_user_from_user_id(
            "google-oauth2|123", self._defaults(seeded_tenant.id)
        )
        get_or_create_user_from_user_id(
            "google-oauth2|123",
            self._defaults(seeded_tenant.id, email="changed@checkpointone.com"),
        )
        assert get_user_from_user_id("google-oauth2|123").email == "new@checkpointone.com"

    def test_distinct_user_ids_create_distinct_rows(self, seeded_tenant):
        first = get_or_create_user_from_user_id(
            "google-oauth2|1",
            self._defaults(
                seeded_tenant.id,
                sub="google-oauth2|1",
                user_id="google-oauth2|1",
                email="one@test.com",
            ),
        )
        second = get_or_create_user_from_user_id(
            "google-oauth2|2",
            self._defaults(
                seeded_tenant.id,
                sub="google-oauth2|2",
                user_id="google-oauth2|2",
                email="two@test.com",
            ),
        )
        assert first.id != second.id


class TestUserHasPasskey:
    def test_false_when_the_user_has_none(self, seeded_user):
        assert user_has_passkey(seeded_user.id) is False

    def test_true_once_a_passkey_is_registered(self, database, seeded_user):
        from models.passkey import Passkey

        with database() as session:
            session.add(
                Passkey(
                    user_id=seeded_user.id,
                    credential_id=b"credential-bytes",
                    public_key=b"public-key-bytes",
                    sign_count=0,
                    transports=["internal"],
                )
            )
            session.commit()
        assert user_has_passkey(seeded_user.id) is True

    def test_false_for_an_unknown_user(self, seeded_user):
        assert user_has_passkey(uuid.uuid4()) is False

    def test_credential_id_is_unique(self, database, seeded_user):
        from sqlalchemy.exc import IntegrityError

        from models.passkey import Passkey

        with database() as session:
            session.add(
                Passkey(
                    user_id=seeded_user.id,
                    credential_id=b"same-credential",
                    public_key=b"key",
                )
            )
            session.commit()

        with pytest.raises(IntegrityError):
            with database() as session:
                session.add(
                    Passkey(
                        user_id=seeded_user.id,
                        credential_id=b"same-credential",
                        public_key=b"other-key",
                    )
                )
                session.commit()

    def test_device_type_is_constrained(self, database, seeded_user):
        from sqlalchemy.exc import IntegrityError

        from models.passkey import Passkey

        with pytest.raises(IntegrityError):
            with database() as session:
                session.add(
                    Passkey(
                        user_id=seeded_user.id,
                        credential_id=b"c",
                        public_key=b"k",
                        device_type="hologram",
                    )
                )
                session.commit()
