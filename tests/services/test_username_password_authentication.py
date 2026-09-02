"""Tests for services.connections.username_password_authentication."""

import uuid

import pytest
from werkzeug.security import check_password_hash

import services.connections.username_password_authentication as native
from services.connections.username_password_authentication import (
    authenticate_user,
    email_already_registered,
    register_user,
    user_claims,
)
from tests.factories import DEFAULT_PASSWORD, make_user
from utility.constants import IdentityProvider


@pytest.fixture
def stored_user(monkeypatch):
    user = make_user(email="test@checkpointone.com", password=DEFAULT_PASSWORD)
    monkeypatch.setattr(
        native, "get_user_from_email", lambda email: user if email == user.email else None
    )
    return user


class TestAuthenticateUser:
    def test_returns_the_user_for_correct_credentials(self, stored_user):
        assert authenticate_user(stored_user.email, DEFAULT_PASSWORD) is stored_user

    def test_rejects_a_wrong_password(self, stored_user):
        assert authenticate_user(stored_user.email, "WrongPassword1!") is None

    def test_rejects_an_unknown_email(self, stored_user):
        assert authenticate_user("nobody@checkpointone.com", DEFAULT_PASSWORD) is None

    @pytest.mark.parametrize(
        ("email", "password"),
        [
            ("", DEFAULT_PASSWORD),
            (None, DEFAULT_PASSWORD),
            ("test@checkpointone.com", ""),
            ("test@checkpointone.com", None),
            (None, None),
        ],
    )
    def test_rejects_missing_credentials_without_a_lookup(
        self, monkeypatch, email, password
    ):
        # Short-circuiting before the query keeps empty input from reaching the
        # database at all.
        def _fail(_email):
            raise AssertionError("should not query for empty credentials")

        monkeypatch.setattr(native, "get_user_from_email", _fail)
        assert authenticate_user(email, password) is None

    def test_password_comparison_is_hash_based(self, stored_user):
        # The stored value is a hash, never the password itself.
        assert stored_user.password != DEFAULT_PASSWORD
        assert check_password_hash(stored_user.password, DEFAULT_PASSWORD)

    def test_a_federated_user_with_no_password_crashes_instead_of_failing_cleanly(
        self, monkeypatch
    ):
        """Pins a real defect rather than asserting intended behaviour.

        Google and GitHub accounts are stored with ``password=None``. If such an
        address is submitted through the native login form,
        ``check_password_hash(None, ...)`` raises ``AttributeError`` and the
        request becomes a 500 instead of the 401 that a wrong password produces.

        Beyond the crash, the differing status codes let an unauthenticated
        caller tell a federated account apart from one that does not exist,
        which is a user-enumeration oracle. The fix is a
        ``if not user.password`` guard in ``authenticate_user`` returning None;
        this test should then be rewritten to assert that.
        """
        federated = make_user(connection=IdentityProvider.GOOGLE)
        federated.password = None
        monkeypatch.setattr(native, "get_user_from_email", lambda email: federated)
        with pytest.raises(AttributeError):
            authenticate_user(federated.email, "anything")


class TestEmailAlreadyRegistered:
    def test_true_when_a_user_exists(self, stored_user):
        assert email_already_registered(stored_user.email) is True

    def test_false_when_no_user_exists(self, stored_user):
        assert email_already_registered("nobody@checkpointone.com") is False


class TestRegisterUser:
    @pytest.fixture
    def captured(self, monkeypatch):
        recorded = {}

        def _capture(user_id, defaults):
            recorded["user_id"] = user_id
            recorded["defaults"] = defaults
            return make_user(**{k: v for k, v in defaults.items() if k != "password"})

        monkeypatch.setattr(native, "get_or_create_user_from_user_id", _capture)
        return recorded

    def test_user_id_is_namespaced_to_the_native_provider(self, captured):
        register_user("new@checkpointone.com", DEFAULT_PASSWORD, uuid.uuid4())
        assert captured["user_id"].startswith(f"{IdentityProvider.CHECK_POINT_ONE}|")

    def test_sub_and_user_id_match(self, captured):
        register_user("new@checkpointone.com", DEFAULT_PASSWORD, uuid.uuid4())
        defaults = captured["defaults"]
        assert defaults["sub"] == defaults["user_id"] == captured["user_id"]

    def test_password_is_stored_hashed(self, captured):
        register_user("new@checkpointone.com", DEFAULT_PASSWORD, uuid.uuid4())
        stored = captured["defaults"]["password"]
        assert stored != DEFAULT_PASSWORD
        assert check_password_hash(stored, DEFAULT_PASSWORD)

    def test_new_accounts_start_unverified(self, captured):
        register_user("new@checkpointone.com", DEFAULT_PASSWORD, uuid.uuid4())
        assert captured["defaults"]["email_verified"] is False

    def test_records_the_native_connection_and_tenant(self, captured):
        tenant_id = uuid.uuid4()
        register_user("new@checkpointone.com", DEFAULT_PASSWORD, tenant_id)
        defaults = captured["defaults"]
        assert defaults["connection"] == IdentityProvider.NATIVE
        assert defaults["tenant_id"] == tenant_id
        assert defaults["username"] == defaults["email"] == "new@checkpointone.com"

    def test_each_registration_gets_a_distinct_identifier(self, monkeypatch):
        seen = []
        monkeypatch.setattr(
            native,
            "get_or_create_user_from_user_id",
            lambda user_id, defaults: seen.append(user_id),
        )
        for _ in range(50):
            register_user("a@b.c", DEFAULT_PASSWORD, uuid.uuid4())
        assert len(set(seen)) == 50

    def test_the_same_password_hashes_differently_each_time(self, monkeypatch):
        hashes = []
        monkeypatch.setattr(
            native,
            "get_or_create_user_from_user_id",
            lambda user_id, defaults: hashes.append(defaults["password"]),
        )
        register_user("a@b.c", DEFAULT_PASSWORD, uuid.uuid4())
        register_user("d@e.f", DEFAULT_PASSWORD, uuid.uuid4())
        # Werkzeug salts every hash, so identical passwords never collide.
        assert hashes[0] != hashes[1]


class TestUserClaims:
    def test_always_includes_email_and_verification_status(self):
        user = make_user(email="a@b.c", email_verified=True)
        claims = user_claims(user)
        assert claims["email"] == "a@b.c"
        assert claims["email_verified"] is True

    def test_email_verified_is_coerced_to_a_boolean(self):
        # The column is nullable, but the claim must be a bool for OIDC.
        user = make_user(email_verified=None)
        assert user_claims(user)["email_verified"] is False

    def test_includes_profile_fields_that_are_set(self):
        user = make_user(name="Test Person", locale="en-US")
        claims = user_claims(user)
        assert claims["name"] == "Test Person"
        assert claims["locale"] == "en-US"

    def test_omits_profile_fields_that_are_unset(self):
        user = make_user()
        claims = user_claims(user)
        assert "picture" not in claims
        assert "birthdate" not in claims

    def test_never_exposes_the_password_hash(self):
        user = make_user()
        assert "password" not in user_claims(user)

    def test_never_exposes_internal_identifiers(self):
        user = make_user()
        claims = user_claims(user)
        assert "tenant_id" not in claims
        assert "id" not in claims
        assert "user_id" not in claims

    def test_includes_the_address_structure_when_present(self):
        user = make_user(address={"country": "US", "locality": "Denver"})
        assert user_claims(user)["address"] == {"country": "US", "locality": "Denver"}
