"""Integration tests for repo.applications and repo.tenants."""

import pytest

from repo.applications import (
    allowed_logout_uri,
    allowed_redirect_uri,
    get_application_from_client_id,
    get_tenant_from_application,
)
from repo.tenants import get_tenant_by_slug
from tests.factories import (
    DEFAULT_CLIENT_ID,
    DEFAULT_LOGOUT_URI,
    DEFAULT_REDIRECT_URI,
    make_application,
)

pytestmark = pytest.mark.integration


class TestGetApplicationFromClientId:
    def test_returns_the_registered_application(self, seeded_application):
        found = get_application_from_client_id(DEFAULT_CLIENT_ID)
        assert found is not None
        assert found.client_id == DEFAULT_CLIENT_ID
        assert found.name == seeded_application.name

    def test_returns_none_for_an_unknown_client(self, seeded_application):
        assert get_application_from_client_id("client_does_not_exist") is None

    @pytest.mark.parametrize("client_id", ["", None])
    def test_short_circuits_on_empty_input(self, client_id):
        # Guards against a blank client_id matching a row by accident, and
        # avoids a pointless query.
        assert get_application_from_client_id(client_id) is None

    def test_array_columns_round_trip(self, seeded_application):
        found = get_application_from_client_id(DEFAULT_CLIENT_ID)
        assert found.redirect_uris == [DEFAULT_REDIRECT_URI]
        assert found.logout_uris == [DEFAULT_LOGOUT_URI]
        assert found.permissions == ["offline_access"]

    def test_client_id_is_unique(self, database, seeded_application, seeded_tenant):
        from sqlalchemy.exc import IntegrityError

        duplicate = make_application(
            client_id=DEFAULT_CLIENT_ID, tenant_id=seeded_tenant.id
        )
        with pytest.raises(IntegrityError):
            with database() as session:
                session.add(duplicate)
                session.commit()

    def test_client_type_is_constrained(self, database, seeded_tenant):
        from sqlalchemy.exc import IntegrityError

        invalid = make_application(
            client_id="client_bad_type",
            client_type="Toaster",
            tenant_id=seeded_tenant.id,
        )
        with pytest.raises(IntegrityError):
            with database() as session:
                session.add(invalid)
                session.commit()


class TestAllowedRedirectUri:
    def test_accepts_a_registered_uri(self, seeded_application):
        assert allowed_redirect_uri(DEFAULT_REDIRECT_URI, DEFAULT_CLIENT_ID) is True

    def test_rejects_an_unregistered_uri(self, seeded_application):
        assert allowed_redirect_uri("https://attacker.test/cb", DEFAULT_CLIENT_ID) is False

    def test_rejects_when_the_client_does_not_exist(self, seeded_application):
        assert allowed_redirect_uri(DEFAULT_REDIRECT_URI, "client_unknown") is False

    def test_matching_is_exact(self, seeded_application):
        # Prefix or suffix matching would open a redirect hole.
        assert allowed_redirect_uri(f"{DEFAULT_REDIRECT_URI}/extra", DEFAULT_CLIENT_ID) is False
        assert allowed_redirect_uri(DEFAULT_REDIRECT_URI.rstrip("/callback"), DEFAULT_CLIENT_ID) is False

    def test_is_case_sensitive(self, seeded_application):
        assert allowed_redirect_uri(DEFAULT_REDIRECT_URI.upper(), DEFAULT_CLIENT_ID) is False


class TestAllowedLogoutUri:
    def test_accepts_a_registered_uri(self, seeded_application):
        assert allowed_logout_uri(DEFAULT_LOGOUT_URI, DEFAULT_CLIENT_ID) is True

    def test_rejects_an_unregistered_uri(self, seeded_application):
        assert allowed_logout_uri("https://attacker.test/out", DEFAULT_CLIENT_ID) is False

    def test_rejects_when_the_client_does_not_exist(self, seeded_application):
        assert allowed_logout_uri(DEFAULT_LOGOUT_URI, "client_unknown") is False

    def test_a_redirect_uri_is_not_automatically_a_logout_uri(self, seeded_application):
        assert allowed_logout_uri(DEFAULT_REDIRECT_URI, DEFAULT_CLIENT_ID) is False


class TestGetTenantFromApplication:
    def test_returns_the_owning_tenant(self, seeded_application, seeded_tenant):
        tenant = get_tenant_from_application(DEFAULT_CLIENT_ID)
        assert tenant is not None
        assert tenant.id == seeded_tenant.id
        assert tenant.slug == seeded_tenant.slug

    def test_returns_none_for_an_unknown_client(self, seeded_application):
        assert get_tenant_from_application("client_unknown") is None

    @pytest.mark.parametrize("client_id", ["", None])
    def test_short_circuits_on_empty_input(self, client_id):
        assert get_tenant_from_application(client_id) is None


class TestGetTenantBySlug:
    def test_returns_the_tenant(self, seeded_tenant):
        found = get_tenant_by_slug(seeded_tenant.slug)
        assert found is not None
        assert found.id == seeded_tenant.id

    def test_returns_none_for_an_unknown_slug(self, seeded_tenant):
        assert get_tenant_by_slug("no-such-tenant") is None

    @pytest.mark.parametrize("slug", ["", None])
    def test_short_circuits_on_empty_input(self, slug):
        assert get_tenant_by_slug(slug) is None

    def test_slug_is_unique(self, database, seeded_tenant):
        from sqlalchemy.exc import IntegrityError

        from tests.factories import make_tenant

        with pytest.raises(IntegrityError):
            with database() as session:
                session.add(make_tenant(slug=seeded_tenant.slug))
                session.commit()
