"""Tests for the client_credentials grant at POST /oauth/token."""

import pytest

import resources.token as token_resource
from tests.factories import (
    DEFAULT_AUDIENCE,
    DEFAULT_CLIENT_SECRET,
    DEFAULT_CONFIDENTIAL_CLIENT_ID,
    make_application,
    make_confidential_application,
)
from tests.resources.conftest import post_token
from utility.constants import ClientType


@pytest.fixture
def confidential_client(monkeypatch):
    application = make_confidential_application()
    monkeypatch.setattr(
        token_resource,
        "get_application_from_client_id",
        lambda client_id: application if client_id == application.client_id else None,
    )
    return application


def _post(client, **overrides):
    body = {
        "grant_type": "client_credentials",
        "client_id": DEFAULT_CONFIDENTIAL_CLIENT_ID,
        "client_secret": DEFAULT_CLIENT_SECRET,
    }
    body.update(overrides)
    return post_token(client, **body)


class TestClientCredentialsGrant:
    def test_issues_an_access_token(self, client, confidential_client, decode_token):
        response = _post(client)
        assert response.status_code == 200
        body = response.get_json()
        assert body["token_type"] == "Bearer"
        assert body["expires_in"] == token_resource.ACCESS_TOKEN_TTL_SECONDS
        assert decode_token(body["access_token"])["aud"] == DEFAULT_AUDIENCE

    def test_subject_is_the_client_itself(self, client, confidential_client, decode_token):
        # There is no end user in this grant, so the client is the subject.
        claims = decode_token(_post(client).get_json()["access_token"])
        assert claims["sub"] == DEFAULT_CONFIDENTIAL_CLIENT_ID

    def test_grants_the_registered_permissions_as_scope(
        self, client, confidential_client, decode_token
    ):
        claims = decode_token(_post(client).get_json()["access_token"])
        assert set(claims["scope"].split(" ")) == set(confidential_client.permissions)

    def test_never_issues_an_id_token(self, client, confidential_client):
        # An ID token asserts an end user's identity, which this grant has none of.
        assert "id_token" not in _post(client).get_json()

    def test_marks_the_response_as_not_cacheable(self, client, confidential_client):
        assert _post(client).headers["Cache-Control"] == "no-store"

    def test_omits_scope_when_the_client_has_no_permissions(
        self, client, monkeypatch, decode_token
    ):
        application = make_confidential_application(permissions=[])
        monkeypatch.setattr(
            token_resource, "get_application_from_client_id", lambda cid: application
        )
        claims = decode_token(_post(client).get_json()["access_token"])
        assert claims["scope"] is None

    def test_issues_a_refresh_token_when_offline_access_is_requested(
        self, client, confidential_client, captured_refresh_tokens
    ):
        response = _post(client, scope="offline_access")
        assert response.get_json()["refresh_token"]
        assert len(captured_refresh_tokens) == 1

    def test_refresh_token_is_recorded_against_the_client(
        self, client, confidential_client, captured_refresh_tokens
    ):
        _post(client, scope="offline_access")
        record = captured_refresh_tokens[0]
        assert record.sub == DEFAULT_CONFIDENTIAL_CLIENT_ID
        assert record.client_id == DEFAULT_CONFIDENTIAL_CLIENT_ID
        assert record.audience == DEFAULT_AUDIENCE

    def test_omits_the_refresh_token_by_default(self, client, confidential_client):
        assert "refresh_token" not in _post(client).get_json()


class TestClientCredentialsRejections:
    def test_unregistered_client(self, client, confidential_client):
        response = _post(client, client_id="client_unknown")
        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid_request"

    def test_public_client_cannot_use_this_grant(self, client, monkeypatch):
        # Public clients cannot hold a secret, so machine-to-machine access must
        # be refused for them.
        public = make_application(client_type=ClientType.USER_AGENT)
        monkeypatch.setattr(
            token_resource, "get_application_from_client_id", lambda cid: public
        )
        response = _post(client, client_id=public.client_id)
        assert response.status_code == 400
        assert response.get_json()["error"] == "client_unsupported"

    def test_native_client_cannot_use_this_grant(self, client, monkeypatch):
        native = make_application(client_type=ClientType.NATIVE)
        monkeypatch.setattr(
            token_resource, "get_application_from_client_id", lambda cid: native
        )
        response = _post(client, client_id=native.client_id)
        assert response.status_code == 400
        assert response.get_json()["error"] == "client_unsupported"

    def test_wrong_client_secret(self, client, confidential_client):
        response = _post(client, client_secret="wrong-secret")
        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid_credentials"

    def test_missing_client_secret(self, client, confidential_client):
        response = _post(client, client_secret=None)
        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid_credentials"

    def test_no_token_is_issued_when_credentials_fail(self, client, confidential_client):
        assert "access_token" not in _post(client, client_secret="wrong").get_json()
