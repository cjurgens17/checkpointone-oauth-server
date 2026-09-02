"""Tests for the authorization_code grant at POST /oauth/token."""

import pytest

import resources.token as token_resource
from tests.factories import (
    DEFAULT_AUDIENCE,
    DEFAULT_CLIENT_ID,
    DEFAULT_REDIRECT_URI,
    authorization_code_metadata,
    make_session,
)
from tests.resources.conftest import post_token

CODE_VERIFIER = "test-code-verifier-value"


@pytest.fixture
def redeemable_code(monkeypatch):
    """Install a single-use authorization code and report what was redeemed."""
    state = {"metadata": authorization_code_metadata(), "redeemed": []}

    def _redeem(code):
        state["redeemed"].append(code)
        return state["metadata"] if code == "valid-code" else None

    monkeypatch.setattr(token_resource, "redeem_auth_code", _redeem)
    return state


@pytest.fixture
def code_grant(registered_client, token_subject, no_session, redeemable_code):
    """Everything the happy path needs, bundled."""
    return redeemable_code


class TestRequiredParameters:
    @pytest.mark.parametrize("missing", ["grant_type", "client_id", "audience"])
    def test_rejects_a_request_missing_a_required_parameter(self, client, missing):
        body = {
            "grant_type": "authorization_code",
            "client_id": DEFAULT_CLIENT_ID,
            "audience": DEFAULT_AUDIENCE,
        }
        body.pop(missing)
        response = client.post("/oauth/token", json=body)
        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid_request"
        assert missing in response.get_json()["error_description"]

    def test_names_every_missing_parameter(self, client):
        response = client.post("/oauth/token", json={})
        description = response.get_json()["error_description"]
        assert "grant_type" in description
        assert "client_id" in description
        assert "audience" in description

    def test_rejects_an_empty_body(self, client):
        assert client.post("/oauth/token", json={}).status_code == 400

    def test_rejects_a_non_json_body(self, client):
        # get_json(silent=True) yields None, which becomes an empty parameter set.
        response = client.post("/oauth/token", data="not json")
        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid_request"


class TestAuthorizationCodeGrant:
    def test_issues_an_access_token(self, client, code_grant, decode_token):
        response = post_token(
            client,
            grant_type="authorization_code",
            code="valid-code",
            code_verifier=CODE_VERIFIER,
            redirect_uri=DEFAULT_REDIRECT_URI,
        )
        assert response.status_code == 200
        body = response.get_json()
        assert body["token_type"] == "Bearer"
        assert body["expires_in"] == token_resource.ACCESS_TOKEN_TTL_SECONDS
        assert decode_token(body["access_token"])["aud"] == DEFAULT_AUDIENCE

    def test_marks_the_response_as_not_cacheable(self, client, code_grant):
        # RFC 6749 requires Cache-Control: no-store on token responses.
        response = post_token(
            client,
            grant_type="authorization_code",
            code="valid-code",
            code_verifier=CODE_VERIFIER,
            redirect_uri=DEFAULT_REDIRECT_URI,
        )
        assert response.headers["Cache-Control"] == "no-store"

    def test_includes_an_id_token_when_openid_was_requested(
        self, client, code_grant, decode_token
    ):
        response = post_token(
            client,
            grant_type="authorization_code",
            code="valid-code",
            code_verifier=CODE_VERIFIER,
            redirect_uri=DEFAULT_REDIRECT_URI,
        )
        id_token = response.get_json()["id_token"]
        assert decode_token(id_token)["aud"] == DEFAULT_CLIENT_ID

    def test_omits_the_id_token_without_the_openid_scope(self, client, code_grant):
        code_grant["metadata"] = authorization_code_metadata(scope="read:things")
        response = post_token(
            client,
            grant_type="authorization_code",
            code="valid-code",
            code_verifier=CODE_VERIFIER,
            redirect_uri=DEFAULT_REDIRECT_URI,
        )
        assert "id_token" not in response.get_json()

    def test_issues_a_refresh_token_for_offline_access(
        self, client, code_grant, captured_refresh_tokens
    ):
        code_grant["metadata"] = authorization_code_metadata(
            scope="openid email offline_access"
        )
        response = post_token(
            client,
            grant_type="authorization_code",
            code="valid-code",
            code_verifier=CODE_VERIFIER,
            redirect_uri=DEFAULT_REDIRECT_URI,
        )
        assert response.get_json()["refresh_token"]
        assert len(captured_refresh_tokens) == 1

    def test_omits_the_refresh_token_without_offline_access(self, client, code_grant):
        response = post_token(
            client,
            grant_type="authorization_code",
            code="valid-code",
            code_verifier=CODE_VERIFIER,
            redirect_uri=DEFAULT_REDIRECT_URI,
        )
        assert "refresh_token" not in response.get_json()

    def test_redeems_the_code_exactly_once(self, client, code_grant):
        post_token(
            client,
            grant_type="authorization_code",
            code="valid-code",
            code_verifier=CODE_VERIFIER,
            redirect_uri=DEFAULT_REDIRECT_URI,
        )
        assert code_grant["redeemed"] == ["valid-code"]


class TestAuthorizationCodeRejections:
    def _post(self, client, **overrides):
        body = {
            "grant_type": "authorization_code",
            "code": "valid-code",
            "code_verifier": CODE_VERIFIER,
            "redirect_uri": DEFAULT_REDIRECT_URI,
        }
        body.update(overrides)
        return post_token(client, **body)

    def test_missing_code(self, client, code_grant):
        response = self._post(client, code=None)
        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid_request"

    def test_unknown_code(self, client, code_grant):
        response = self._post(client, code="never-issued")
        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid_authorization"

    def test_expired_code(self, client, code_grant):
        from datetime import datetime, timedelta, timezone

        code_grant["metadata"] = authorization_code_metadata(
            expires_at=(
                datetime.now(timezone.utc) - timedelta(seconds=1)
            ).isoformat()
        )
        response = self._post(client)
        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid_authorization"

    def test_code_issued_to_a_different_client(self, client, code_grant):
        # Prevents one client redeeming a code minted for another.
        code_grant["metadata"] = authorization_code_metadata(
            client_id="client_someone_else"
        )
        response = self._post(client)
        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid_client"

    def test_redirect_uri_mismatch(self, client, code_grant):
        response = self._post(client, redirect_uri="https://attacker.test/cb")
        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid_redirect"

    def test_missing_code_verifier(self, client, code_grant):
        # PKCE is mandatory here, so a missing verifier is refused outright.
        response = self._post(client, code_verifier=None)
        assert response.status_code == 400
        assert "code_verifier" in response.get_json()["error_description"]

    def test_wrong_code_verifier(self, client, code_grant):
        response = self._post(client, code_verifier="not-the-right-verifier")
        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid_request"

    def test_plain_pkce_method_is_refused(self, client, code_grant):
        code_grant["metadata"] = authorization_code_metadata(
            code_challenge=CODE_VERIFIER, code_challenge_method="plain"
        )
        response = self._post(client)
        assert response.status_code == 400


class TestSessionScopeBinding:
    def test_an_active_session_overrides_the_requested_scope(
        self, client, code_grant, monkeypatch, decode_token
    ):
        # The session is authoritative: a code cannot widen scope beyond what the
        # user actually consented to in the current session.
        session = make_session(scope="openid", audience=DEFAULT_AUDIENCE)
        monkeypatch.setattr(token_resource, "is_valid_session", lambda: True)
        monkeypatch.setattr(
            token_resource, "get_session_from_session_id", lambda sid: session
        )
        code_grant["metadata"] = authorization_code_metadata(
            scope="openid email profile"
        )

        response = post_token(
            client,
            grant_type="authorization_code",
            code="valid-code",
            code_verifier=CODE_VERIFIER,
            redirect_uri=DEFAULT_REDIRECT_URI,
        )
        assert decode_token(response.get_json()["access_token"])["scope"] == "openid"

    def test_rejects_a_session_bound_to_a_different_client(
        self, client, code_grant, monkeypatch
    ):
        session = make_session(client_id="client_other", audience=DEFAULT_AUDIENCE)
        monkeypatch.setattr(token_resource, "is_valid_session", lambda: True)
        monkeypatch.setattr(
            token_resource, "get_session_from_session_id", lambda sid: session
        )
        response = post_token(
            client,
            grant_type="authorization_code",
            code="valid-code",
            code_verifier=CODE_VERIFIER,
            redirect_uri=DEFAULT_REDIRECT_URI,
        )
        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid_grant"

    def test_rejects_a_session_bound_to_a_different_audience(
        self, client, code_grant, monkeypatch
    ):
        session = make_session(audience="https://api.other/resource")
        monkeypatch.setattr(token_resource, "is_valid_session", lambda: True)
        monkeypatch.setattr(
            token_resource, "get_session_from_session_id", lambda sid: session
        )
        response = post_token(
            client,
            grant_type="authorization_code",
            code="valid-code",
            code_verifier=CODE_VERIFIER,
            redirect_uri=DEFAULT_REDIRECT_URI,
        )
        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid_grant"
