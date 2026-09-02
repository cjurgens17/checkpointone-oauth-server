"""Tests for the Google and GitHub callback views - the inbound federated leg."""

from urllib.parse import parse_qs, urlsplit

import pytest

import views.callbacks.github as github_callback
import views.callbacks.google as google_callback
from tests.factories import (
    DEFAULT_CLIENT_ID,
    DEFAULT_REDIRECT_URI,
    make_application,
    make_user,
)
from utility.redis.cache import cache_set


def _query(response):
    return parse_qs(urlsplit(response.headers["Location"]).query)


def _resource_owner_request(**overrides):
    values = {
        "state": "clients-own-state",
        "redirect_uri": DEFAULT_REDIRECT_URI,
        "client_id": DEFAULT_CLIENT_ID,
        "response_type": "code",
        "scope": "openid email profile",
        "code_challenge": "challenge",
        "code_challenge_method": "S256",
        "audience": "https://api.test/resource",
    }
    values.update(overrides)
    return values


@pytest.fixture
def federated_env(monkeypatch):
    """Shared stubs for both callbacks: client lookup, user upsert, code, session."""
    captured = {"codes": [], "sessions": [], "users": []}

    def _create_auth_code(payload):
        captured["codes"].append(payload)
        return "federated-auth-code"

    def _generate_session(user_id, client_id, response_type, scope, connection, audience=None, ttl=None):
        captured["sessions"].append(
            {"user_id": user_id, "connection": connection, "audience": audience}
        )
        return "cp1_auth", "federated-session", {"path": "/"}

    def _get_or_create(user_id, defaults):
        captured["users"].append({"user_id": user_id, "defaults": defaults})
        return make_user(user_id=user_id, sub=user_id, email=defaults.get("email"))

    for module in (google_callback, github_callback):
        monkeypatch.setattr(
            module, "get_application_from_client_id", lambda cid: make_application()
        )
        monkeypatch.setattr(module, "create_auth_code", _create_auth_code)
        monkeypatch.setattr(module, "generate_server_session_cookie", _generate_session)
        monkeypatch.setattr(module, "get_or_create_user_from_user_id", _get_or_create)

    return captured


class TestGoogleCallback:
    @pytest.fixture
    def google_env(self, monkeypatch, federated_env):
        monkeypatch.setattr(
            google_callback, "exchange_code_for_id_token", lambda code: "google.id.token"
        )
        monkeypatch.setattr(
            google_callback,
            "verify_google_id_token",
            lambda token: {
                "sub": "108123456789",
                "email": "person@gmail.com",
                "email_verified": True,
                "name": "Test Person",
            },
        )
        return federated_env

    def test_redirects_back_to_the_client_with_a_code(self, client, google_env):
        cache_set("valid-state", {"resource_owner": _resource_owner_request()})
        response = client.get(
            "/callback/google", query_string={"state": "valid-state", "code": "google-code"}
        )
        assert response.status_code == 302
        assert response.headers["Location"].startswith(DEFAULT_REDIRECT_URI)
        assert _query(response)["code"] == ["federated-auth-code"]

    def test_returns_the_clients_original_state(self, client, google_env):
        cache_set("valid-state", {"resource_owner": _resource_owner_request()})
        response = client.get(
            "/callback/google", query_string={"state": "valid-state", "code": "c"}
        )
        assert _query(response)["state"] == ["clients-own-state"]

    def test_provisions_the_user_namespaced_to_google(self, client, google_env):
        cache_set("valid-state", {"resource_owner": _resource_owner_request()})
        client.get("/callback/google", query_string={"state": "valid-state", "code": "c"})
        provisioned = google_env["users"][0]
        assert provisioned["user_id"] == "google-oauth2|108123456789"
        assert provisioned["defaults"]["connection"] == "google-oauth2"
        assert provisioned["defaults"]["email"] == "person@gmail.com"

    def test_merges_provider_claims_according_to_scope(self, client, google_env):
        cache_set("valid-state", {"resource_owner": _resource_owner_request()})
        client.get("/callback/google", query_string={"state": "valid-state", "code": "c"})
        # profile was requested, so the name claim is provisioned onto the user.
        assert google_env["users"][0]["defaults"].get("name") == "Test Person"

    def test_establishes_a_session_for_the_google_connection(self, client, google_env):
        cache_set("valid-state", {"resource_owner": _resource_owner_request()})
        client.get("/callback/google", query_string={"state": "valid-state", "code": "c"})
        assert google_env["sessions"][0]["connection"] == "google-oauth2"

    def test_an_unknown_state_is_refused(self, client, google_env):
        # State is the CSRF defence on this leg; an unrecognised one must not
        # produce a code.
        response = client.get(
            "/callback/google", query_string={"state": "never-issued", "code": "c"}
        )
        assert response.status_code == 400
        assert google_env["codes"] == []

    def test_the_state_is_single_use(self, client, google_env):
        cache_set("valid-state", {"resource_owner": _resource_owner_request()})
        first = client.get(
            "/callback/google", query_string={"state": "valid-state", "code": "c"}
        )
        second = client.get(
            "/callback/google", query_string={"state": "valid-state", "code": "c"}
        )
        assert first.status_code == 302
        assert second.status_code == 400

    def test_user_denial_is_relayed_to_the_client(self, client, google_env):
        cache_set("valid-state", {"resource_owner": _resource_owner_request()})
        response = client.get(
            "/callback/google",
            query_string={"state": "valid-state", "error": "access_denied"},
        )
        assert response.status_code == 302
        assert _query(response)["error"] == ["access_denied"]
        assert _query(response)["state"] == ["clients-own-state"]


class TestGithubCallback:
    @pytest.fixture
    def github_env(self, monkeypatch, federated_env):
        monkeypatch.setattr(
            github_callback, "exchange_code_for_access_token", lambda code: "gho_token"
        )
        monkeypatch.setattr(
            github_callback,
            "get_userinfo",
            lambda token: {
                "id": 583231,
                "login": "octocat",
                "name": "The Octocat",
                "email": "octocat@github.test",
            },
        )
        return federated_env

    def test_redirects_back_to_the_client_with_a_code(self, client, github_env):
        cache_set("valid-state", {"resource_owner": _resource_owner_request()})
        response = client.get(
            "/callback/github", query_string={"state": "valid-state", "code": "gh-code"}
        )
        assert response.status_code == 302
        assert _query(response)["code"] == ["federated-auth-code"]

    def test_provisions_the_user_namespaced_to_github(self, client, github_env):
        cache_set("valid-state", {"resource_owner": _resource_owner_request()})
        client.get("/callback/github", query_string={"state": "valid-state", "code": "c"})
        assert github_env["users"][0]["user_id"] == "github|583231"

    def test_an_unknown_state_is_refused(self, client, github_env):
        response = client.get(
            "/callback/github", query_string={"state": "never-issued", "code": "c"}
        )
        assert response.status_code == 400
        assert github_env["codes"] == []

    def test_user_denial_is_relayed_to_the_client(self, client, github_env):
        cache_set("valid-state", {"resource_owner": _resource_owner_request()})
        response = client.get(
            "/callback/github",
            query_string={"state": "valid-state", "error": "access_denied"},
        )
        assert _query(response)["error"] == ["access_denied"]

    def test_a_private_email_prompts_the_user_to_supply_one(
        self, client, github_env, monkeypatch
    ):
        # GitHub omits the address when the user keeps it private, and the server
        # cannot provision an account without one.
        monkeypatch.setattr(
            github_callback,
            "get_userinfo",
            lambda token: {"id": 583231, "login": "octocat", "email": None},
        )
        monkeypatch.setattr(github_callback, "get_user_from_user_id", lambda uid: None)
        cache_set("valid-state", {"resource_owner": _resource_owner_request()})
        response = client.get(
            "/callback/github", query_string={"state": "valid-state", "code": "c"}
        )
        assert response.status_code == 200
        assert b"email" in response.data.lower()
        assert github_env["codes"] == []

    def test_a_returning_user_keeps_their_stored_email(
        self, client, github_env, monkeypatch
    ):
        monkeypatch.setattr(
            github_callback,
            "get_userinfo",
            lambda token: {"id": 583231, "login": "octocat", "email": None},
        )
        monkeypatch.setattr(
            github_callback,
            "get_user_from_user_id",
            lambda uid: make_user(email="stored@github.test", email_verified=True),
        )
        cache_set("valid-state", {"resource_owner": _resource_owner_request()})
        response = client.get(
            "/callback/github", query_string={"state": "valid-state", "code": "c"}
        )
        assert response.status_code == 302
        assert github_env["users"][0]["defaults"]["email"] == "stored@github.test"

    def test_submitting_a_valid_email_completes_the_flow(
        self, client, github_env, monkeypatch
    ):
        monkeypatch.setattr(
            github_callback, "email_already_registered", lambda email: False
        )
        cache_set(
            "pending-state",
            {
                "resource_owner_request": _resource_owner_request(),
                "user_id": "github|583231",
                "username": "octocat",
                "claims": {"preferred_username": "octocat"},
            },
        )
        response = client.post(
            "/callback/github",
            data={"pending_state": "pending-state", "email": "chosen@github.test"},
        )
        assert response.status_code == 302
        assert github_env["users"][0]["defaults"]["email"] == "chosen@github.test"
        # A self-asserted address is never treated as verified.
        assert github_env["users"][0]["defaults"]["email_verified"] is False

    def test_an_invalid_submitted_email_is_refused(self, client, github_env, monkeypatch):
        monkeypatch.setattr(
            github_callback, "email_already_registered", lambda email: False
        )
        cache_set(
            "pending-state",
            {
                "resource_owner_request": _resource_owner_request(),
                "user_id": "github|583231",
                "username": "octocat",
                "claims": {},
            },
        )
        response = client.post(
            "/callback/github",
            data={"pending_state": "pending-state", "email": "not-an-email"},
        )
        assert response.status_code == 400
        assert github_env["codes"] == []

    def test_an_already_registered_email_is_refused(
        self, client, github_env, monkeypatch
    ):
        monkeypatch.setattr(
            github_callback, "email_already_registered", lambda email: True
        )
        cache_set(
            "pending-state",
            {
                "resource_owner_request": _resource_owner_request(),
                "user_id": "github|583231",
                "username": "octocat",
                "claims": {},
            },
        )
        response = client.post(
            "/callback/github",
            data={"pending_state": "pending-state", "email": "taken@github.test"},
        )
        assert response.status_code == 400
        assert b"already exists" in response.data

    def test_an_expired_pending_state_is_refused(self, client, github_env):
        response = client.post(
            "/callback/github",
            data={"pending_state": "never-issued", "email": "a@b.test"},
        )
        assert response.status_code == 400
