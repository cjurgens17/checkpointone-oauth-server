"""Tests for the Google and GitHub connections at /authorize.

These cover the outbound leg only - building the redirect to the upstream
provider and stashing the original request under a state value. The inbound leg
lives in test_callbacks_*.py.
"""

from urllib.parse import parse_qs, urlsplit

import pytest

import views.authorize as authorize_view
from tests.factories import authorize_query
from utility.constants import IdentityProvider, Prompt


@pytest.fixture
def captured_state(monkeypatch):
    """Record what gets stashed for the return trip."""
    stashed = []

    def _prepare(data):
        stashed.append(data)
        return f"server-state-{len(stashed)}"

    monkeypatch.setattr(authorize_view, "prepare_redirect_to_oauth_server", _prepare)
    return stashed


def _params(response):
    return parse_qs(urlsplit(response.headers["Location"]).query)


class TestGoogleRedirect:
    def test_redirects_to_googles_authorization_endpoint(
        self, client, authorize_env, captured_state
    ):
        response = client.get(
            "/authorize", query_string=authorize_query(connection=IdentityProvider.GOOGLE)
        )
        assert response.status_code == 302
        assert response.headers["Location"].startswith(
            authorize_view.GOOGLE_AUTHORIZATION_ENDPOINT
        )

    def test_sends_googles_own_client_id_and_redirect_uri(
        self, client, authorize_env, captured_state
    ):
        response = client.get(
            "/authorize", query_string=authorize_query(connection=IdentityProvider.GOOGLE)
        )
        params = _params(response)
        assert params["client_id"] == [authorize_view.GOOGLE_CLIENT_ID]
        assert params["redirect_uri"] == [authorize_view.GOOGLE_REDIRECT_URI]
        assert params["response_type"] == ["code"]

    def test_forwards_only_the_openid_portion_of_the_scope(
        self, client, authorize_env, captured_state
    ):
        # API permissions are meaningless to Google, so only OIDC scopes travel.
        response = client.get(
            "/authorize",
            query_string=authorize_query(
                connection=IdentityProvider.GOOGLE, scope="openid email offline_access"
            ),
        )
        assert _params(response)["scope"] == ["openid email"]

    def test_state_is_the_opaque_server_state(
        self, client, authorize_env, captured_state
    ):
        # The client's own state must not be exposed to Google; the server
        # substitutes its own handle.
        response = client.get(
            "/authorize",
            query_string=authorize_query(
                connection=IdentityProvider.GOOGLE, state="clients-own-state"
            ),
        )
        assert _params(response)["state"] == ["server-state-1"]

    def test_the_original_request_is_stashed_for_the_return_trip(
        self, client, authorize_env, captured_state
    ):
        client.get(
            "/authorize",
            query_string=authorize_query(
                connection=IdentityProvider.GOOGLE, state="clients-own-state"
            ),
        )
        stashed = captured_state[0]
        assert stashed["state"] == "clients-own-state"
        assert stashed["client_id"] == authorize_env["application"].client_id
        assert stashed["code_challenge"] == authorize_query()["code_challenge"]

    def test_defaults_to_select_account(self, client, authorize_env, captured_state):
        response = client.get(
            "/authorize", query_string=authorize_query(connection=IdentityProvider.GOOGLE)
        )
        assert _params(response)["prompt"] == [Prompt.SELECT_ACCOUNT]

    def test_forwards_an_explicit_prompt(self, client, authorize_env, captured_state):
        response = client.get(
            "/authorize",
            query_string=authorize_query(
                connection=IdentityProvider.GOOGLE, prompt=Prompt.CONSENT
            ),
        )
        assert _params(response)["prompt"] == [Prompt.CONSENT]

    def test_an_existing_session_short_circuits_the_federated_round_trip(
        self, client, registered_application, issued_codes, issued_sessions,
        active_session, captured_state,
    ):
        response = client.get(
            "/authorize", query_string=authorize_query(connection=IdentityProvider.GOOGLE)
        )
        assert _params(response)["code"] == ["auth-code-1"]
        assert captured_state == []

    def test_prompt_login_bypasses_the_session(
        self, client, registered_application, issued_codes, issued_sessions,
        active_session, captured_state,
    ):
        # prompt=login is invalid for Google per valid_prompt, so the request is
        # rejected before reaching the provider at all.
        response = client.get(
            "/authorize",
            query_string=authorize_query(
                connection=IdentityProvider.GOOGLE, prompt=Prompt.LOGIN
            ),
        )
        assert _params(response)["error"] == ["invalid_prompt"]


class TestGithubRedirect:
    def test_redirects_to_githubs_authorization_endpoint(
        self, client, authorize_env, captured_state
    ):
        response = client.get(
            "/authorize", query_string=authorize_query(connection=IdentityProvider.GITHUB)
        )
        assert response.status_code == 302
        assert response.headers["Location"].startswith(
            authorize_view.GITHUB_AUTHORIZATION_ENDPOINT
        )

    def test_requests_the_fixed_github_scope(
        self, client, authorize_env, captured_state
    ):
        response = client.get(
            "/authorize", query_string=authorize_query(connection=IdentityProvider.GITHUB)
        )
        assert _params(response)["scope"] == [authorize_view.GITHUB_SCOPE]

    def test_always_forces_select_account(self, client, authorize_env, captured_state):
        # Matches the Google sign-out experience so a user can tell they really
        # left the authorization server's session.
        response = client.get(
            "/authorize", query_string=authorize_query(connection=IdentityProvider.GITHUB)
        )
        assert _params(response)["prompt"] == [Prompt.SELECT_ACCOUNT]

    def test_stashes_the_original_request(self, client, authorize_env, captured_state):
        client.get(
            "/authorize",
            query_string=authorize_query(
                connection=IdentityProvider.GITHUB, state="clients-own-state"
            ),
        )
        assert captured_state[0]["state"] == "clients-own-state"

    def test_an_existing_session_short_circuits_the_round_trip(
        self, client, registered_application, issued_codes, issued_sessions,
        active_session, captured_state,
    ):
        response = client.get(
            "/authorize", query_string=authorize_query(connection=IdentityProvider.GITHUB)
        )
        assert _params(response)["code"] == ["auth-code-1"]
        assert captured_state == []
