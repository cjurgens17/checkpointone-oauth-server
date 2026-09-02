"""Tests for the native (username/password) connection at /authorize.

Covers login, signup, silent SSO from an existing session, and the passkey
enrolment interstitial.
"""

from urllib.parse import parse_qs, urlsplit

import pytest

import views.authorize as authorize_view
from tests.factories import (
    DEFAULT_PASSWORD,
    DEFAULT_REDIRECT_URI,
    authorize_query,
    make_user,
)


@pytest.fixture
def credentials(monkeypatch):
    """A user who authenticates with the factory default password."""
    user = make_user()
    monkeypatch.setattr(
        authorize_view,
        "authenticate_user",
        lambda username, password: user
        if (username, password) == (user.email, DEFAULT_PASSWORD)
        else None,
    )
    monkeypatch.setattr(authorize_view, "user_has_passkey", lambda user_id: True)
    return user


def _redirect_query(response):
    return parse_qs(urlsplit(response.headers["Location"]).query)


class TestLoginForm:
    def test_get_renders_the_login_form(self, client, authorize_env):
        response = client.get("/authorize", query_string=authorize_query())
        assert response.status_code == 200
        assert b"<form" in response.data

    def test_the_form_carries_the_oauth_parameters_forward(self, client, authorize_env):
        # The POST back to /authorize must replay the original request, so the
        # parameters have to survive in the rendered form.
        response = client.get(
            "/authorize", query_string=authorize_query(state="carried-state")
        )
        assert b"carried-state" in response.data


class TestSuccessfulLogin:
    def test_redirects_to_the_client_with_a_code(self, client, authorize_env, credentials):
        response = client.post(
            "/authorize",
            query_string=authorize_query(),
            data={"username": credentials.email, "password": DEFAULT_PASSWORD},
        )
        assert response.status_code == 302
        assert response.headers["Location"].startswith(DEFAULT_REDIRECT_URI)
        assert _redirect_query(response)["code"] == ["auth-code-1"]

    def test_echoes_the_state(self, client, authorize_env, credentials):
        response = client.post(
            "/authorize",
            query_string=authorize_query(state="round-trip"),
            data={"username": credentials.email, "password": DEFAULT_PASSWORD},
        )
        assert _redirect_query(response)["state"] == ["round-trip"]

    def test_the_code_records_the_subject_and_pkce_challenge(
        self, client, authorize_env, credentials
    ):
        client.post(
            "/authorize",
            query_string=authorize_query(),
            data={"username": credentials.email, "password": DEFAULT_PASSWORD},
        )
        payload = authorize_env["codes"][0]
        assert payload["sub"] == credentials.sub
        assert payload["code_challenge"] == authorize_query()["code_challenge"]
        assert payload["redirect_uri"] == DEFAULT_REDIRECT_URI

    def test_the_code_carries_provider_claims_for_the_id_token(
        self, client, authorize_env, credentials
    ):
        client.post(
            "/authorize",
            query_string=authorize_query(),
            data={"username": credentials.email, "password": DEFAULT_PASSWORD},
        )
        assert authorize_env["codes"][0]["provider_claims"]["email"] == credentials.email

    def test_a_session_cookie_is_established(self, client, authorize_env, credentials):
        response = client.post(
            "/authorize",
            query_string=authorize_query(),
            data={"username": credentials.email, "password": DEFAULT_PASSWORD},
        )
        assert authorize_view.SESSION_COOKIE_NAME in response.headers.get(
            "Set-Cookie", ""
        )
        assert authorize_env["sessions"][0]["user_id"] == credentials.user_id


class TestFailedLogin:
    def test_wrong_password_returns_401_and_redisplays_the_form(
        self, client, authorize_env, credentials
    ):
        response = client.post(
            "/authorize",
            query_string=authorize_query(),
            data={"username": credentials.email, "password": "WrongPassword1!"},
        )
        assert response.status_code == 401
        assert b"<form" in response.data

    def test_unknown_user_returns_the_same_response_as_a_wrong_password(
        self, client, authorize_env, credentials
    ):
        # Identical answers keep the form from confirming which addresses exist.
        wrong_password = client.post(
            "/authorize",
            query_string=authorize_query(),
            data={"username": credentials.email, "password": "WrongPassword1!"},
        )
        unknown_user = client.post(
            "/authorize",
            query_string=authorize_query(),
            data={"username": "nobody@checkpointone.com", "password": DEFAULT_PASSWORD},
        )
        assert wrong_password.status_code == unknown_user.status_code == 401
        assert b"Incorrect username or password" in unknown_user.data

    def test_no_code_is_issued_on_failure(self, client, authorize_env, credentials):
        client.post(
            "/authorize",
            query_string=authorize_query(),
            data={"username": credentials.email, "password": "nope"},
        )
        assert authorize_env["codes"] == []

    def test_no_session_is_established_on_failure(self, client, authorize_env, credentials):
        client.post(
            "/authorize",
            query_string=authorize_query(),
            data={"username": credentials.email, "password": "nope"},
        )
        assert authorize_env["sessions"] == []


class TestSilentSingleSignOn:
    def test_an_existing_session_issues_a_code_without_a_prompt(
        self, client, registered_application, issued_codes, issued_sessions, active_session
    ):
        response = client.get("/authorize", query_string=authorize_query())
        assert response.status_code == 302
        assert _redirect_query(response)["code"] == ["auth-code-1"]

    def test_prompt_login_forces_reauthentication_despite_a_session(
        self, client, registered_application, issued_codes, issued_sessions, active_session
    ):
        response = client.get(
            "/authorize", query_string=authorize_query(prompt="login")
        )
        assert response.status_code == 200
        assert issued_codes == []

    def test_a_session_whose_user_vanished_falls_back_to_the_login_form(
        self, client, registered_application, issued_codes, issued_sessions,
        active_session, monkeypatch,
    ):
        # SessionUserNotFoundError is raised and handled by ending the session
        # rather than surfacing a 500.
        monkeypatch.setattr(authorize_view, "get_user_from_user_id", lambda uid: None)
        ended = []
        monkeypatch.setattr(
            authorize_view,
            "end_session",
            lambda response, sid: ended.append(sid) or response,
        )
        response = client.get("/authorize", query_string=authorize_query())
        assert response.status_code == 200
        assert issued_codes == []
        assert ended


class TestSignup:
    @pytest.fixture
    def signup_env(self, monkeypatch, authorize_env):
        registered = []
        monkeypatch.setattr(
            authorize_view, "email_already_registered", lambda email: email in registered
        )
        monkeypatch.setattr(
            authorize_view,
            "register_user",
            lambda email, password, tenant_id: make_user(email=email, username=email),
        )
        monkeypatch.setattr(authorize_view, "user_has_passkey", lambda user_id: True)
        return {"registered": registered, **authorize_env}

    def test_get_renders_the_signup_form(self, client, signup_env):
        response = client.get(
            "/authorize", query_string=authorize_query(screen_hint="signup")
        )
        assert response.status_code == 200
        assert b"<form" in response.data

    def test_valid_signup_creates_the_account_and_issues_a_code(self, client, signup_env):
        response = client.post(
            "/authorize",
            query_string=authorize_query(screen_hint="signup"),
            data={
                "email": "new@checkpointone.com",
                "password": DEFAULT_PASSWORD,
                "confirm_password": DEFAULT_PASSWORD,
            },
        )
        assert response.status_code == 302
        assert _redirect_query(response)["code"] == ["auth-code-1"]

    @pytest.mark.parametrize(
        ("form", "expected"),
        [
            (
                {"email": "not-an-email", "password": DEFAULT_PASSWORD,
                 "confirm_password": DEFAULT_PASSWORD},
                b"valid email",
            ),
            (
                {"email": "new@checkpointone.com", "password": "weak",
                 "confirm_password": "weak"},
                b"Password must be at least",
            ),
            (
                {"email": "new@checkpointone.com", "password": DEFAULT_PASSWORD,
                 "confirm_password": "Different1!"},
                b"do not match",
            ),
        ],
    )
    def test_invalid_signup_returns_400_with_a_message(
        self, client, signup_env, form, expected
    ):
        response = client.post(
            "/authorize", query_string=authorize_query(screen_hint="signup"), data=form
        )
        assert response.status_code == 400
        assert expected in response.data

    def test_duplicate_email_is_refused(self, client, signup_env):
        signup_env["registered"].append("taken@checkpointone.com")
        response = client.post(
            "/authorize",
            query_string=authorize_query(screen_hint="signup"),
            data={
                "email": "taken@checkpointone.com",
                "password": DEFAULT_PASSWORD,
                "confirm_password": DEFAULT_PASSWORD,
            },
        )
        assert response.status_code == 400
        assert b"already exists" in response.data

    def test_signup_ignores_an_existing_session(
        self, client, signup_env, active_session
    ):
        # Signup always creates a fresh account, so it must not silently reuse
        # whoever is already signed in.
        response = client.get(
            "/authorize", query_string=authorize_query(screen_hint="signup")
        )
        assert response.status_code == 200
        assert signup_env["codes"] == []


class TestPasskeyPrompt:
    def test_a_user_without_a_passkey_is_offered_enrolment(
        self, client, authorize_env, credentials, monkeypatch
    ):
        monkeypatch.setattr(authorize_view, "user_has_passkey", lambda user_id: False)
        response = client.post(
            "/authorize",
            query_string=authorize_query(screen_hint="passkey"),
            data={"username": credentials.email, "password": DEFAULT_PASSWORD},
        )
        assert response.status_code == 200
        assert b"Passkey" in response.data
        # The code is deferred until the user finishes or skips enrolment.
        assert authorize_env["codes"] == []

    def test_the_prompt_still_establishes_the_session(
        self, client, authorize_env, credentials, monkeypatch
    ):
        monkeypatch.setattr(authorize_view, "user_has_passkey", lambda user_id: False)
        response = client.post(
            "/authorize",
            query_string=authorize_query(screen_hint="passkey"),
            data={"username": credentials.email, "password": DEFAULT_PASSWORD},
        )
        assert authorize_view.SESSION_COOKIE_NAME in response.headers.get("Set-Cookie", "")

    def test_a_user_who_already_has_a_passkey_is_not_prompted(
        self, client, authorize_env, credentials, monkeypatch
    ):
        monkeypatch.setattr(authorize_view, "user_has_passkey", lambda user_id: True)
        response = client.post(
            "/authorize",
            query_string=authorize_query(screen_hint="passkey"),
            data={"username": credentials.email, "password": DEFAULT_PASSWORD},
        )
        assert response.status_code == 302

    def test_enrolment_is_skipped_without_the_passkey_screen_hint(
        self, client, authorize_env, credentials, monkeypatch
    ):
        monkeypatch.setattr(authorize_view, "user_has_passkey", lambda user_id: False)
        response = client.post(
            "/authorize",
            query_string=authorize_query(),
            data={"username": credentials.email, "password": DEFAULT_PASSWORD},
        )
        assert response.status_code == 302
