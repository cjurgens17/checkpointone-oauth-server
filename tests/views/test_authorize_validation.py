"""Tests for the request validation performed by GET/POST /authorize.

RFC 6749 section 4.1.2.1 draws a hard line here: errors involving the client_id
or redirect_uri must NOT redirect (a bad URI is exactly what an attacker
supplies), while every later error redirects back with an error code. These
tests hold that line.
"""

from urllib.parse import parse_qs, urlsplit

import pytest

from tests.factories import DEFAULT_REDIRECT_URI, authorize_query


def _error(response):
    return parse_qs(urlsplit(response.headers["Location"]).query)


class TestClientAndRedirectUriAreNeverRedirected:
    def test_unknown_client_renders_an_error_page(self, client, authorize_env):
        response = client.get("/authorize", query_string=authorize_query(client_id="nope"))
        assert response.status_code == 400
        assert b"client_id" in response.data

    def test_missing_client_renders_an_error_page(self, client, authorize_env):
        query = authorize_query()
        del query["client_id"]
        response = client.get("/authorize", query_string=query)
        assert response.status_code == 400

    def test_missing_redirect_uri_renders_an_error_page(self, client, authorize_env):
        query = authorize_query()
        del query["redirect_uri"]
        response = client.get("/authorize", query_string=query)
        assert response.status_code == 400
        assert response.headers.get("Location") is None

    def test_malformed_redirect_uri_renders_an_error_page(self, client, authorize_env):
        response = client.get(
            "/authorize", query_string=authorize_query(redirect_uri="not-a-uri")
        )
        assert response.status_code == 400
        assert response.headers.get("Location") is None

    def test_unregistered_redirect_uri_renders_an_error_page(self, client, authorize_env):
        # The open-redirect defence: never bounce to a URI the client did not
        # register, not even to report the error.
        response = client.get(
            "/authorize",
            query_string=authorize_query(redirect_uri="https://attacker.test/steal"),
        )
        assert response.status_code == 400
        assert response.headers.get("Location") is None
        assert b"attacker.test" not in response.data or response.status_code == 400


class TestParameterErrorsRedirectBack:
    def test_missing_response_type(self, client, authorize_env):
        query = authorize_query()
        del query["response_type"]
        response = client.get("/authorize", query_string=query)
        assert response.status_code == 302
        assert _error(response)["error"] == ["unsupported_response_type"]

    def test_unsupported_response_type(self, client, authorize_env):
        response = client.get(
            "/authorize", query_string=authorize_query(response_type="id_token")
        )
        assert _error(response)["error"] == ["unsupported_response_type"]

    def test_scope_without_openid(self, client, authorize_env):
        response = client.get(
            "/authorize", query_string=authorize_query(scope="email profile")
        )
        assert _error(response)["error"] == ["invalid_scope"]

    def test_scope_beyond_registered_permissions(self, client, authorize_env):
        response = client.get(
            "/authorize", query_string=authorize_query(scope="openid admin:all")
        )
        assert _error(response)["error"] == ["invalid_scope"]

    def test_unsupported_code_challenge_method(self, client, authorize_env):
        response = client.get(
            "/authorize", query_string=authorize_query(code_challenge_method="plain")
        )
        assert _error(response)["error"] == ["invalid_code_challenge_method"]

    def test_missing_code_challenge(self, client, authorize_env):
        # PKCE is mandatory for every authorization code flow on this server.
        query = authorize_query()
        del query["code_challenge"]
        response = client.get("/authorize", query_string=query)
        assert _error(response)["error"] == ["invalid_code_challenge"]

    def test_unsupported_connection(self, client, authorize_env):
        response = client.get(
            "/authorize", query_string=authorize_query(connection="facebook")
        )
        assert _error(response)["error"] == ["invalid_connection"]

    def test_prompt_not_supported_for_the_connection(self, client, authorize_env):
        # prompt=login has no GitHub equivalent, so it is refused rather than
        # silently ignored.
        response = client.get(
            "/authorize", query_string=authorize_query(connection="github", prompt="login")
        )
        assert _error(response)["error"] == ["invalid_prompt"]

    def test_the_state_is_echoed_back_on_error(self, client, authorize_env):
        # Without state the client cannot correlate the error with its request.
        response = client.get(
            "/authorize",
            query_string=authorize_query(response_type="bad", state="correlate-me"),
        )
        assert _error(response)["state"] == ["correlate-me"]

    def test_errors_redirect_to_the_registered_uri(self, client, authorize_env):
        response = client.get(
            "/authorize", query_string=authorize_query(response_type="bad")
        )
        location = response.headers["Location"]
        assert location.startswith(DEFAULT_REDIRECT_URI)


class TestValidationOrdering:
    def test_missing_code_challenge_method_redirects_with_an_oauth_error(
        self, client, authorize_env
    ):
        # Regression guard: an unguarded .lower() made this a 500 rather than an
        # OAuth error, reachable by any unauthenticated caller.
        query = authorize_query()
        del query["code_challenge_method"]
        response = client.get("/authorize", query_string=query)
        assert response.status_code == 302
        assert _error(response)["error"] == ["invalid_code_challenge_method"]

    def test_no_missing_parameter_produces_a_server_error(self, app, authorize_env):
        app.config["PROPAGATE_EXCEPTIONS"] = False
        try:
            test_client = app.test_client()
            for omitted in (
                "response_type",
                "scope",
                "code_challenge",
                "code_challenge_method",
                "connection",
                "state",
                "audience",
            ):
                query = authorize_query()
                query.pop(omitted, None)
                response = test_client.get("/authorize", query_string=query)
                assert response.status_code < 500, f"omitting {omitted} caused a 5xx"
        finally:
            app.config.pop("PROPAGATE_EXCEPTIONS", None)

    def test_a_valid_request_reaches_the_login_form(self, client, authorize_env):
        response = client.get("/authorize", query_string=authorize_query())
        assert response.status_code == 200
        assert b"<form" in response.data


class TestScreenHint:
    def test_an_unknown_screen_hint_falls_back_to_login(self, client, authorize_env):
        response = client.get(
            "/authorize", query_string=authorize_query(screen_hint="nonsense")
        )
        assert response.status_code == 200

    @pytest.mark.parametrize("screen_hint", ["login", "signup", "passkey"])
    def test_documented_screen_hints_are_accepted(
        self, client, authorize_env, screen_hint
    ):
        response = client.get(
            "/authorize", query_string=authorize_query(screen_hint=screen_hint)
        )
        assert response.status_code == 200
