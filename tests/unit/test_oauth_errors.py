"""Tests for utility.oauth_errors - the RFC 6749 error redirect helper."""

from urllib.parse import parse_qs, urlsplit

import pytest

from utility.oauth_errors import redirect_with_error


@pytest.fixture
def app():
    """redirect() needs an application context to build a response."""
    from flask import Flask

    return Flask(__name__)


def _query(response):
    return parse_qs(urlsplit(response.headers["Location"]).query)


class TestRedirectWithError:
    def test_returns_a_302_to_the_redirect_uri(self, app):
        with app.test_request_context():
            response = redirect_with_error("https://app.test/cb", "invalid_scope")
        assert response.status_code == 302
        assert urlsplit(response.headers["Location"]).netloc == "app.test"

    def test_includes_the_error_code(self, app):
        with app.test_request_context():
            response = redirect_with_error("https://app.test/cb", "invalid_scope")
        assert _query(response)["error"] == ["invalid_scope"]

    def test_includes_description_and_state_when_supplied(self, app):
        with app.test_request_context():
            response = redirect_with_error(
                "https://app.test/cb",
                "invalid_scope",
                error_description="The requested scope is invalid.",
                state="opaque-state",
            )
        query = _query(response)
        assert query["error_description"] == ["The requested scope is invalid."]
        assert query["state"] == ["opaque-state"]

    def test_omits_description_and_state_when_absent(self, app):
        with app.test_request_context():
            response = redirect_with_error("https://app.test/cb", "invalid_scope")
        query = _query(response)
        assert "error_description" not in query
        assert "state" not in query

    def test_preserves_query_parameters_already_on_the_redirect_uri(self, app):
        # A client may register a redirect URI that carries its own parameters;
        # dropping them would break the round trip back into the application.
        with app.test_request_context():
            response = redirect_with_error(
                "https://app.test/cb?tenant=acme", "access_denied", state="s"
            )
        query = _query(response)
        assert query["tenant"] == ["acme"]
        assert query["error"] == ["access_denied"]
        assert query["state"] == ["s"]

    def test_preserves_the_uri_fragment(self, app):
        with app.test_request_context():
            response = redirect_with_error("https://app.test/cb#anchor", "invalid_scope")
        assert urlsplit(response.headers["Location"]).fragment == "anchor"

    def test_encodes_characters_that_would_otherwise_break_the_query(self, app):
        with app.test_request_context():
            response = redirect_with_error(
                "https://app.test/cb",
                "invalid_request",
                error_description="spaces & ampersands = trouble",
            )
        location = response.headers["Location"]
        assert " " not in location
        assert _query(response)["error_description"] == [
            "spaces & ampersands = trouble"
        ]

    def test_a_state_containing_a_separator_cannot_forge_extra_parameters(self, app):
        # Attacker-influenced state must stay a single value rather than
        # splitting into additional query parameters.
        with app.test_request_context():
            response = redirect_with_error(
                "https://app.test/cb", "invalid_scope", state="x&error=none"
            )
        query = _query(response)
        assert query["state"] == ["x&error=none"]
        assert query["error"] == ["invalid_scope"]
