"""Tests for services.connections.github."""

import pytest
import responses

from services.connections.github import (
    GITHUB_SCOPE,
    GITHUB_TOKEN_ENDPOINT,
    GITHUB_USERINFO,
    exchange_code_for_access_token,
    get_userinfo,
    normalize_userinfo_claims,
)


class TestExchangeCodeForAccessToken:
    @responses.activate
    def test_returns_the_access_token(self):
        responses.post(GITHUB_TOKEN_ENDPOINT, json={"access_token": "gho_token"})
        assert exchange_code_for_access_token("auth-code") == "gho_token"

    @responses.activate
    def test_posts_the_code_and_client_credentials(self):
        responses.post(GITHUB_TOKEN_ENDPOINT, json={"access_token": "t"})
        exchange_code_for_access_token("auth-code")

        request = responses.calls[0].request
        assert "code=auth-code" in request.body
        assert "client_secret=" in request.body
        # GitHub returns form-encoded bodies unless JSON is requested explicitly.
        assert request.headers["Accept"] == "application/json"

    @responses.activate
    def test_returns_none_when_github_reports_an_error(self):
        # GitHub answers 200 with an error document for a bad code, so the
        # caller receives None rather than an exception.
        responses.post(GITHUB_TOKEN_ENDPOINT, json={"error": "bad_verification_code"})
        assert exchange_code_for_access_token("stale-code") is None

    @responses.activate
    def test_raises_when_the_body_is_not_json(self):
        responses.post(GITHUB_TOKEN_ENDPOINT, body="<html>502</html>", status=502)
        with pytest.raises(ValueError, match="Github Token Exchange failed"):
            exchange_code_for_access_token("auth-code")


class TestGetUserinfo:
    @responses.activate
    def test_returns_the_profile(self):
        responses.get(GITHUB_USERINFO, json={"id": 1, "login": "octocat"})
        assert get_userinfo("gho_token") == {"id": 1, "login": "octocat"}

    @responses.activate
    def test_sends_the_bearer_token(self):
        responses.get(GITHUB_USERINFO, json={"id": 1})
        get_userinfo("gho_token")
        assert responses.calls[0].request.headers["Authorization"] == "Bearer gho_token"

    @responses.activate
    def test_raises_when_the_body_is_not_json(self):
        responses.get(GITHUB_USERINFO, body="Unauthorized", status=401)
        with pytest.raises(ValueError, match="Github userinfo request failed"):
            get_userinfo("bad-token")


class TestNormalizeUserinfoClaims:
    def test_maps_every_supported_field(self):
        claims = normalize_userinfo_claims(
            {
                "name": "The Octocat",
                "login": "octocat",
                "avatar_url": "https://avatars.test/octocat.png",
                "html_url": "https://github.com/octocat",
                "blog": "https://octocat.test",
                "email": "octocat@github.test",
            }
        )
        assert claims == {
            "name": "The Octocat",
            "preferred_username": "octocat",
            "nickname": "octocat",
            "picture": "https://avatars.test/octocat.png",
            "profile": "https://github.com/octocat",
            "website": "https://octocat.test",
            "email": "octocat@github.test",
        }

    def test_login_populates_both_username_claims(self):
        claims = normalize_userinfo_claims({"login": "octocat"})
        assert claims["preferred_username"] == claims["nickname"] == "octocat"

    def test_omits_absent_fields(self):
        assert normalize_userinfo_claims({"login": "octocat"}) == {
            "preferred_username": "octocat",
            "nickname": "octocat",
        }

    def test_empty_profile_yields_no_claims(self):
        assert normalize_userinfo_claims({}) == {}

    def test_empty_strings_are_treated_as_absent(self):
        # GitHub returns "" rather than null for an unset blog or name.
        claims = normalize_userinfo_claims({"name": "", "blog": "", "login": "octocat"})
        assert "name" not in claims
        assert "website" not in claims

    def test_null_email_is_dropped(self):
        # A user with private email settings has email=None; the callback view
        # relies on that key being absent to trigger its email prompt.
        assert "email" not in normalize_userinfo_claims({"email": None, "login": "o"})

    def test_unknown_fields_are_ignored(self):
        claims = normalize_userinfo_claims({"login": "o", "company": "GitHub"})
        assert "company" not in claims


class TestGithubScope:
    def test_requests_the_fixed_scope_set(self):
        # GitHub has no OIDC scope model, so the server always asks for the
        # permissions it needs to build a profile.
        assert GITHUB_SCOPE == "read:user user:email"
