"""Tests for utility.validation.

This module is the authorization server's input filter, so the cases below lean
on the failure modes that matter for an OAuth 2.0 deployment: open redirects,
CRLF injection into a redirect URI, and scope escalation past what a client is
registered for.
"""

import pytest

from utility.constants import IdentityProvider, Prompt
from utility.validation import (
    MIN_PASSWORD_LENGTH,
    valid_code_challenge_method,
    valid_connection,
    valid_email,
    valid_password,
    valid_prompt,
    valid_redirect_uri,
    valid_response_type,
    valid_scope,
)


class TestValidRedirectUri:
    @pytest.mark.parametrize(
        "redirect_uri",
        [
            "https://app.test/callback",
            "http://localhost:4200/callback",
            "https://app.test/callback?next=%2Fdashboard",
            "https://app.test:8443/deep/path",
            "com.checkpointone.app://callback",
            "https://app.test/callback#fragment",
        ],
    )
    def test_accepts_well_formed_absolute_uris(self, redirect_uri):
        assert valid_redirect_uri(redirect_uri) is True

    @pytest.mark.parametrize(
        "redirect_uri",
        [
            "",
            None,
            "/relative/path",
            "app.test/callback",
            "https://",
        ],
    )
    def test_rejects_missing_scheme_or_authority(self, redirect_uri):
        assert valid_redirect_uri(redirect_uri) is False

    @pytest.mark.parametrize(
        "redirect_uri",
        [
            "https://app.test/callback\r\nSet-Cookie: session=stolen",
            "https://app.test/callback\nX-Injected: 1",
            "https://app.test/call\tback",
            "https://app.test/callback\x00",
        ],
    )
    def test_rejects_control_characters_used_for_header_injection(self, redirect_uri):
        assert valid_redirect_uri(redirect_uri) is False

    @pytest.mark.parametrize(
        "redirect_uri",
        [
            "https://app.test/%zz",
            "https://app.test/%2",
            "https://app.test/100%",
        ],
    )
    def test_rejects_malformed_percent_encoding(self, redirect_uri):
        assert valid_redirect_uri(redirect_uri) is False

    @pytest.mark.parametrize(
        "redirect_uri",
        [
            "https://app.test/<script>",
            'https://app.test/"quoted"',
            "https://app.test/`backtick`",
            "https://ex\\ample.test/cb",
            "https://app.test/{braces}",
            "https://app.test/pipe|char",
            "https://app.tëst/cb",
        ],
    )
    def test_rejects_characters_outside_the_rfc3986_set(self, redirect_uri):
        # These parse cleanly as URLs but contain characters a URI may not carry
        # unencoded, so the allow-list is what stops them.
        assert valid_redirect_uri(redirect_uri) is False

    def test_rejects_a_uri_that_cannot_be_parsed(self):
        # An unterminated IPv6 literal makes urlsplit raise; the caller must get
        # False rather than the exception.
        assert valid_redirect_uri("http://[::1") is False

    def test_rejects_control_characters_hidden_by_percent_encoding(self):
        # %0d%0a decodes to CRLF. The raw string looks clean, so this is only
        # caught because the query component is unquoted before being checked.
        assert valid_redirect_uri("https://app.test/cb?a=%0d%0aX-Injected:1") is False

    def test_rejects_non_string_input(self):
        assert valid_redirect_uri(12345) is False


class TestValidResponseType:
    @pytest.mark.parametrize("response_type", ["code", "token", "CODE", "Token"])
    def test_accepts_supported_response_types_case_insensitively(self, response_type):
        assert valid_response_type(response_type) is True

    @pytest.mark.parametrize("response_type", ["id_token", "code token", "", "none"])
    def test_rejects_unsupported_response_types(self, response_type):
        assert valid_response_type(response_type) is False


class TestValidScope:
    APP_PERMISSIONS = ["offline_access", "read:things"]

    def test_accepts_openid_only(self):
        assert valid_scope("openid", self.APP_PERMISSIONS) is True

    def test_accepts_openid_with_registered_application_permissions(self):
        assert valid_scope("openid email read:things", self.APP_PERMISSIONS) is True

    def test_requires_openid(self):
        # Every flow through this server issues an OIDC response, so a scope
        # without openid is rejected outright rather than downgraded.
        assert valid_scope("email profile", self.APP_PERMISSIONS) is False

    def test_rejects_permission_the_application_is_not_registered_for(self):
        assert valid_scope("openid admin:everything", self.APP_PERMISSIONS) is False

    @pytest.mark.parametrize(
        "scope",
        [
            " openid",
            "openid ",
            "openid  email",
            "openid\temail",
        ],
    )
    def test_rejects_malformed_whitespace(self, scope):
        assert valid_scope(scope, self.APP_PERMISSIONS) is False

    @pytest.mark.parametrize("scope", ["", None])
    def test_rejects_empty_scope(self, scope):
        assert valid_scope(scope, self.APP_PERMISSIONS) is False

    def test_openid_scopes_are_never_checked_against_application_permissions(self):
        # profile/email/address/phone are OIDC scopes rather than API permissions,
        # so an application need not enumerate them to request them.
        assert valid_scope("openid profile email address phone", []) is True


class TestValidCodeChallengeMethod:
    @pytest.mark.parametrize("method", ["S256", "s256"])
    def test_accepts_s256_in_either_case(self, method):
        assert valid_code_challenge_method(method) is True

    @pytest.mark.parametrize("method", ["plain", "S512", ""])
    def test_rejects_anything_weaker_than_s256(self, method):
        assert valid_code_challenge_method(method) is False

    def test_raises_on_none_rather_than_returning_false(self):
        # Documents current behaviour: callers must not pass None here. The
        # authorize view always supplies a string from request.values.
        with pytest.raises(AttributeError):
            valid_code_challenge_method(None)


class TestValidConnection:
    @pytest.mark.parametrize(
        "connection",
        [
            IdentityProvider.NATIVE,
            IdentityProvider.GOOGLE,
            IdentityProvider.GITHUB,
        ],
    )
    def test_accepts_every_supported_identity_provider(self, connection):
        assert valid_connection(connection) is True

    @pytest.mark.parametrize("connection", ["facebook", "", "cp1", None])
    def test_rejects_unknown_connections(self, connection):
        assert valid_connection(connection) is False


class TestValidPrompt:
    def test_absent_prompt_is_allowed_for_any_connection(self):
        assert valid_prompt(None, IdentityProvider.NATIVE) is True
        assert valid_prompt("", IdentityProvider.GITHUB) is True

    @pytest.mark.parametrize(
        "prompt",
        [Prompt.NONE, Prompt.LOGIN, Prompt.SELECT_ACCOUNT, Prompt.CONSENT],
    )
    def test_native_accepts_all_four_prompts(self, prompt):
        assert valid_prompt(prompt, IdentityProvider.NATIVE) is True

    @pytest.mark.parametrize(
        "prompt", [Prompt.CONSENT, Prompt.NONE, Prompt.SELECT_ACCOUNT]
    )
    def test_google_accepts_the_prompts_google_itself_supports(self, prompt):
        assert valid_prompt(prompt, IdentityProvider.GOOGLE) is True

    def test_google_rejects_login_prompt(self):
        assert valid_prompt(Prompt.LOGIN, IdentityProvider.GOOGLE) is False

    def test_github_rejects_any_explicit_prompt(self):
        # GitHub's authorize endpoint has no prompt parameter to forward.
        assert valid_prompt(Prompt.LOGIN, IdentityProvider.GITHUB) is False
        assert valid_prompt(Prompt.NONE, IdentityProvider.GITHUB) is False


class TestValidEmail:
    @pytest.mark.parametrize(
        "email",
        [
            "test@checkpointone.com",
            "first.last+tag@sub.domain.co.uk",
        ],
    )
    def test_accepts_plausible_addresses(self, email):
        assert valid_email(email) is True

    @pytest.mark.parametrize(
        "email",
        [
            "",
            None,
            "no-at-sign.com",
            "no@tld",
            "two@@at.com",
            "spaces in@email.com",
            "trailing@space.com ",
        ],
    )
    def test_rejects_malformed_addresses(self, email):
        assert valid_email(email) is False

    def test_rejects_non_string_input(self):
        assert valid_email(12345) is False


class TestValidPassword:
    def test_accepts_password_meeting_length_and_two_criteria(self):
        # Upper + digit satisfies the "2 of 3" rule.
        assert valid_password("Password1") is True

    def test_accepts_upper_and_symbol(self):
        assert valid_password("Password!") is True

    def test_accepts_digit_and_symbol(self):
        assert valid_password("password1!") is True

    def test_rejects_password_meeting_only_one_criterion(self):
        assert valid_password("passwordd") is False

    def test_rejects_password_below_minimum_length(self):
        assert len("Pass1!") < MIN_PASSWORD_LENGTH
        assert valid_password("Pass1!") is False

    def test_length_is_checked_before_complexity(self):
        # Satisfies all three criteria but is still too short.
        assert valid_password("Ab1!") is False

    @pytest.mark.parametrize("password", ["", None, 12345])
    def test_rejects_empty_and_non_string_input(self, password):
        assert valid_password(password) is False
