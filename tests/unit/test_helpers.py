"""Tests for utility.helpers - hashing, state generation, and URL building."""

import hashlib
import string
from datetime import timezone
from urllib.parse import parse_qs, urlsplit

import pytest

from utility.constants import VALID_OPEN_ID_SCOPE
from utility.helpers import (
    ALPHANUMERIC_LENGTH,
    STATE_MAX_LENGTH,
    STATE_MIN_LENGTH,
    build_encoded_url,
    generate_state,
    generate_unique_sub_id,
    get_current_timestamp,
    hash_sha256,
    retrieve_open_id_scope,
)


class TestHashSha256:
    def test_matches_hashlib(self):
        assert hash_sha256("code-verifier") == hashlib.sha256(b"code-verifier").hexdigest()

    def test_is_deterministic(self):
        assert hash_sha256("same-input") == hash_sha256("same-input")

    def test_differs_for_different_input(self):
        assert hash_sha256("a") != hash_sha256("b")

    def test_returns_hex_digest_of_expected_width(self):
        digest = hash_sha256("anything")
        assert len(digest) == 64
        assert set(digest) <= set(string.hexdigits.lower())


class TestGenerateState:
    def test_length_stays_within_configured_bounds(self):
        for _ in range(200):
            assert STATE_MIN_LENGTH <= len(generate_state()) <= STATE_MAX_LENGTH

    def test_uses_only_url_safe_alphanumerics(self):
        allowed = set(string.ascii_letters + string.digits)
        for _ in range(50):
            assert set(generate_state()) <= allowed

    def test_values_are_unpredictable(self):
        # State is the CSRF defence on the federated legs, so collisions would
        # be a real finding rather than a flake.
        assert len({generate_state() for _ in range(500)}) == 500


class TestGenerateUniqueSubId:
    def test_has_configured_length(self):
        assert len(generate_unique_sub_id()) == ALPHANUMERIC_LENGTH

    def test_uses_lowercase_alphanumerics_only(self):
        allowed = set(string.ascii_lowercase + string.digits)
        for _ in range(50):
            assert set(generate_unique_sub_id()) <= allowed

    def test_values_do_not_repeat(self):
        assert len({generate_unique_sub_id() for _ in range(500)}) == 500


class TestBuildEncodedUrl:
    def test_appends_encoded_query_parameters(self):
        url = build_encoded_url("https://app.test/cb", {"code": "abc", "state": "xyz"})
        parsed = urlsplit(url)
        assert parsed.scheme == "https"
        assert parsed.netloc == "app.test"
        assert parsed.path == "/cb"
        assert parse_qs(parsed.query) == {"code": ["abc"], "state": ["xyz"]}

    def test_percent_encodes_reserved_characters(self):
        url = build_encoded_url("https://app.test/cb", {"next": "/a b&c=d"})
        assert " " not in url
        assert parse_qs(urlsplit(url).query) == {"next": ["/a b&c=d"]}

    def test_omitted_params_produce_a_bare_question_mark(self):
        # Documents current behaviour - the logout view calls it this way.
        assert build_encoded_url("https://app.test/logout") == "https://app.test/logout?"

    def test_none_values_are_encoded_as_the_string_none(self):
        # Worth pinning: an absent state reaches the client as "None", it is not
        # dropped from the query string.
        url = build_encoded_url("https://app.test/cb", {"state": None})
        assert parse_qs(urlsplit(url).query) == {"state": ["None"]}


class TestRetrieveOpenIdScope:
    def test_keeps_only_recognised_openid_scopes(self):
        assert retrieve_open_id_scope("openid email read:things") == "openid email"

    def test_preserves_requested_order(self):
        assert retrieve_open_id_scope("email openid profile") == "email openid profile"

    def test_returns_empty_string_when_nothing_matches(self):
        assert retrieve_open_id_scope("read:things write:things") == ""

    def test_accepts_every_documented_openid_scope(self):
        scope = " ".join(VALID_OPEN_ID_SCOPE)
        assert retrieve_open_id_scope(scope) == scope

    def test_raises_on_none_rather_than_returning_empty(self):
        # Documents current behaviour: callers pass a string from the request.
        with pytest.raises(AttributeError):
            retrieve_open_id_scope(None)


class TestGetCurrentTimestamp:
    def test_is_timezone_aware_utc(self):
        # Naive datetimes would break comparisons against the timezone-aware
        # expiry columns on sessions and refresh tokens.
        now = get_current_timestamp()
        assert now.tzinfo is not None
        assert now.utcoffset() == timezone.utc.utcoffset(None)

    def test_advances(self):
        first = get_current_timestamp()
        second = get_current_timestamp()
        assert second >= first
