"""Tests for the Redis-backed cache and the passkey challenge helpers.

These run against fakeredis (installed by the autouse ``fake_redis`` fixture),
so they exercise the real serialisation and TTL behaviour without a daemon.
"""

import pytest
from freezegun import freeze_time

from utility.redis.cache import DEFAULT_TTL_SECONDS, cache_delete, cache_get, cache_set


class TestCacheRoundTrip:
    def test_stores_and_returns_a_dictionary(self):
        payload = {"sub": "cp1|abc", "scope": "openid email"}
        cache_set("auth-code", payload)
        assert cache_get("auth-code") == payload

    @pytest.mark.parametrize(
        "value",
        [
            "a string",
            1234,
            True,
            None,
            ["a", "list"],
            {"nested": {"structures": ["work"]}},
        ],
    )
    def test_survives_a_json_round_trip(self, value):
        cache_set("key", value)
        assert cache_get("key") == value

    def test_missing_key_returns_none(self):
        assert cache_get("never-written") is None

    def test_delete_removes_the_entry(self):
        cache_set("key", {"a": 1})
        cache_delete("key")
        assert cache_get("key") is None

    def test_delete_is_a_no_op_for_a_missing_key(self):
        cache_delete("never-written")

    def test_overwriting_replaces_the_previous_value(self):
        cache_set("key", {"version": 1})
        cache_set("key", {"version": 2})
        assert cache_get("key") == {"version": 2}


class TestCacheExpiry:
    def test_applies_the_default_ttl(self, fake_redis):
        cache_set("key", "value")
        assert 0 < fake_redis.ttl("key") <= DEFAULT_TTL_SECONDS

    def test_applies_an_explicit_ttl(self, fake_redis):
        cache_set("key", "value", ttl=42)
        assert 0 < fake_redis.ttl("key") <= 42

    def test_entry_disappears_once_the_ttl_elapses(self):
        # fakeredis honours the frozen clock, so expiry is actually exercised
        # rather than inferred from the TTL value alone.
        with freeze_time("2026-01-01 00:00:00") as frozen:
            cache_set("short-lived", "value", ttl=10)
            assert cache_get("short-lived") == "value"
            frozen.tick(11)
            assert cache_get("short-lived") is None


class TestPasskeyChallengeHelpers:
    def test_key_is_namespaced(self):
        from utility.redis.passkey import PASSKEY_CHALLENGE, generate_challenge_key

        assert generate_challenge_key("abc").startswith(PASSKEY_CHALLENGE)
        assert generate_challenge_key("abc") == f"{PASSKEY_CHALLENGE}abc"

    def test_stored_challenge_can_be_read_back_and_deleted(self):
        from utility.redis.cache import cache_set as raw_set
        from utility.redis.passkey import (
            delete_passkey_challenge,
            generate_challenge_key,
            get_passkey_challenge,
        )

        raw_set(generate_challenge_key("chal"), "chal")
        assert get_passkey_challenge("chal") == "chal"

        delete_passkey_challenge("chal")
        assert get_passkey_challenge("chal") is None

    def test_set_passkey_challenge_is_currently_broken(self):
        """Pins a real defect rather than asserting intended behaviour.

        ``webauthn.helpers.generate_challenge()`` returns ``bytes``, and
        ``cache_set`` serialises with ``json.dumps``, which cannot encode bytes.
        So ``set_passkey_challenge()`` raises every time it is called - it has no
        working path at all. It also returns None, meaning a caller could not
        learn the challenge or its key even once the encoding is fixed.

        When that is repaired (store ``bytes_to_base64url(challenge)`` and return
        the challenge), this test should start failing and be rewritten to assert
        the round trip.
        """
        from utility.redis.passkey import set_passkey_challenge

        with pytest.raises(TypeError, match="not JSON serializable"):
            set_passkey_challenge()

    def test_missing_challenge_returns_none(self):
        from utility.redis.passkey import get_passkey_challenge

        assert get_passkey_challenge("never-issued") is None
