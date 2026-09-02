"""Tests for services.session - cookie issuance and session validity."""

import importlib
from datetime import datetime, timedelta, timezone

import pytest
from flask import Flask

import services.session as session_service
from services.session import (
    SESSION_COOKIE_NAME,
    SESSION_TTL_SECONDS,
    end_session,
    generate_server_session_cookie,
    is_valid_session,
    remove_session,
)
from tests.factories import DEFAULT_AUDIENCE, DEFAULT_CLIENT_ID, make_session
from utility.constants import IdentityProvider


@pytest.fixture
def flask_app():
    return Flask(__name__)


class TestGenerateServerSessionCookie:
    def test_returns_the_cookie_name_and_the_persisted_session_id(self, monkeypatch):
        created = make_session(session_id="persisted-id")
        monkeypatch.setattr(session_service, "create_session", lambda *a, **k: created)

        name, value, options = generate_server_session_cookie(
            "cp1|abc", DEFAULT_CLIENT_ID, "code", "openid", IdentityProvider.NATIVE
        )
        assert name == SESSION_COOKIE_NAME
        assert value == "persisted-id"
        assert options["max_age"] == SESSION_TTL_SECONDS

    def test_cookie_is_http_only_and_lax(self, monkeypatch):
        # HttpOnly keeps the session out of reach of scripts; Lax still allows
        # the top-level redirect back from an identity provider.
        monkeypatch.setattr(
            session_service, "create_session", lambda *a, **k: make_session()
        )
        _, _, options = generate_server_session_cookie(
            "cp1|abc", DEFAULT_CLIENT_ID, "code", "openid", IdentityProvider.NATIVE
        )
        assert options["httponly"] is True
        assert options["samesite"] == "Lax"
        assert options["path"] == "/"

    def test_secure_flag_is_off_only_in_the_local_environment(self, monkeypatch):
        monkeypatch.setattr(
            session_service, "create_session", lambda *a, **k: make_session()
        )
        # conftest sets env=local, so the flag is relaxed for http development.
        _, _, options = generate_server_session_cookie(
            "cp1|abc", DEFAULT_CLIENT_ID, "code", "openid", IdentityProvider.NATIVE
        )
        assert options["secure"] is False

    def test_secure_flag_is_on_outside_the_local_environment(self, monkeypatch):
        # IS_LOCAL_ENV is captured at import, so the module is reloaded to prove
        # a deployed instance marks the cookie Secure.
        monkeypatch.setenv("env", "production")
        reloaded = importlib.reload(session_service)
        try:
            monkeypatch.setattr(
                reloaded, "create_session", lambda *a, **k: make_session()
            )
            _, _, options = reloaded.generate_server_session_cookie(
                "cp1|abc", DEFAULT_CLIENT_ID, "code", "openid", IdentityProvider.NATIVE
            )
            assert options["secure"] is True
        finally:
            monkeypatch.setenv("env", "local")
            importlib.reload(session_service)

    def test_forwards_every_field_to_the_repository(self, monkeypatch):
        recorded = {}

        def _capture(user_id, ttl, client_id, response_type, scope, connection, audience=None):
            recorded.update(
                user_id=user_id,
                ttl=ttl,
                client_id=client_id,
                response_type=response_type,
                scope=scope,
                connection=connection,
                audience=audience,
            )
            return make_session()

        monkeypatch.setattr(session_service, "create_session", _capture)
        generate_server_session_cookie(
            "cp1|abc",
            DEFAULT_CLIENT_ID,
            "code",
            "openid email",
            IdentityProvider.GOOGLE,
            audience=DEFAULT_AUDIENCE,
        )
        assert recorded == {
            "user_id": "cp1|abc",
            "ttl": SESSION_TTL_SECONDS,
            "client_id": DEFAULT_CLIENT_ID,
            "response_type": "code",
            "scope": "openid email",
            "connection": IdentityProvider.GOOGLE,
            "audience": DEFAULT_AUDIENCE,
        }

    def test_honours_a_custom_ttl(self, monkeypatch):
        monkeypatch.setattr(
            session_service, "create_session", lambda *a, **k: make_session()
        )
        _, _, options = generate_server_session_cookie(
            "cp1|abc",
            DEFAULT_CLIENT_ID,
            "code",
            "openid",
            IdentityProvider.NATIVE,
            ttl=60,
        )
        assert options["max_age"] == 60


class TestIsValidSession:
    def test_false_without_a_cookie(self, flask_app):
        with flask_app.test_request_context("/"):
            assert is_valid_session() is False

    def test_false_when_the_cookie_matches_no_session(self, flask_app, monkeypatch):
        monkeypatch.setattr(
            session_service, "get_session_from_session_id", lambda sid: None
        )
        with flask_app.test_request_context(
            "/", headers={"Cookie": f"{SESSION_COOKIE_NAME}=stale"}
        ):
            assert is_valid_session() is False

    def test_true_for_a_live_session(self, flask_app, monkeypatch):
        live = make_session(expires_at=datetime.now(timezone.utc) + timedelta(hours=1))
        monkeypatch.setattr(
            session_service, "get_session_from_session_id", lambda sid: live
        )
        with flask_app.test_request_context(
            "/", headers={"Cookie": f"{SESSION_COOKIE_NAME}=live"}
        ):
            assert is_valid_session() is True

    def test_false_for_an_expired_session(self, flask_app, monkeypatch):
        expired = make_session(
            expires_at=datetime.now(timezone.utc) - timedelta(seconds=1)
        )
        monkeypatch.setattr(
            session_service, "get_session_from_session_id", lambda sid: expired
        )
        with flask_app.test_request_context(
            "/", headers={"Cookie": f"{SESSION_COOKIE_NAME}=expired"}
        ):
            assert is_valid_session() is False

    def test_looks_the_session_up_by_the_cookie_value(self, flask_app, monkeypatch):
        seen = []

        def _capture(session_id):
            seen.append(session_id)
            return make_session()

        monkeypatch.setattr(session_service, "get_session_from_session_id", _capture)
        with flask_app.test_request_context(
            "/", headers={"Cookie": f"{SESSION_COOKIE_NAME}=the-value"}
        ):
            is_valid_session()
        assert seen == ["the-value"]


class TestEndSession:
    def test_deletes_the_stored_session(self, flask_app, monkeypatch):
        deleted = []
        monkeypatch.setattr(
            session_service, "delete_session", lambda sid: deleted.append(sid)
        )
        with flask_app.test_request_context("/"):
            from flask import make_response

            end_session(make_response(""), "session-to-kill")
        assert deleted == ["session-to-kill"]

    def test_clears_the_browser_cookie(self, flask_app, monkeypatch):
        monkeypatch.setattr(session_service, "delete_session", lambda sid: None)
        with flask_app.test_request_context("/"):
            from flask import make_response

            response = end_session(make_response(""), "session-to-kill")
        set_cookie = response.headers.get("Set-Cookie", "")
        assert SESSION_COOKIE_NAME in set_cookie
        # An immediate expiry is how Werkzeug signals deletion.
        assert "Expires=Thu, 01 Jan 1970" in set_cookie or "Max-Age=0" in set_cookie

    def test_still_clears_the_cookie_without_a_session_id(self, flask_app, monkeypatch):
        # A user holding a cookie for an already-deleted session must still end
        # up logged out locally.
        called = []
        monkeypatch.setattr(
            session_service, "delete_session", lambda sid: called.append(sid)
        )
        with flask_app.test_request_context("/"):
            from flask import make_response

            response = end_session(make_response(""), None)
        assert called == []
        assert SESSION_COOKIE_NAME in response.headers.get("Set-Cookie", "")


class TestRemoveSession:
    def test_delegates_to_the_repository(self, monkeypatch):
        deleted = []
        monkeypatch.setattr(
            session_service, "delete_session", lambda sid: deleted.append(sid)
        )
        remove_session("abc")
        assert deleted == ["abc"]
