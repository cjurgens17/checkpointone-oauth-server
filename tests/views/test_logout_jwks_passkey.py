"""Tests for the logout, discovery/JWKS, and passkey-continue views."""

from urllib.parse import urlsplit

import jwt
import pytest

import views.logout as logout_view
import views.passkey as passkey_view
from services.tokens.id_token import generate_id_token
from tests.factories import (
    DEFAULT_CLIENT_ID,
    DEFAULT_LOGOUT_URI,
    DEFAULT_REDIRECT_URI,
    make_session,
    make_user,
)


@pytest.fixture
def logout_env(monkeypatch):
    ended = []
    monkeypatch.setattr(
        logout_view,
        "allowed_logout_uri",
        lambda uri, client_id: uri == DEFAULT_LOGOUT_URI,
    )
    monkeypatch.setattr(
        logout_view,
        "end_session",
        lambda response, session_id: ended.append(session_id) or response,
    )
    return ended


def _id_token(**overrides):
    metadata = {"client_id": DEFAULT_CLIENT_ID, "sub": "cp1|abc", "scope": "openid"}
    metadata.update(overrides)
    return generate_id_token(metadata)


class TestLogout:
    def test_redirects_to_the_registered_logout_uri(self, client, logout_env):
        response = client.get(
            "/logout",
            query_string={
                "client_id": DEFAULT_CLIENT_ID,
                "post_logout_redirect_uri": DEFAULT_LOGOUT_URI,
                "id_token_hint": _id_token(),
            },
        )
        assert response.status_code == 302
        assert response.headers["Location"].startswith(DEFAULT_LOGOUT_URI)

    def test_ends_the_server_session(self, client, logout_env):
        client.set_cookie("cp1_auth", "the-session")
        client.get(
            "/logout",
            query_string={
                "client_id": DEFAULT_CLIENT_ID,
                "post_logout_redirect_uri": DEFAULT_LOGOUT_URI,
                "id_token_hint": _id_token(),
            },
        )
        assert logout_env == ["the-session"]

    def test_accepts_post_as_well_as_get(self, client, logout_env):
        # The OIDC RP-initiated logout spec requires both methods.
        response = client.post(
            "/logout",
            data={
                "client_id": DEFAULT_CLIENT_ID,
                "post_logout_redirect_uri": DEFAULT_LOGOUT_URI,
                "id_token_hint": _id_token(),
            },
        )
        assert response.status_code == 302

    def test_requires_an_id_token_hint(self, client, logout_env):
        response = client.get(
            "/logout",
            query_string={
                "client_id": DEFAULT_CLIENT_ID,
                "post_logout_redirect_uri": DEFAULT_LOGOUT_URI,
            },
        )
        assert response.status_code == 400
        assert logout_env == []

    def test_rejects_a_token_this_server_did_not_issue(self, client, logout_env):
        forged = jwt.encode({"sub": "cp1|abc"}, "attacker-secret", algorithm="HS256")
        response = client.get(
            "/logout",
            query_string={
                "client_id": DEFAULT_CLIENT_ID,
                "post_logout_redirect_uri": DEFAULT_LOGOUT_URI,
                "id_token_hint": forged,
            },
        )
        assert response.status_code == 400
        assert logout_env == []

    def test_accepts_an_expired_id_token(self, client, logout_env):
        from freezegun import freeze_time

        with freeze_time("2026-01-01 00:00:00"):
            token = _id_token()
        # Logging out after the token lapsed still has to work.
        response = client.get(
            "/logout",
            query_string={
                "client_id": DEFAULT_CLIENT_ID,
                "post_logout_redirect_uri": DEFAULT_LOGOUT_URI,
                "id_token_hint": token,
            },
        )
        assert response.status_code == 302

    def test_rejects_an_unregistered_logout_uri(self, client, logout_env):
        # Open-redirect defence on the logout leg.
        response = client.get(
            "/logout",
            query_string={
                "client_id": DEFAULT_CLIENT_ID,
                "post_logout_redirect_uri": "https://attacker.test/steal",
                "id_token_hint": _id_token(),
            },
        )
        assert response.status_code == 400
        assert logout_env == []

    def test_rejects_a_malformed_logout_uri(self, client, logout_env):
        response = client.get(
            "/logout",
            query_string={
                "client_id": DEFAULT_CLIENT_ID,
                "post_logout_redirect_uri": "not-a-uri",
                "id_token_hint": _id_token(),
            },
        )
        assert response.status_code == 400

    def test_requires_a_client_id_alongside_the_redirect(self, client, logout_env):
        response = client.get(
            "/logout",
            query_string={
                "post_logout_redirect_uri": DEFAULT_LOGOUT_URI,
                "id_token_hint": _id_token(),
            },
        )
        assert response.status_code == 400

    def test_without_a_redirect_uri_it_reports_rather_than_redirects(
        self, client, logout_env
    ):
        response = client.get(
            "/logout",
            query_string={
                "client_id": DEFAULT_CLIENT_ID,
                "id_token_hint": _id_token(),
            },
        )
        assert response.status_code == 400
        # The session is not ended on this path, which is worth knowing: a user
        # calling /logout without a redirect stays signed in.
        assert logout_env == []


class TestDiscoveryAndJwks:
    def test_jwks_publishes_the_signing_key(self, client, signing_key):
        response = client.get("/.well-known/jwks.json")
        assert response.status_code == 200
        keys = response.get_json()["keys"]
        assert len(keys) == 1
        assert keys[0]["kid"] == signing_key["kid"]

    def test_the_published_key_is_public_only(self, client):
        # A leaked private exponent would be catastrophic, so assert the RSA
        # private fields never appear.
        key = client.get("/.well-known/jwks.json").get_json()["keys"][0]
        for private_field in ("d", "p", "q", "dp", "dq", "qi"):
            assert private_field not in key

    def test_the_published_key_is_usable_for_verification(self, client, decode_token):
        key = client.get("/.well-known/jwks.json").get_json()["keys"][0]
        token = generate_id_token(
            {"client_id": DEFAULT_CLIENT_ID, "sub": "cp1|abc", "scope": "openid"}
        )
        public_key = jwt.PyJWK.from_dict(key).key
        claims = jwt.decode(
            token, public_key, algorithms=["RS256"], options={"verify_aud": False}
        )
        assert claims["sub"] == "cp1|abc"

    def test_key_is_advertised_for_rs256_signing(self, client):
        key = client.get("/.well-known/jwks.json").get_json()["keys"][0]
        assert key["use"] == "sig"
        assert key["alg"] == "RS256"
        assert key["kty"] == "RSA"

    @pytest.mark.parametrize(
        "path",
        ["/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"],
    )
    def test_discovery_documents_are_served(self, client, path):
        response = client.get(path)
        assert response.status_code == 200
        assert response.get_json()["issuer"]

    @pytest.mark.parametrize(
        "path",
        ["/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"],
    )
    def test_discovery_advertises_the_endpoints(self, client, path):
        metadata = client.get(path).get_json()
        assert metadata["authorization_endpoint"].endswith("/authorize")
        assert metadata["token_endpoint"].endswith("/oauth/token")
        assert metadata["jwks_uri"].endswith("/.well-known/jwks.json")
        assert metadata["end_session_endpoint"].endswith("/logout")

    def test_discovery_advertises_the_implemented_grants(self, client):
        metadata = client.get("/.well-known/openid-configuration").get_json()
        assert set(metadata["grant_types_supported"]) == {
            "authorization_code",
            "client_credentials",
            "refresh_token",
        }

    def test_discovery_requires_pkce_with_s256(self, client):
        metadata = client.get("/.well-known/openid-configuration").get_json()
        assert metadata["code_challenge_methods_supported"] == ["S256"]

    def test_both_discovery_documents_agree(self, client):
        oidc = client.get("/.well-known/openid-configuration").get_json()
        oauth = client.get("/.well-known/oauth-authorization-server").get_json()
        assert oidc == oauth


class TestPasskeyContinue:
    @pytest.fixture
    def passkey_env(self, monkeypatch):
        issued = []
        session = make_session()
        user = make_user(user_id=session.user_id, sub=session.user_id)
        monkeypatch.setattr(
            passkey_view, "get_session_from_session_id", lambda sid: session
        )
        monkeypatch.setattr(passkey_view, "get_user_from_user_id", lambda uid: user)
        monkeypatch.setattr(
            passkey_view,
            "_issue_auth_code",
            lambda params, u, conn: issued.append((params, u, conn))
            or __import__("flask").redirect(DEFAULT_REDIRECT_URI),
        )
        return {"issued": issued, "session": session, "user": user}

    def _form(self, **overrides):
        values = {
            "response_type": "code",
            "client_id": DEFAULT_CLIENT_ID,
            "redirect_uri": DEFAULT_REDIRECT_URI,
            "scope": "openid email",
            "state": "opaque-state",
            "code_challenge": "challenge",
            "code_challenge_method": "S256",
            "audience": "https://api.test/resource",
            "connection": "Username-Password-Authentication",
        }
        values.update(overrides)
        return values

    def test_continues_the_flow_by_issuing_a_code(self, client, passkey_env):
        client.set_cookie("cp1_auth", "the-session")
        response = client.post("/authorize/passkey/continue", data=self._form())
        assert response.status_code == 302
        assert len(passkey_env["issued"]) == 1

    def test_forwards_the_original_oauth_parameters(self, client, passkey_env):
        client.set_cookie("cp1_auth", "the-session")
        client.post("/authorize/passkey/continue", data=self._form(state="carried"))
        params = passkey_env["issued"][0][0]
        assert params["state"] == "carried"
        assert params["code_challenge"] == "challenge"

    def test_without_a_session_it_restarts_authorization(
        self, client, passkey_env, monkeypatch
    ):
        monkeypatch.setattr(
            passkey_view, "get_session_from_session_id", lambda sid: None
        )
        response = client.post("/authorize/passkey/continue", data=self._form())
        assert response.status_code == 302
        assert urlsplit(response.headers["Location"]).path == "/authorize"
        assert passkey_env["issued"] == []

    def test_an_expired_session_restarts_authorization(
        self, client, passkey_env, monkeypatch
    ):
        from datetime import datetime, timedelta, timezone

        expired = make_session(
            expires_at=datetime.now(timezone.utc) - timedelta(seconds=1)
        )
        monkeypatch.setattr(
            passkey_view, "get_session_from_session_id", lambda sid: expired
        )
        response = client.post("/authorize/passkey/continue", data=self._form())
        assert urlsplit(response.headers["Location"]).path == "/authorize"
        assert passkey_env["issued"] == []

    def test_a_session_whose_user_vanished_restarts_authorization(
        self, client, passkey_env, monkeypatch
    ):
        monkeypatch.setattr(passkey_view, "get_user_from_user_id", lambda uid: None)
        response = client.post("/authorize/passkey/continue", data=self._form())
        assert urlsplit(response.headers["Location"]).path == "/authorize"
        assert passkey_env["issued"] == []

    def test_only_accepts_post(self, client, passkey_env):
        assert client.get("/authorize/passkey/continue").status_code == 405


class TestIndex:
    def test_the_landing_page_renders(self, client):
        response = client.get("/")
        assert response.status_code == 200
