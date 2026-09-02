"""Tests for the refresh_token grant at POST /oauth/token.

Covers rotation, the reuse-detection path that revokes a whole token family, and
the confidential-client authentication rules.
"""

from datetime import datetime, timedelta, timezone

import pytest

import resources.token as token_resource
from tests.factories import (
    DEFAULT_AUDIENCE,
    DEFAULT_CLIENT_ID,
    DEFAULT_CLIENT_SECRET,
    DEFAULT_CONFIDENTIAL_CLIENT_ID,
    make_application,
    make_confidential_application,
    make_refresh_token_record,
)
from tests.resources.conftest import post_token
from utility.constants import RevokeReason


@pytest.fixture
def refresh_flow(monkeypatch, registered_client, token_subject, captured_refresh_tokens):
    """Wire up a stored refresh token and record every mutation made to it."""
    state = {
        "record": make_refresh_token_record(),
        "used": [],
        "revoked": [],
        "revoked_families": [],
        "created": captured_refresh_tokens,
    }

    monkeypatch.setattr(
        token_resource,
        "get_refresh_token_from_token_hash",
        lambda token_hash: state["record"],
    )
    monkeypatch.setattr(
        token_resource,
        "update_refresh_token_used_at",
        lambda token_hash, used_at: state["used"].append(token_hash),
    )
    monkeypatch.setattr(
        token_resource,
        "revoke_refresh_token",
        lambda token_hash, reason, at: state["revoked"].append((token_hash, reason)),
    )
    monkeypatch.setattr(
        token_resource,
        "revoke_refresh_token_family",
        lambda family_id, reason, at: state["revoked_families"].append(
            (family_id, reason)
        ),
    )
    return state


def _post(client, **overrides):
    body = {"grant_type": "refresh_token", "refresh_token": "the-refresh-token"}
    body.update(overrides)
    return post_token(client, **body)


class TestRefreshTokenRotation:
    def test_issues_a_new_access_token(self, client, refresh_flow, decode_token):
        response = _post(client)
        assert response.status_code == 200
        body = response.get_json()
        assert body["token_type"] == "Bearer"
        assert decode_token(body["access_token"])["aud"] == DEFAULT_AUDIENCE

    def test_issues_a_replacement_refresh_token(self, client, refresh_flow):
        response = _post(client)
        assert response.get_json()["refresh_token"]
        assert len(refresh_flow["created"]) == 1

    def test_the_presented_token_is_marked_used_and_revoked(self, client, refresh_flow):
        # Rotation must retire the old token, otherwise it stays replayable.
        _post(client)
        assert len(refresh_flow["used"]) == 1
        assert refresh_flow["revoked"][0][1] == RevokeReason.ROTATE

    def test_the_replacement_stays_in_the_same_family(self, client, refresh_flow):
        _post(client)
        replacement = refresh_flow["created"][0]
        assert replacement.family_id == refresh_flow["record"].family_id

    def test_the_replacement_records_its_parent(self, client, refresh_flow):
        # The parent link is what makes a reuse chain reconstructable.
        _post(client)
        assert refresh_flow["created"][0].parent_id == refresh_flow["record"].id

    def test_scope_and_audience_carry_over(self, client, refresh_flow):
        _post(client)
        replacement = refresh_flow["created"][0]
        assert replacement.scope == refresh_flow["record"].scope
        assert replacement.audience == refresh_flow["record"].audience

    def test_the_absolute_expiry_ceiling_is_preserved(self, client, refresh_flow):
        # Rotation must not extend the absolute lifetime, or a token family could
        # be kept alive forever by refreshing.
        _post(client)
        assert (
            refresh_flow["created"][0].absolute_exp
            == refresh_flow["record"].absolute_exp
        )

    def test_returns_the_granted_scope(self, client, refresh_flow):
        assert _post(client).get_json()["scope"] == refresh_flow["record"].scope

    def test_includes_an_id_token_for_openid_scope(self, client, refresh_flow, decode_token):
        response = _post(client)
        assert decode_token(response.get_json()["id_token"])["aud"] == DEFAULT_CLIENT_ID

    def test_omits_the_id_token_without_openid_scope(self, client, refresh_flow):
        refresh_flow["record"] = make_refresh_token_record(scope="read:things")
        assert "id_token" not in _post(client).get_json()

    def test_marks_the_response_as_not_cacheable(self, client, refresh_flow):
        assert _post(client).headers["Cache-Control"] == "no-store"


class TestRefreshTokenReuseDetection:
    def test_reusing_a_spent_token_revokes_the_whole_family(self, client, refresh_flow):
        # The canonical stolen-token signal: a token already rotated is presented
        # again, so every descendant is burned.
        refresh_flow["record"] = make_refresh_token_record(
            used_at=datetime.now(timezone.utc)
        )
        _post(client)
        assert refresh_flow["revoked_families"]
        assert refresh_flow["revoked_families"][0][1] == RevokeReason.REUSE

    def test_a_revoked_token_also_triggers_family_revocation(self, client, refresh_flow):
        refresh_flow["record"] = make_refresh_token_record(
            revoked_at=datetime.now(timezone.utc), revoke_reason=RevokeReason.LOGOUT
        )
        _post(client)
        assert refresh_flow["revoked_families"][0][1] == RevokeReason.REUSE

    def test_reuse_revokes_the_family_of_the_presented_token(self, client, refresh_flow):
        record = make_refresh_token_record(used_at=datetime.now(timezone.utc))
        refresh_flow["record"] = record
        _post(client)
        assert refresh_flow["revoked_families"][0][0] == record.family_id

    def test_reuse_issues_no_new_tokens(self, client, refresh_flow):
        refresh_flow["record"] = make_refresh_token_record(
            used_at=datetime.now(timezone.utc)
        )
        response = _post(client)
        assert refresh_flow["created"] == []
        assert response.get_json() is None or "access_token" not in (
            response.get_json() or {}
        )

    def test_reuse_is_reported_as_invalid_grant(self, client, refresh_flow):
        refresh_flow["record"] = make_refresh_token_record(
            used_at=datetime.now(timezone.utc)
        )
        response = _post(client)
        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid_grant"

    def test_reuse_does_not_leak_into_the_authorization_code_handler(
        self, client, refresh_flow
    ):
        # Regression guard: the reuse branch used to fall out of the refresh
        # grant entirely and answer "missing required code parameter".
        refresh_flow["record"] = make_refresh_token_record(
            used_at=datetime.now(timezone.utc)
        )
        description = _post(client).get_json()["error_description"]
        assert "code parameter" not in description

    def test_reuse_does_not_disclose_that_detection_fired(self, client, refresh_flow):
        # The wording matches the expired case so a caller holding a stolen token
        # cannot tell revocation apart from ordinary expiry.
        refresh_flow["record"] = make_refresh_token_record(
            used_at=datetime.now(timezone.utc)
        )
        reused = _post(client).get_json()

        issued = datetime.now(timezone.utc) - timedelta(days=30)
        refresh_flow["record"] = make_refresh_token_record(
            iat=issued,
            exp=issued + timedelta(days=7),
            absolute_exp=issued + timedelta(days=14),
        )
        expired = _post(client).get_json()

        assert reused == expired


class TestRefreshTokenRejections:
    def test_missing_refresh_token(self, client, refresh_flow):
        response = _post(client, refresh_token=None)
        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid_request"

    def test_unknown_refresh_token(self, client, refresh_flow, monkeypatch):
        monkeypatch.setattr(
            token_resource, "get_refresh_token_from_token_hash", lambda h: None
        )
        response = _post(client)
        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid_request"

    def test_expired_refresh_token_requires_reauthorization(self, client, refresh_flow):
        issued = datetime.now(timezone.utc) - timedelta(days=30)
        refresh_flow["record"] = make_refresh_token_record(
            iat=issued,
            exp=issued + timedelta(days=7),
            absolute_exp=issued + timedelta(days=14),
        )
        response = _post(client)
        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid_grant"

    def test_unregistered_client_is_rejected_with_400(
        self, client, refresh_flow, monkeypatch
    ):
        # Regression guard: this branch used to return a bare dict with no status
        # tuple, which Flask-RESTful served as 200 OK alongside an error body.
        monkeypatch.setattr(
            token_resource, "get_application_from_client_id", lambda cid: None
        )
        response = _post(client)
        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid_request"

    def test_no_rejection_path_returns_a_2xx(self, client, refresh_flow, monkeypatch):
        monkeypatch.setattr(
            token_resource, "get_application_from_client_id", lambda cid: None
        )
        unregistered = _post(client)

        monkeypatch.setattr(
            token_resource, "get_application_from_client_id", lambda cid: make_application()
        )
        monkeypatch.setattr(
            token_resource, "get_refresh_token_from_token_hash", lambda h: None
        )
        unknown_token = _post(client)
        missing_token = _post(client, refresh_token=None)

        for response in (unregistered, unknown_token, missing_token):
            assert response.status_code == 400
            assert "access_token" not in response.get_json()

    def test_no_tokens_are_issued_when_the_grant_is_refused(self, client, refresh_flow):
        _post(client, refresh_token=None)
        assert refresh_flow["created"] == []


class TestConfidentialClientRefresh:
    @pytest.fixture
    def confidential_refresh(self, refresh_flow, monkeypatch):
        application = make_confidential_application()
        monkeypatch.setattr(
            token_resource, "get_application_from_client_id", lambda cid: application
        )
        refresh_flow["record"] = make_refresh_token_record(
            client_id=DEFAULT_CONFIDENTIAL_CLIENT_ID
        )
        return refresh_flow

    def test_requires_a_client_secret(self, client, confidential_refresh):
        response = _post(client, client_id=DEFAULT_CONFIDENTIAL_CLIENT_ID)
        assert response.status_code == 400
        assert "client_secret" in response.get_json()["error_description"]

    def test_rejects_a_wrong_client_secret(self, client, confidential_refresh):
        response = _post(
            client,
            client_id=DEFAULT_CONFIDENTIAL_CLIENT_ID,
            client_secret="wrong-secret",
        )
        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid_request"

    def test_succeeds_with_the_correct_secret(self, client, confidential_refresh):
        response = _post(
            client,
            client_id=DEFAULT_CONFIDENTIAL_CLIENT_ID,
            client_secret=DEFAULT_CLIENT_SECRET,
        )
        assert response.status_code == 200
        assert response.get_json()["access_token"]

    def test_public_clients_need_no_secret(self, client, refresh_flow):
        # The default registered_client fixture is a public client.
        assert _post(client).status_code == 200
