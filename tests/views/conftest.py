"""Fixtures for the view tests.

Views import their collaborators by name, so stubs are installed on the view
module itself. ``services.session`` is patched separately where relevant because
``is_valid_session`` resolves ``get_session_from_session_id`` through its own
module-level binding rather than the view's.
"""

import pytest

import services.session as session_service
import views.authorize as authorize_view
from tests.factories import make_application, make_tenant, make_user


@pytest.fixture
def registered_application(monkeypatch):
    """A registered client whose sole redirect URI is the factory default."""
    application = make_application()
    monkeypatch.setattr(
        authorize_view,
        "get_application_from_client_id",
        lambda client_id: application if client_id == application.client_id else None,
    )
    monkeypatch.setattr(
        authorize_view,
        "allowed_redirect_uri",
        lambda uri, client_id: uri in application.redirect_uris,
    )
    monkeypatch.setattr(
        authorize_view, "get_tenant_from_application", lambda client_id: make_tenant()
    )
    return application


@pytest.fixture
def issued_codes(monkeypatch):
    """Capture authorization codes instead of caching them."""
    issued = []

    def _create(payload):
        issued.append(payload)
        return f"auth-code-{len(issued)}"

    monkeypatch.setattr(authorize_view, "create_auth_code", _create)
    return issued


@pytest.fixture
def issued_sessions(monkeypatch):
    """Capture session cookies instead of persisting sessions."""
    issued = []

    def _generate(user_id, client_id, response_type, scope, connection, audience=None, ttl=None):
        issued.append(
            {
                "user_id": user_id,
                "client_id": client_id,
                "response_type": response_type,
                "scope": scope,
                "connection": connection,
                "audience": audience,
            }
        )
        return authorize_view.SESSION_COOKIE_NAME, f"session-{len(issued)}", {"path": "/"}

    monkeypatch.setattr(authorize_view, "generate_server_session_cookie", _generate)
    return issued


@pytest.fixture
def no_active_session(monkeypatch):
    monkeypatch.setattr(authorize_view, "is_valid_session", lambda: False)
    monkeypatch.setattr(session_service, "get_session_from_session_id", lambda sid: None)


@pytest.fixture
def active_session(monkeypatch):
    """Install a live session for the default user and return it."""
    from tests.factories import make_session

    session = make_session()
    user = make_user(user_id=session.user_id, sub=session.user_id)

    monkeypatch.setattr(authorize_view, "is_valid_session", lambda: True)
    monkeypatch.setattr(
        authorize_view, "get_session_from_session_id", lambda sid: session
    )
    monkeypatch.setattr(
        session_service, "get_session_from_session_id", lambda sid: session
    )
    monkeypatch.setattr(
        authorize_view,
        "get_user_from_user_id",
        lambda user_id: user if user_id == session.user_id else None,
    )
    return {"session": session, "user": user}


@pytest.fixture
def authorize_env(registered_application, issued_codes, issued_sessions, no_active_session):
    """The common bundle: a registered client, captured output, no session."""
    return {
        "application": registered_application,
        "codes": issued_codes,
        "sessions": issued_sessions,
    }
