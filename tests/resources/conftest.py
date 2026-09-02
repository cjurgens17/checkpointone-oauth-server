"""Fixtures for the /oauth/token resource tests.

``resources.token`` imports its collaborators by name, so every stub below is
installed on that module rather than on the repo package it came from.
"""

import pytest

import resources.token as token_resource
import services.tokens.access_token as access_token_module
from tests.factories import (
    DEFAULT_AUDIENCE,
    DEFAULT_CLIENT_ID,
    make_application,
    make_user,
)


@pytest.fixture
def registered_client(monkeypatch):
    """A public client registered under the default test client_id."""
    application = make_application()
    monkeypatch.setattr(
        token_resource,
        "get_application_from_client_id",
        lambda client_id: application if client_id == application.client_id else None,
    )
    return application


@pytest.fixture
def token_subject(monkeypatch):
    """Resolve the access token's subject without touching the user table."""
    user = make_user()
    monkeypatch.setattr(access_token_module, "get_user_from_sub", lambda sub: user)
    return user


@pytest.fixture
def no_session(monkeypatch):
    """Default to no browser session, which is the common API-client case."""
    monkeypatch.setattr(token_resource, "is_valid_session", lambda: False)


@pytest.fixture
def captured_refresh_tokens(monkeypatch):
    """Record refresh token rows instead of writing them."""
    created = []

    def _create(**kwargs):
        from tests.factories import make_refresh_token_record

        record = make_refresh_token_record(
            **{
                key: value
                for key, value in kwargs.items()
                if key
                in {
                    "sub",
                    "token_hash",
                    "scope",
                    "audience",
                    "client_id",
                    "iat",
                    "exp",
                    "absolute_exp",
                    "family_id",
                    "parent_id",
                }
            }
        )
        created.append(record)
        return record

    monkeypatch.setattr(token_resource, "create_refresh_token", _create)
    return created


def post_token(client, **body):
    """POST to the token endpoint with a JSON body."""
    payload = {
        "client_id": DEFAULT_CLIENT_ID,
        "audience": DEFAULT_AUDIENCE,
    }
    payload.update(body)
    return client.post(
        "/oauth/token",
        json={key: value for key, value in payload.items() if value is not None},
    )
