"""Builders for the domain objects the suite needs.

These construct real SQLAlchemy model instances rather than stand-in stubs. A
transient (unattached) instance needs no database, unset columns read back as
None exactly as they would after a real query, and the objects stay correct for
free when a model gains a column. That fidelity matters here because production
code inspects these objects with ``getattr(user, field, None)``, which a loose
stub would answer differently.
"""

import uuid
from datetime import datetime, timedelta, timezone

from werkzeug.security import generate_password_hash

from models.application import Application
from models.refresh_token import RefreshToken
from models.session import Session
from models.tenant import Tenant
from models.user import User
from utility.constants import ClientType, IdentityProvider

DEFAULT_PASSWORD = "Password123!"
DEFAULT_CLIENT_ID = "client_public_test"
DEFAULT_CONFIDENTIAL_CLIENT_ID = "client_confidential_test"
DEFAULT_CLIENT_SECRET = "confidential-client-secret"
DEFAULT_REDIRECT_URI = "https://app.test/callback"
DEFAULT_LOGOUT_URI = "https://app.test/logout"
DEFAULT_AUDIENCE = "https://api.test/resource"


def make_tenant(**overrides):
    values = {
        "id": uuid.uuid4(),
        "slug": "CheckPointOne",
        "logo_url": "/static/assets/checkpointone_logo.svg",
    }
    values.update(overrides)
    return Tenant(**values)


def make_user(**overrides):
    """A native (username/password) user with a usable password hash."""
    password = overrides.pop("password", DEFAULT_PASSWORD)
    subject = overrides.pop("sub", f"{IdentityProvider.CHECK_POINT_ONE}|testsubject01")
    values = {
        "id": uuid.uuid4(),
        "username": "test@checkpointone.com",
        "email": "test@checkpointone.com",
        "email_verified": True,
        "sub": subject,
        "user_id": subject,
        "connection": IdentityProvider.NATIVE,
        "password": generate_password_hash(password),
        "tenant_id": uuid.uuid4(),
    }
    values.update(overrides)
    return User(**values)


def make_application(**overrides):
    """A public client, which is what the authorization code flow uses."""
    values = {
        "id": uuid.uuid4(),
        "client_id": DEFAULT_CLIENT_ID,
        "client_secret": "public-clients-do-not-use-this",
        "name": "CheckPointOne Test App",
        "redirect_uris": [DEFAULT_REDIRECT_URI],
        "logout_uris": [DEFAULT_LOGOUT_URI],
        "permissions": ["offline_access"],
        "tenant_id": uuid.uuid4(),
        "client_type": ClientType.USER_AGENT,
    }
    values.update(overrides)
    return Application(**values)


def make_confidential_application(**overrides):
    """A confidential client, eligible for the client_credentials grant."""
    values = {
        "client_id": DEFAULT_CONFIDENTIAL_CLIENT_ID,
        "client_secret": DEFAULT_CLIENT_SECRET,
        "name": "CheckPointOne Test Service",
        "redirect_uris": [],
        "logout_uris": [],
        "permissions": ["read:things", "write:things", "offline_access"],
        "client_type": ClientType.WEB_APPLICATION,
    }
    values.update(overrides)
    return make_application(**values)


def make_session(**overrides):
    """An authenticated browser session, valid for a day unless told otherwise."""
    values = {
        "id": uuid.uuid4(),
        "session_id": "test-session-identifier",
        "user_id": f"{IdentityProvider.CHECK_POINT_ONE}|testsubject01",
        "expires_at": datetime.now(timezone.utc) + timedelta(hours=1),
        "client_id": DEFAULT_CLIENT_ID,
        "response_type": "code",
        "scope": "openid email profile",
        "connection": IdentityProvider.NATIVE,
        "audience": DEFAULT_AUDIENCE,
    }
    values.update(overrides)
    return Session(**values)


def make_refresh_token_record(**overrides):
    """A refresh token row in its freshly issued, still-valid state."""
    issued_at = overrides.pop("iat", datetime.now(timezone.utc))
    values = {
        "id": uuid.uuid4(),
        "sub": f"{IdentityProvider.CHECK_POINT_ONE}|testsubject01",
        "token_hash": "hash-of-the-refresh-token",
        "used_at": None,
        "revoked_at": None,
        "revoke_reason": None,
        "parent_id": None,
        "scope": "openid email offline_access",
        "audience": DEFAULT_AUDIENCE,
        "client_id": DEFAULT_CLIENT_ID,
        "iat": issued_at,
        "exp": issued_at + timedelta(days=7),
        "absolute_exp": issued_at + timedelta(days=14),
        "family_id": uuid.uuid4(),
    }
    values.update(overrides)
    return RefreshToken(**values)


def authorization_code_metadata(**overrides):
    """The payload the authorize endpoint caches under an authorization code.

    ``code_challenge`` is the S256 hash of ``code_verifier`` below, so the pair
    satisfies ``valid_code_challenge`` without the test restating the hash.
    """
    from utility.helpers import hash_sha256

    verifier = overrides.pop("code_verifier", "test-code-verifier-value")
    values = {
        "response_type": "code",
        "client_id": DEFAULT_CLIENT_ID,
        "redirect_uri": DEFAULT_REDIRECT_URI,
        "scope": "openid email",
        "state": "opaque-state",
        "code_challenge": hash_sha256(verifier),
        "code_challenge_method": "S256",
        "audience": DEFAULT_AUDIENCE,
        "sub": f"{IdentityProvider.CHECK_POINT_ONE}|testsubject01",
        "provider_claims": {"email": "test@checkpointone.com", "email_verified": True},
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(),
    }
    values.update(overrides)
    return values


def authorize_query(**overrides):
    """A complete, valid set of /authorize query parameters."""
    values = {
        "response_type": "code",
        "client_id": DEFAULT_CLIENT_ID,
        "redirect_uri": DEFAULT_REDIRECT_URI,
        "scope": "openid email profile",
        "state": "opaque-state",
        "code_challenge": "Q1ZoTFNVVXhVMVpvVEVWU1UxWnVWVEZT",
        "code_challenge_method": "S256",
        "audience": DEFAULT_AUDIENCE,
        "connection": IdentityProvider.NATIVE,
    }
    values.update(overrides)
    return {key: value for key, value in values.items() if value is not None}
