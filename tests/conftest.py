"""Shared pytest configuration for the CheckPointOne authorization server.

Environment bootstrapping happens at module import time on purpose. Several
application modules read configuration while being imported rather than when
called - ``utility.jwt_keys`` parses the signing key into a cryptography object,
``services.connections.google`` constructs a ``PyJWKClient``, and every module
that issues a token captures ``ISSUER`` as a constant. All of that runs the
moment a test module imports the code under test, so the values below have to be
in ``os.environ`` first.

python-dotenv's ``load_dotenv()`` never overrides an already-set variable, which
means these test values also take precedence over a developer's real ``.env``.
Tests therefore sign with a throwaway key generated per session and never touch
production secrets, and they behave identically on a machine with no ``.env`` at
all.
"""

import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def _generate_test_signing_key() -> str:
    """Mint a throwaway RS256 key so no real signing material reaches the suite."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


TEST_ISSUER = "https://test-issuer.checkpointone.local"
TEST_GOOGLE_CLIENT_ID = "test-google-client-id.apps.googleusercontent.com"
TEST_GOOGLE_ISSUER = "https://accounts.google.com"

os.environ["JWT_PRIVATE_KEY"] = _generate_test_signing_key()
os.environ["ISSUER"] = TEST_ISSUER
# services.session reads this to decide whether the session cookie is Secure.
os.environ["env"] = "local"
# Pointed at a database that is never contacted - unit tests are guarded against
# real connections by the block_database_access fixture below.
os.environ["DATABASE_URL"] = "postgresql+psycopg://unused:unused@127.0.0.1:1/unused"
os.environ["REDIS_URL"] = "redis://127.0.0.1:1/0"

os.environ["GOOGLE_CLIENT_ID"] = TEST_GOOGLE_CLIENT_ID
os.environ["GOOGLE_CLIENT_SECRET"] = "test-google-client-secret"
os.environ["GOOGLE_REDIRECT_URI"] = "https://op.test/callback/google"
os.environ["GOOGLE_AUTHORIZATION_ENDPOINT"] = "https://accounts.google.com/o/oauth2/v2/auth"
os.environ["GOOGLE_TOKEN_ENDPOINT"] = "https://oauth2.googleapis.com/token"
os.environ["GOOGLE_JWKS_URL"] = "https://www.googleapis.com/oauth2/v3/certs"
os.environ["GOOGLE_ISSUER"] = TEST_GOOGLE_ISSUER

os.environ["GITHUB_CLIENT_ID"] = "test-github-client-id"
os.environ["GITHUB_CLIENT_SECRET"] = "test-github-client-secret"
os.environ["GITHUB_REDIRECT_URI"] = "https://op.test/callback/github"
os.environ["GITHUB_AUTHORIZATION_ENDPOINT"] = "https://github.com/login/oauth/authorize"
os.environ["GITHUB_TOKEN_ENDPOINT"] = "https://github.com/login/oauth/access_token"
os.environ["GITHUB_USERINFO"] = "https://api.github.com/user"

# Application imports are only safe below this line.
import importlib  # noqa: E402

import fakeredis  # noqa: E402
import pytest  # noqa: E402

# Every module that reaches the database binds SessionLocal at import time, so
# the guard below has to neutralise each binding individually.
_REPO_MODULES = (
    "repo.applications",
    "repo.passkey",
    "repo.refresh_token",
    "repo.session",
    "repo.tenants",
    "repo.user",
)


@pytest.fixture(autouse=True)
def block_database_access(request, monkeypatch):
    """Turn accidental database use into an immediate, readable failure.

    Without this a unit test that forgets to stub a repo call would sit waiting
    on a TCP connect and then fail with a psycopg connection error that says
    nothing about which dependency was missed. Tests marked ``integration`` opt
    out because reaching the database is precisely what they are for.
    """
    if request.node.get_closest_marker("integration"):
        return

    def _refuse(*args, **kwargs):
        raise AssertionError(
            "This test reached the database through SessionLocal. Stub the repo "
            "function the code under test calls, or mark the test @pytest.mark.integration."
        )

    for module_name in _REPO_MODULES:
        monkeypatch.setattr(
            importlib.import_module(module_name), "SessionLocal", _refuse
        )


@pytest.fixture(autouse=True)
def fake_redis(monkeypatch):
    """Swap the Redis client for an in-memory double.

    ``utility.redis.cache`` binds ``redis_client`` at import, so patching the
    client module would have no effect - the cache module's own reference is the
    one that has to move. ``decode_responses=True`` matches how the real client
    is constructed, which keeps ``json.loads`` in ``cache_get`` working.
    """
    client = fakeredis.FakeRedis(decode_responses=True)
    cache_module = importlib.import_module("utility.redis.cache")
    monkeypatch.setattr(cache_module, "redis_client", client)
    return client


@pytest.fixture
def app():
    """The real Flask application, so route wiring is covered rather than mocked."""
    from app import app as flask_app

    flask_app.config.update(TESTING=True)
    return flask_app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def signing_key():
    """The public/private material the suite signs and verifies test tokens with."""
    from utility.jwt_keys import JWT_KEY_ID, JWT_PRIVATE_KEY, JWT_PUBLIC_KEY

    return {
        "private": JWT_PRIVATE_KEY,
        "public": JWT_PUBLIC_KEY,
        "kid": JWT_KEY_ID,
    }


@pytest.fixture
def decode_token(signing_key):
    """Decode a token this server issued, without enforcing audience."""
    import jwt

    def _decode(token, **overrides):
        options = {"verify_aud": False}
        options.update(overrides.pop("options", {}))
        return jwt.decode(
            token,
            signing_key["public"],
            algorithms=["RS256"],
            options=options,
            **overrides,
        )

    return _decode


def patch_all(monkeypatch, module, **attributes):
    """Replace attributes on an already-imported module.

    Views and resources import their collaborators by name
    (``from repo.applications import get_application_from_client_id``), which
    rebinds them into the importing module. Patching the source module would
    leave those bindings untouched, so tests patch the call site instead.
    """
    for name, replacement in attributes.items():
        monkeypatch.setattr(module, name, replacement, raising=True)
