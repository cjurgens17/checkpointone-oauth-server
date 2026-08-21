import os
import secrets
import time

import jwt

from repo.user import get_user_from_sub
from utility.jwt_keys import JWT_KEY_ID, JWT_PRIVATE_KEY

# TODO - ENHANCEMENT -> Extract Clients Requested Access Token TTL instead of having a single standard

ISSUER = os.getenv("ISSUER", "http://localhost:5000")
ACCESS_TOKEN_TTL_SECONDS = 3600


def create_access_token(client_metadata):
    user = get_user_from_sub(client_metadata.get("sub"))
    issued_at = int(time.time())

    payload = {
        "iss": ISSUER,
        "aud": client_metadata.get("audience"),
        "sub": user.sub,
        "iat": issued_at,
        "exp": issued_at + ACCESS_TOKEN_TTL_SECONDS,
        "jti": secrets.token_urlsafe(16),
        "scope": client_metadata.get("scope"),
    }

    return jwt.encode(
        payload, JWT_PRIVATE_KEY, algorithm="RS256", headers={"kid": JWT_KEY_ID}
    )


def create_confidential_client_access_token(confidential_client_metadata):
    issued_at = int(time.time())

    payload = {
        "iss": ISSUER,
        "aud": confidential_client_metadata.get("audience"),
        "sub": confidential_client_metadata.get("client_id"),
        "iat": issued_at,
        "exp": issued_at + ACCESS_TOKEN_TTL_SECONDS,
        "jti": secrets.token_urlsafe(16),
        "scope": confidential_client_metadata.get("permissions"),
    }

    return jwt.encode(
        payload, JWT_PRIVATE_KEY, algorithm="RS256", headers={"kid": JWT_KEY_ID}
    )
