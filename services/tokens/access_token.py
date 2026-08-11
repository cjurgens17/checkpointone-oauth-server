import os
import secrets
import time

import jwt

from repo.user import get_user_from_sub

ISSUER = os.getenv("ISSUER", "http://localhost:5000")
JWT_PRIVATE_KEY = os.getenv("JWT_PRIVATE_KEY", "").replace("\\n", "\n")
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

    return jwt.encode(payload, JWT_PRIVATE_KEY, algorithm="RS256")
