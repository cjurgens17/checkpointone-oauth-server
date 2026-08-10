import secrets
from datetime import datetime, timedelta, timezone

from utility.redis.cache import cache_delete, cache_get, cache_set

AUTH_CODE_TTL_SECONDS = 600


def create_auth_code(data):
    code = secrets.token_urlsafe(24)
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=AUTH_CODE_TTL_SECONDS)

    payload = {
        **data,
        "id": secrets.token_urlsafe(16),
        "expires_at": expires_at.isoformat(),
    }

    cache_set(code, payload, AUTH_CODE_TTL_SECONDS)
    return code

def redeem_auth_code(code):
    data = cache_get(code)
    cache_delete(code)
    return data