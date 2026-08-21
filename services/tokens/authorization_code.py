import secrets
from datetime import datetime, timedelta, timezone

from utility.helpers import hash_sha256
from utility.redis.cache import cache_delete, cache_get, cache_set
from utility.validation import valid_code_challenge_method

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


def auth_code_expired(data):
    expires_at = data.get("expires_at")
    if not expires_at:
        return True
    return datetime.now(timezone.utc) >= datetime.fromisoformat(expires_at)


def valid_code_challenge(code_verifier, code_challenge_method, code_challenge):
    if not valid_code_challenge_method(code_challenge_method):
        return False
    return hash_sha256(code_verifier) == code_challenge
