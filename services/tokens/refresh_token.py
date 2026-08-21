import secrets
from datetime import datetime, timedelta, timezone

from utility.helpers import hash_sha256

REFRESH_TOKEN_BYTE_LENGTH = 32
DEFAULT_REFRESH_TOKEN_IDLE_TIME = 604800 # 7 Days
DEFAULT_REFRESH_TOKEN_ABSOLUTE_TTL = 1209600 # 14 Days

def generate_refresh_token_tag():
    return secrets.token_urlsafe(REFRESH_TOKEN_BYTE_LENGTH)


def hash_refresh_token(refresh_token: str):
    return hash_sha256(refresh_token)


def refresh_token_validity_metadata(refresh_token, now: datetime | None = None):
    now = now or datetime.now(timezone.utc)

    already_used = refresh_token.used_at is not None
    revoked = refresh_token.revoked_at is not None
    expired = now >= refresh_token.exp or now >= refresh_token.absolute_exp
    valid = not already_used and not revoked and not expired

    return {
        "valid": valid,
        "already_used": already_used,
        "expired": expired,
        "revoked": revoked,
        "revoke_reason": refresh_token.revoke_reason,
        "family_id": refresh_token.family_id,
    }

def generate_exp(iat):
    return iat + timedelta(seconds=DEFAULT_REFRESH_TOKEN_IDLE_TIME)

def generate_absolute_exp(iat):
    return iat + timedelta(seconds=DEFAULT_REFRESH_TOKEN_ABSOLUTE_TTL)

def scope_requires_refresh_token(scope):
    if not scope:
        return False
    return "offline_access" in scope.split(" ")
