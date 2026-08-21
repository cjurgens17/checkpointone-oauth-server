import hashlib
import secrets
import string
from datetime import datetime, timezone
from urllib.parse import urlencode

from utility.constants import VALID_OPEN_ID_SCOPE

STATE_ALPHABET = string.ascii_letters + string.digits
STATE_MIN_LENGTH = 25
STATE_MAX_LENGTH = 30

ALPHANUMERIC_ALPHABET = string.ascii_lowercase + string.digits
ALPHANUMERIC_LENGTH = 24


def hash_sha256(value):
    return hashlib.sha256(value.encode()).hexdigest()


def generate_state():
    length = secrets.choice(range(STATE_MIN_LENGTH, STATE_MAX_LENGTH + 1))
    return "".join(secrets.choice(STATE_ALPHABET) for _ in range(length))


def build_encoded_url(url, params=""):
    return f"{url}?{urlencode(params)}"


def retrieve_open_id_scope(scope):
    open_id_scope = []
    permissions = scope.split(" ")
    for permission in permissions:
        if permission in VALID_OPEN_ID_SCOPE:
            open_id_scope.append(permission)
    return " ".join(open_id_scope).strip()


# TODO- some type of callback system here to enforce uniqueness across tenant users
def generate_unique_sub_id():
    return "".join(
        secrets.choice(ALPHANUMERIC_ALPHABET) for _ in range(ALPHANUMERIC_LENGTH)
    )


def get_current_timestamp():
    return datetime.now(timezone.utc)
