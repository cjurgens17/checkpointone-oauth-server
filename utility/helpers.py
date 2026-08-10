import hashlib
import secrets
import string
from urllib.parse import urlencode

STATE_ALPHABET = string.ascii_letters + string.digits
STATE_MIN_LENGTH = 25
STATE_MAX_LENGTH = 30


def hash_sha256(value):
    return hashlib.sha256(value.encode()).hexdigest()

def generate_state():
    length = secrets.choice(range(STATE_MIN_LENGTH, STATE_MAX_LENGTH + 1))
    return "".join(secrets.choice(STATE_ALPHABET) for _ in range(length))

def build_encoded_url(url, params):
    return f"{url}?{urlencode(params)}"