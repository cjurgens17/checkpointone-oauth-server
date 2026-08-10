import os
from urllib.parse import urlencode

from utility.helpers import generate_state
from utility.redis.cache import cache_set

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")
GOOGLE_AUTHORIZATION_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"


def prepare_redirect_to_oauth_server(data: dict):
    server_state = generate_state()
    nonce = {
        "resource_owner": data
    }
    cache_set(server_state, nonce, 1000)
    return server_state


def build_google_authorization_url(state: str, scope: str) -> str:
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": scope,
        "state": state,
    }
    return f"{GOOGLE_AUTHORIZATION_ENDPOINT}?{urlencode(params)}"
