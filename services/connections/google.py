import json
import os
import time
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import jwt
from jwt import PyJWKClient

from utility.helpers import generate_state
from utility.redis.cache import cache_set

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")
GOOGLE_AUTHORIZATION_ENDPOINT = os.getenv("GOOGLE_AUTHORIZATION_ENDPOINT")
GOOGLE_TOKEN_ENDPOINT = os.getenv("GOOGLE_TOKEN_ENDPOINT")
GOOGLE_JWKS_URL = os.getenv("GOOGLE_JWKS_URL")
GOOGLE_ISSUER = os.getenv("GOOGLE_ISSUER")

# Fetches + caches Google's published signing keys (and re-fetches on an
# unrecognized kid, e.g. after Google rotates its keys) instead of hardcoding them.
_jwks_client = PyJWKClient(GOOGLE_JWKS_URL, cache_keys=True)


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


def exchange_code_for_id_token(code: str) -> str:
    # Google requires application/x-www-form-urlencoded per RFC spec
    payload = urlencode({
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code",
    }).encode()

    headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
    
    request = Request(GOOGLE_TOKEN_ENDPOINT, data=payload, method="POST", headers=headers)
    try:
        with urlopen(request) as response:
            tokens = json.loads(response.read())
    except HTTPError as error:
        raise ValueError(f"Google token exchange failed: {error.read().decode()}") from error

    return tokens["id_token"]


def verify_google_id_token(id_token: str) -> dict:
    signing_key = _jwks_client.get_signing_key_from_jwt(id_token)
    #jwt.decode does an implicit exp claim check
    claims = jwt.decode(
        id_token,
        signing_key.key,
        algorithms=["RS256"],
        audience=GOOGLE_CLIENT_ID,
        issuer=GOOGLE_ISSUER,
    )
    
    if claims["iat"] > time.time():
        raise ValueError("id_token was issued in the future")

    return claims
