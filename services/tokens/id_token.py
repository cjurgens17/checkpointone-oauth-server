import os
import time

import jwt

# REQUIRED CLAIMS: iss, exp, iat, aud, sub

ISSUER = os.getenv("ISSUER", "http://localhost:5000")
JWT_PRIVATE_KEY = os.getenv("JWT_PRIVATE_KEY", "").replace("\\n", "\n")
ID_TOKEN_TTL_SECONDS = 3600

_ADDITIONAL_OPENID_SCOPES = ["email", "profile", "phone", "address"]
_CLAIM_KEYS = {
    "email": ("email", "email_verified"),
    "profile": (
        "name",
        "family_name",
        "given_name",
        "middle_name",
        "nickname",
        "preferred_username",
        "profile",
        "picture",
        "website",
        "gender",
        "birthdate",
        "zoneinfo",
        "locale",
        "updated_at",
    ),
    "phone": ("phone_number", "phone_number_verified"),
    "address": ("address",),
}


def _copy_present_claims(payload, provider_claims, keys):
    for key in keys:
        if key in provider_claims:
            payload[key] = provider_claims[key]


def generate_id_token(client_metadata):
    issued_at = int(time.time())

    payload = {
        "iss": ISSUER,
        "aud": client_metadata.get("audience"),
        "sub": client_metadata.get("sub"),
        "iat": issued_at,
        "exp": issued_at + ID_TOKEN_TTL_SECONDS,
    }

    scope = client_metadata.get("scope", "").split(" ")
    provider_claims = client_metadata.get("provider_claims", {})

    payload = merge_provider_claims(scope, payload, provider_claims)

    return jwt.encode(payload, JWT_PRIVATE_KEY, algorithm="RS256")


def merge_provider_claims(scope: list[str], curr_claims, provider_claims):
    if not isinstance(scope, list):
        raise TypeError("Scope must explicilty be a list of strings here")
    if "openid" not in scope:
        return curr_claims
    for openid_scope in _ADDITIONAL_OPENID_SCOPES:
        keys = _CLAIM_KEYS.get(openid_scope)
        if openid_scope in scope:
            _copy_present_claims(curr_claims, provider_claims, keys)
    return curr_claims
