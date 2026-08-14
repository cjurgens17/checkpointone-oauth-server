import os

from flask import Blueprint, jsonify

from utility.constants import VALID_OPEN_ID_SCOPE
from utility.jwt_keys import JWT_JWK

jwks_bp = Blueprint("jwks", __name__)

ISSUER = os.getenv("ISSUER", "http://localhost:5000")

#Refer to https://datatracker.ietf.org/doc/html/rfc8414

@jwks_bp.get("/.well-known/jwks.json")
def jwks():
    return jsonify({"keys": [JWT_JWK]})


def _discovery_metadata():
    return {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/authorize",
        "token_endpoint": f"{ISSUER}/oauth/token",
        "end_session_endpoint": f"{ISSUER}/logout",
        "jwks_uri": f"{ISSUER}/.well-known/jwks.json",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "client_credentials"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": VALID_OPEN_ID_SCOPE,
        "token_endpoint_auth_methods_supported": ["none"],
        "code_challenge_methods_supported": ["S256"],
    }


@jwks_bp.get("/.well-known/openid-configuration")
def openid_configuration():
    return jsonify(_discovery_metadata())


@jwks_bp.get("/.well-known/oauth-authorization-server")
def oauth_authorization_server():
    return jsonify(_discovery_metadata())
