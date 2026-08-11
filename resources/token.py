from flask import request
from flask_restful import Resource

from services.tokens.access_token import ACCESS_TOKEN_TTL_SECONDS, create_access_token
from services.tokens.authorization_code import (
    auth_code_expired,
    redeem_auth_code,
    valid_code_challenge,
)
from services.tokens.id_token import generate_id_token

REQUIRED_PARAMS = [
    "code",
    "grant_type",
    "redirect_uri",
    "client_id",
    "audience",
]


class OAuthToken(Resource):
    def post(self):
        body = request.get_json(silent=True) or {}
        params = {name: body.get(name) for name in REQUIRED_PARAMS}

        missing = [name for name, value in params.items() if not value]
        if missing:
            return {
                "error": "invalid_request",
                "error_description": f"Missing required parameter(s): {', '.join(missing)}.",
            }, 400
        # TODO
        # If client secret is available then authenticate the client via a client credential grant before continuing.
        # Verify Auth Code and not expired, Correct Client, and Redirect Uri

        client_metadata = redeem_auth_code(body.get("code"))

        if not client_metadata or auth_code_expired(client_metadata):
            return {
                "error": "invalid_authorization",
                "error_description": "invalid authorization code",
            }, 400
        if client_metadata.get("client_id") != body.get("client_id"):
            return {
                "error": "invalid_client",
                "error_description": "the requested client is incorrect or not authorized",
            }, 400
        if client_metadata.get("redirect_uri") != body.get("redirect_uri"):
            return {
                "error": "invalid_redirect",
                "error_description": "the provided redirect uri is missing or not supported",
            }, 400

        if body.get("code_verifier") and not valid_code_challenge(
            body.get("code_verifier"),
            client_metadata.get("code_challenge_method"),
            client_metadata.get("code_challenge"),
        ):
            return {
                "error": "invalid_request",
                "error_description": "failed to identify correct code challenge",
            }, 400

        access_token = create_access_token(client_metadata)
        oauth_response = {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_TTL_SECONDS,
        }
        if "openid" in client_metadata.get("scope"):
            oauth_response["id_token"] = generate_id_token(client_metadata)
        return oauth_response
