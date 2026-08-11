from flask import request
from flask_restful import Resource

from services.tokens.authorization_code import (
    auth_code_expired,
    redeem_auth_code,
    valid_code_challenge,
)

REQUIRED_PARAMS = [
    "code",
    "grant_type",
    "redirect_uri",
    "client_id",
    "audience",
]


class Token(Resource):
    def post(self):
        body = request.get_json(silent=True) or {}
        params = {name: body.get(name) for name in REQUIRED_PARAMS}

        missing = [name for name, value in params.items() if not value]
        if missing:
            return {
                "error": "invalid_request",
                "error_description": f"Missing required parameter(s): {', '.join(missing)}.",
            }, 400
        #TODO
            #If client secret is available then authenticate the client via a client credential grant before continuing.
            #Verify Auth Code and not expired, Correct Client, and Redirect Uri

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

        if body.get("code_verifier") or body.get("code_challenge_method"):
            if not (body.get("code_verifier") and body.get("code_challenge_method")):
                return {
                        "error": "invalid_request",
                        "error_description": "missing required parameters to validate code challenge"
                        }, 400
            is_valid = valid_code_challenge(body.get("code_verifier"), body.get("code_challenge_method"), client_metadata.get("code_challenge"))
            if not is_valid:
                return {
                        "error": "invalid_authorization",
                        "error_description": "client has failed to recognize code challenge"
                        }, 400

        
        return "token"