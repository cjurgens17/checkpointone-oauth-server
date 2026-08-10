from flask import request
from flask_restful import Resource

from services.tokens.authorization_code import auth_code_expired
from utility.redis.cache import cache_delete, cache_get

REQUIRED_PARAMS = [
    "code",
    "grant_type",
    "redirect_uri",
    "client_id",
    "audience",
    "code_verifier",
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

        #If client secret is available then authenticate the client via a client credential grant before continuing.
        #Verify Auth Code and not expired, Correct Client, and Redirect Uri

        client_metadata = cache_get(body.get("code"))
        if client_metadata:
            cache_delete(body.get("code"))
        elif not client_metadata or auth_code_expired(client_metadata):
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

        return "token"