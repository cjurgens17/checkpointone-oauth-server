from flask import request
from flask_restful import Resource

from repo.applications import get_application_from_client_id
from repo.session import get_scope_from_session, get_session_from_session_id
from services.session import SESSION_COOKIE_NAME, is_valid_session
from services.tokens.access_token import (
    ACCESS_TOKEN_TTL_SECONDS,
    create_access_token,
    create_confidential_client_access_token,
)
from services.tokens.authorization_code import (
    auth_code_expired,
    redeem_auth_code,
    valid_code_challenge,
)
from services.tokens.id_token import generate_id_token
from utility.constants import ClientType, GrantType

#Currently, Only supporting authorization_code and client_credentials grant_type

REQUIRED_PARAMS = [
    "grant_type",
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
        
        #Handle client_credentials grant_type
        if GrantType.CONFIDENTIAL == body.get("grant_type"):
            client = get_application_from_client_id(body.get("client_id"))

            if not client:
                return {
                    "error": "invalid_request",
                    "error_description": "requested client is not registered"
                }, 400

            if ClientType.WEB_APPLICATION != client.client_type:
                return {
                    "error": "client_unsupported",
                    "error_description": "the client is not registered to perform a client_credentials grant type"
                }, 400
            if client.client_secret != body.get("client_secret"):
                return {
                    "error": "invalid_credentials",
                    "error_description": "client credentials do not match"
                }, 400
            #Returning all granted permissions for now - IF SPECIFIC SCOPE IS ARGUED IT OVERRIDES THE GRANT ALL:***WILL IMPLEMENT***
            confidential_client_metadata = {
                "audience": body.get("audience"),
                "client_id": client.client_id,
            }
            if client.permissions and len(client.permissions) > 0:
                confidential_client_metadata["permissions"] = " ".join(client.permissions)
            access_token = create_confidential_client_access_token(confidential_client_metadata)
            oauth_response = {
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": ACCESS_TOKEN_TTL_SECONDS
            }
            return oauth_response, 200, {"Cache-Control": "no-store"}
            

        #Handle authorization_code grant_type
        if not body.get("code"):
            return {
                "error": "invalid_request",
                "error_description": "missing required code parameter"
            }, 400
        
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
        if client_metadata.get("redirect_uri") and client_metadata.get("redirect_uri") != body.get("redirect_uri"):
            return {
                "error": "invalid_redirect",
                "error_description": "the provided redirect uri is not supported",
            }, 400

        if not body.get("code_verifier"):
            return {
                "error": "invalid_request",
                "error_description": "invalid or missing code_verifier"
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
        #Return Same scope tied to session if the session exists already - Up to Developer to authorize with prompt=login to requst new authorization outside of current session scope.
        if is_valid_session():
            session = get_session_from_session_id(request.cookies.get(SESSION_COOKIE_NAME))
            client_metadata["scope"] = get_scope_from_session(session.session_id)
        access_token = create_access_token(client_metadata)
        oauth_response = {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_TTL_SECONDS,
        }
        if "openid" in client_metadata.get("scope"):
            oauth_response["id_token"] = generate_id_token(client_metadata)
        return oauth_response, 200, {"Cache-Control": "no-store"}
