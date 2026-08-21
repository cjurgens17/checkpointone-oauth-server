import uuid

from flask import request
from flask_restful import Resource

from repo.applications import get_application_from_client_id
from repo.refresh_token import (
    create_refresh_token,
    get_refresh_token_from_token_hash,
    revoke_refresh_token,
    revoke_refresh_token_family,
    update_refresh_token_used_at,
)
from repo.session import get_session_from_session_id
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
from services.tokens.id_token import generate_id_token, scope_requires_id_token
from services.tokens.refresh_token import (
    generate_absolute_exp,
    generate_exp,
    generate_refresh_token_tag,
    hash_refresh_token,
    refresh_token_validity_metadata,
    scope_requires_refresh_token,
)
from utility.constants import ClientType, GrantType, RevokeReason
from utility.helpers import get_current_timestamp

# supporting authorization_code, client_credentials, and refresh_token grant_type

REQUIRED_PARAMS = [
    "grant_type",
    "client_id",
    "audience",
]


def _issue_refresh_token(sub, scope, audience, client_id):
    iat = get_current_timestamp()
    refresh_token = generate_refresh_token_tag()
    refresh_token_record = create_refresh_token(
        sub=sub,
        token_hash=hash_refresh_token(refresh_token),
        scope=scope,
        audience=audience,
        client_id=client_id,
        iat=iat,
        exp=generate_exp(iat),
        absolute_exp=generate_absolute_exp(iat),
        family_id=uuid.uuid4(),
        parent_id=None,
    )
    return refresh_token, refresh_token_record


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

        # Handle refresh_token grant_type
        if GrantType.REFRESH == body.get("grant_type"):
            if not body.get("refresh_token"):
                return {
                    "error": "invalid_request",
                    "error_description": "invalid arguments for specified grant_type",
                }, 400

            client = get_application_from_client_id(body.get("client_id"))

            if not client:
                return {
                    "error": "invalid_request",
                    "error_description": "requested client is not registered",
                }
            if ClientType.WEB_APPLICATION == client.client_type and not body.get(
                "client_secret"
            ):
                return {
                    "error": "invalid_request",
                    "error_description": "confidential clients require client_secret",
                }, 400
            elif (
                ClientType.WEB_APPLICATION == client.client_type
                and client.client_secret != body.get("client_secret")
            ):
                return {
                    "error": "invalid_request",
                    "error_description": "invalid arguments for specified grant_type",
                }, 400

            refresh_token_record = get_refresh_token_from_token_hash(
                hash_refresh_token(body.get("refresh_token"))
            )

            if not refresh_token_record:
                return {
                    "error": "invalid_request",
                    "error_description": "invalid arguments for specified grant_type",
                }, 400

            refresh_token_metadata = refresh_token_validity_metadata(
                refresh_token_record, get_current_timestamp()
            )

            if refresh_token_metadata.get("already_used") or refresh_token_metadata.get(
                "revoked"
            ):
                # Assume Compromise(refresh token reuse abuse)
                revoke_refresh_token_family(
                    refresh_token_metadata.get("family_id"),
                    RevokeReason.REUSE,
                    get_current_timestamp(),
                )
            elif refresh_token_metadata.get("expired"):
                return {
                    "error": "invalid_grant",
                    "error_description": "new authorization is required",
                }, 400

            # Rotate Refresh Token
            if refresh_token_metadata.get("valid"):
                update_refresh_token_used_at(
                    hash_refresh_token(body.get("refresh_token")),
                    get_current_timestamp(),
                )
                revoke_refresh_token(
                    hash_refresh_token(body.get("refresh_token")),
                    RevokeReason.ROTATE,
                    get_current_timestamp(),
                )
                iat = get_current_timestamp()
                new_refresh_token = generate_refresh_token_tag()
                next_refresh_token = create_refresh_token(
                    sub=refresh_token_record.sub,
                    token_hash=hash_refresh_token(new_refresh_token),
                    scope=refresh_token_record.scope,
                    audience=refresh_token_record.audience,
                    client_id=refresh_token_record.client_id,
                    iat=iat,
                    exp=generate_exp(iat),
                    absolute_exp=refresh_token_record.absolute_exp,
                    family_id=refresh_token_record.family_id,
                    parent_id=refresh_token_record.id,
                )

                client_metadata = {
                    "sub": next_refresh_token.sub,
                    "audience": next_refresh_token.audience,
                    "scope": next_refresh_token.scope,
                    "client_id": next_refresh_token.client_id,
                }
                access_token = (
                    create_access_token(client_metadata)
                    if client.client_type != ClientType.WEB_APPLICATION
                    else create_confidential_client_access_token(client_metadata)
                )

                oauth_response = {
                    "access_token": access_token,
                    "refresh_token": new_refresh_token,
                    "token_type": "Bearer",
                    "expires_in": ACCESS_TOKEN_TTL_SECONDS,
                    "scope": next_refresh_token.scope,
                }
                if scope_requires_id_token(next_refresh_token.scope):
                    oauth_response["id_token"] = generate_id_token(client_metadata)
                return oauth_response, 200, {"Cache-Control": "no-store"}

        # Handle client_credentials grant_type
        if GrantType.CONFIDENTIAL == body.get("grant_type"):
            client = get_application_from_client_id(body.get("client_id"))

            if not client:
                return {
                    "error": "invalid_request",
                    "error_description": "requested client is not registered",
                }, 400

            if ClientType.WEB_APPLICATION != client.client_type:
                return {
                    "error": "client_unsupported",
                    "error_description": "the client is not registered to perform a client_credentials grant type",
                }, 400
            if client.client_secret != body.get("client_secret"):
                return {
                    "error": "invalid_credentials",
                    "error_description": "client credentials do not match",
                }, 400
            # Returning all granted permissions for now - IF SPECIFIC SCOPE IS ARGUED IT OVERRIDES THE GRANT ALL:***WILL IMPLEMENT***
            confidential_client_metadata = {
                "audience": body.get("audience"),
                "client_id": client.client_id,
            }
            if client.permissions and len(client.permissions) > 0:
                confidential_client_metadata["permissions"] = " ".join(
                    client.permissions
                )
            access_token = create_confidential_client_access_token(
                confidential_client_metadata
            )
            oauth_response = {
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": ACCESS_TOKEN_TTL_SECONDS,
            }
            if scope_requires_refresh_token(body.get("scope")):
                refresh_token, _ = _issue_refresh_token(
                    sub=client.client_id,
                    scope=confidential_client_metadata.get("permissions"),
                    audience=confidential_client_metadata.get("audience"),
                    client_id=client.client_id,
                )
                oauth_response["refresh_token"] = refresh_token
            return oauth_response, 200, {"Cache-Control": "no-store"}

        # Handle authorization_code grant_type
        if not body.get("code"):
            return {
                "error": "invalid_request",
                "error_description": "missing required code parameter",
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
        if client_metadata.get("redirect_uri") and client_metadata.get(
            "redirect_uri"
        ) != body.get("redirect_uri"):
            return {
                "error": "invalid_redirect",
                "error_description": "the provided redirect uri is not supported",
            }, 400

        if not body.get("code_verifier"):
            return {
                "error": "invalid_request",
                "error_description": "invalid or missing code_verifier",
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
        # Return same scope tied to session if the session exists already - Up to Developer to authorize with prompt=login to requst new authorization outside of current session scope.
        if is_valid_session():
            session = get_session_from_session_id(
                request.cookies.get(SESSION_COOKIE_NAME)
            )
            if session.client_id != client_metadata.get(
                "client_id"
            ) or session.audience != body.get("audience"):
                return {
                    "error": "invalid_grant",
                    "error_description": "the active session is not associated with the requested client_id and audience",
                }, 400
            client_metadata["scope"] = session.scope
        access_token = create_access_token(client_metadata)
        oauth_response = {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_TTL_SECONDS,
        }
        if scope_requires_id_token(client_metadata.get("scope")):
            oauth_response["id_token"] = generate_id_token(client_metadata)
        if scope_requires_refresh_token(client_metadata.get("scope")):
            refresh_token, _ = _issue_refresh_token(
                sub=client_metadata.get("sub"),
                scope=client_metadata.get("scope"),
                audience=client_metadata.get("audience"),
                client_id=client_metadata.get("client_id"),
            )
            oauth_response["refresh_token"] = refresh_token
        return oauth_response, 200, {"Cache-Control": "no-store"}
