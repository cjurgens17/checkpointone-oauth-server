from flask import Blueprint, redirect, render_template, request

from repo.applications import get_application_by_client_id
from repo.user import get_or_create_user_from_user_id
from services.connections.google import (
    exchange_code_for_id_token,
    verify_google_id_token,
)
from services.tokens.authorization_code import create_auth_code
from services.tokens.id_token import merge_provider_claims
from utility.helpers import build_encoded_url
from utility.oauth_errors import redirect_with_error
from utility.redis.cache import cache_delete, cache_get

google_callback_bp = Blueprint("callbacks_google", __name__)


@google_callback_bp.get("/callback/google")
def google_callback():
    returned_state = request.args.get("state")
    error = request.args.get("error")
    code = request.args.get("code")

    nonce = cache_get(returned_state)
    if not nonce:
        return render_template(
            "state_invalid.html",
            title="Authorization Error",
        ), 400
    cache_delete(returned_state)

    resource_owner_request = nonce["resource_owner"]

    if error and error == "access_denied":
        return redirect_with_error(
            resource_owner_request["redirect_uri"],
            error="access_denied",
            error_description="Access to the provider has been cancelled or invalidated",
            state=resource_owner_request["state"],
        )

    id_token = exchange_code_for_id_token(code)
    claims = verify_google_id_token(id_token)

    user_id = f"google-oauth2|{claims['sub']}"

    application = get_application_by_client_id(resource_owner_request["client_id"])
    # Update defaults here to match claims from google -> solves downstream JIT provisioning -> After initial provision, the resource server is responsible for updating user claims

    get_or_create_user_from_user_id(
        user_id,
        merge_provider_claims(
            resource_owner_request.get("scope", "").split(" "),
            {
                "username": claims["email"],
                "email": claims["email"],
                "connection": "google-oauth2",
                "tenant_id": application.tenant_id,
                "sub": user_id,
                "user_id": user_id,
            },
            claims,
        ),
    )

    resource_owner_request["sub"] = user_id
    resource_owner_request["provider_claims"] = claims

    auth_code = create_auth_code(resource_owner_request)
    params = {"state": resource_owner_request["state"], "code": auth_code}
    return redirect(build_encoded_url(resource_owner_request["redirect_uri"], params))
