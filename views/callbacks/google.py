from flask import Blueprint, request

from repo.applications import get_application_by_client_id
from repo.user import get_or_create_user_from_sub
from services.connections.google import (
    exchange_code_for_id_token,
    verify_google_id_token,
)
from utility.redis.cache import cache_delete, cache_get

google_callback_bp = Blueprint("callbacks_google", __name__)


@google_callback_bp.get("/callback/google")
def google_callback():
    returned_state = request.args.get("state")
    code = request.args.get("code")

    nonce = cache_get(returned_state)
    if not nonce:
        return "The state parameter is invalid, expired, or was already used.", 400
    cache_delete(returned_state)

    resource_owner_request = nonce["resource_owner"]

    id_token = exchange_code_for_id_token(code)
    claims = verify_google_id_token(id_token)

    sub = f"google-oauth2 | {claims['sub']}"

    application = get_application_by_client_id(resource_owner_request["client_id"])
    user = get_or_create_user_from_sub(sub, {
        "username": claims["email"],
        "email": claims["email"],
        "connection": "google-oauth2",
        "tenant_id": application.tenant_id,
    })

    user_view = {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "sub": user.sub,
        "connection": user.connection,
        "tenant_id": user.tenant_id,
    }

    print(claims)
    print(user_view)

    return {"claims": claims, "user": user_view}
