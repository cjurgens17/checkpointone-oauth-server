from flask import Blueprint, redirect, render_template, request

from repo.applications import get_application_from_client_id
from repo.user import get_or_create_user_from_user_id, get_user_from_user_id
from services.connections.github import (
    exchange_code_for_access_token,
    get_userinfo,
    normalize_userinfo_claims,
)
from services.connections.username_password_authentication import (
    email_already_registered,
)
from services.session import generate_server_session_cookie
from services.tokens.authorization_code import create_auth_code
from services.tokens.id_token import merge_provider_claims
from utility.constants import IdentityProvider
from utility.helpers import build_encoded_url, generate_state
from utility.oauth_errors import redirect_with_error
from utility.redis.cache import cache_delete, cache_get, cache_set
from utility.validation import valid_email

github_callback_bp = Blueprint("callbacks_github", __name__)

PENDING_EMAIL_TTL_SECONDS = 600


def _issue_github_session(resource_owner_request, user_id, username, claims):
    application = get_application_from_client_id(resource_owner_request["client_id"])

    user = get_or_create_user_from_user_id(
        user_id,
        merge_provider_claims(
            resource_owner_request.get("scope", "").split(" "),
            {
                "username": username,
                "email": claims.get("email"),
                "connection": IdentityProvider.GITHUB,
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
    response = redirect(
        build_encoded_url(resource_owner_request["redirect_uri"], params)
    )

    session_cookie_name, session_id, cookie_options = generate_server_session_cookie(
        user.user_id,
        client_id=resource_owner_request["client_id"],
        response_type=resource_owner_request["response_type"],
        scope=resource_owner_request.get("scope", ""),
        connection=IdentityProvider.GITHUB,
        audience=resource_owner_request.get("audience"),
    )
    response.set_cookie(session_cookie_name, session_id, **cookie_options)
    return response


@github_callback_bp.route("/callback/github", methods=["GET", "POST"])
def github_callback():
    # Interrupt if github comes back with a null email
    if request.method == "POST":
        pending_state = request.form.get("pending_state")
        email = request.form.get("email", "").strip()
        pending = cache_get(pending_state)

        if not pending:
            return render_template(
                "state_invalid.html",
                title="Authorization Error",
            ), 400

        error = None
        if not valid_email(email):
            error = "Enter a valid email address."
        elif email_already_registered(email):
            error = "An account with this email already exists."

        if error:
            return render_template(
                "github_email_required.html",
                title="Confirm your email",
                pending_state=pending_state,
                error=error,
                email=email,
            ), 400

        cache_delete(pending_state)
        claims = pending["claims"]
        claims["email"] = email
        claims["email_verified"] = False
        return _issue_github_session(
            pending["resource_owner_request"],
            pending["user_id"],
            pending["username"],
            claims,
        )

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

    access_token = exchange_code_for_access_token(code)
    userinfo = get_userinfo(access_token)
    claims = normalize_userinfo_claims(userinfo)

    user_id = f"{IdentityProvider.GITHUB}|{userinfo['id']}"
    username = userinfo.get("login")

    if not claims.get("email"):
        existing_user = get_user_from_user_id(user_id)
        if existing_user and existing_user.email:
            claims["email"] = existing_user.email
            claims["email_verified"] = existing_user.email_verified
        else:
            pending_state = generate_state()
            cache_set(
                pending_state,
                {
                    "resource_owner_request": resource_owner_request,
                    "user_id": user_id,
                    "username": username,
                    "claims": claims,
                },
                PENDING_EMAIL_TTL_SECONDS,
            )
            return render_template(
                "github_email_required.html",
                title="Confirm your email",
                pending_state=pending_state,
            )

    return _issue_github_session(resource_owner_request, user_id, username, claims)
