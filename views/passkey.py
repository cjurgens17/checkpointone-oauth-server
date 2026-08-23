from datetime import datetime, timezone

from flask import Blueprint, redirect, request, url_for

from repo.session import get_session_from_session_id
from repo.user import get_user_from_user_id
from services.session import SESSION_COOKIE_NAME
from views.authorize import _issue_auth_code

passkey_bp = Blueprint("passkey", __name__)


@passkey_bp.route("/authorize/passkey/continue", methods=["POST"])
def passkey_prompt_continue():
    oauth_params = {
        "response_type": request.form.get("response_type"),
        "client_id": request.form.get("client_id"),
        "redirect_uri": request.form.get("redirect_uri"),
        "scope": request.form.get("scope"),
        "state": request.form.get("state"),
        "code_challenge": request.form.get("code_challenge"),
        "code_challenge_method": request.form.get("code_challenge_method"),
        "audience": request.form.get("audience"),
    }
    connection = request.form.get("connection")

    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    session = get_session_from_session_id(session_id)
    user = get_user_from_user_id(session.user_id) if session else None

    if not session or session.expires_at <= datetime.now(timezone.utc) or not user:
        return redirect(
            url_for("authorize.authorize", connection=connection, **oauth_params)
        )

    return _issue_auth_code(oauth_params, user, connection)
