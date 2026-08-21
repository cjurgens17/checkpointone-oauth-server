import os

import jwt
from flask import Blueprint, redirect, render_template, request

from repo.applications import allowed_logout_uri
from services.session import SESSION_COOKIE_NAME, end_session
from services.tokens.id_token import verify_id_token_on_logout
from utility.helpers import build_encoded_url
from utility.validation import valid_redirect_uri

logout_bp = Blueprint("logout", __name__)

ISSUER = os.getenv("ISSUER", "http://localhost:5000")


# https://openid.net/specs/openid-connect-rpinitiated-1_0.html
# It is up to the RP to make the decision to logout the user locally upon redirection. It is up to the AS to ensure the current RP is logged-out and any RP's associated with its OP.
# OIDF State Logout MUST include GET and POST Methods
@logout_bp.route("/logout", methods=["GET", "POST"])
def logout():
    client_id = request.values.get("client_id")
    post_logout_redirect_uri = request.values.get("post_logout_redirect_uri")
    id_token_hint = request.values.get("id_token_hint")

    if not id_token_hint:
        return render_template(
            "id_token_hint_missing.html",
            title="Logout Error",
        ), 400

    # Defaulting to Username-Password-Authentication for now - OP is CheckPointOne in this case.
    try:
        verify_id_token_on_logout(id_token_hint)
    except jwt.InvalidTokenError as error:
        return render_template(
            "logout_error.html",
            title="Logout Error",
            message=str(error),
        ), 400

    if (
        post_logout_redirect_uri
        and client_id
        and valid_redirect_uri(post_logout_redirect_uri)
        and allowed_logout_uri(post_logout_redirect_uri, client_id)
    ):
        response = redirect(build_encoded_url(post_logout_redirect_uri))
        session_id = request.cookies.get(SESSION_COOKIE_NAME)
        response = end_session(response, session_id)
        return response
    else:
        return render_template(
            "post_logout_redirect_uri_invalid.html",
            title="Logout Error",
            post_logout_redirect_uri=post_logout_redirect_uri,
        ), 400
