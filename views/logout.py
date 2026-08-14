import os

from flask import Blueprint, make_response, redirect, render_template, request

from repo.applications import allowed_logout_uri
from services.session import SESSION_COOKIE_NAME, end_session
from utility.helpers import build_encoded_url
from utility.validation import valid_redirect_uri

logout_bp = Blueprint("logout", __name__)

ISSUER = os.getenv("ISSUER", "http://localhost:5000")


@logout_bp.route("/logout", methods=["GET"])
def logout():
    client_id = request.args.get("client_id")
    post_logout_redirect_uri = request.args.get("post_logout_redirect_uri")

    if (
        post_logout_redirect_uri
        and client_id
        and valid_redirect_uri(post_logout_redirect_uri)
        and allowed_logout_uri(post_logout_redirect_uri, client_id)
    ):
        redirect_target = build_encoded_url(post_logout_redirect_uri)

    if redirect_target:
        response = redirect(redirect_target)
    else:
        response = make_response(render_template("logged_out.html", title="Logged Out"))

    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    response = end_session(response, session_id)
    return response
