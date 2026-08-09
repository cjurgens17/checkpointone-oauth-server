from flask import Blueprint, render_template, request

from services.applications import allowed_redirect_uri, get_application_by_client_id
from utility.oauth_errors import redirect_with_error
from utility.validation import valid_code_challenge_method, valid_connection, valid_redirect_uri, valid_response_type, valid_scope

authorize_bp = Blueprint("authorize", __name__)


@authorize_bp.get("/authorize")
def authorize():
    response_type = request.args.get("response_type")
    client_id = request.args.get("client_id")
    redirect_uri = request.args.get("redirect_uri")
    scope = request.args.get("scope", "openid email profile")
    state = request.args.get("state")
    connection = request.args.get("connection", "Username-Password-Authentication")
    code_challenge = request.args.get("code_challenge")
    code_challenge_method = request.args.get("code_challenge_method")

    application = get_application_by_client_id(client_id)

    if not application:
        return render_template(
            "authorize_error.html",
            title="Authorization Error",
            message="The client_id parameter is missing or does not match any registered application.",
            client_id=client_id,
        ), 400

    if not redirect_uri:
        return render_template(
            "redirect_uri_missing.html",
            title="Authorization Error",
        ), 400
    elif not valid_redirect_uri(redirect_uri):
        return render_template(
            "redirect_uri_invalid.html",
            title="Authorization Error",
            redirect_uri=redirect_uri,
        ), 400
    elif not allowed_redirect_uri(redirect_uri, application.client_id):
        return render_template(
            "redirect_uri_mismatch.html",
            title="Authorization Error",
            redirect_uri=redirect_uri,
        ), 400
    
    # RFC 6749 - https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
    if not response_type or not valid_response_type(response_type):
        return redirect_with_error(
            redirect_uri,
            error="unsupported_response_type",
            error_description="The response_type parameter is missing or not supported.",
            state=state,
        )

    if not valid_scope(scope, application.scope):
        return redirect_with_error(
            redirect_uri,
            error="invalid_scope",
            error_description="The requested scope is invalid, unknown, or malformed.",
            state=state
        )

    if not valid_code_challenge_method(code_challenge_method):
        return redirect_with_error(
            redirect_uri,
            error="invalid_code_challenge_method",
            error_description="The requested code challenge method is not supported.",
            state=state
        )

    if not valid_connection(connection):
        return redirect_with_error(
            redirect_uri,
            error="invalid_connection",
            error_description="The connection is malformed or not supported",
            state=state
        )



    return "Hello World"
