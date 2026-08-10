from flask import Blueprint, redirect, render_template, request

from repo.applications import (
    allowed_redirect_uri,
    get_application_by_client_id,
    get_tenant_from_application,
)
from services.connections.google import (
    build_google_authorization_url,
    prepare_redirect_to_oauth_server,
)
from services.connections.username_password_authentication import (
    authenticate_user_success,
)
from utility.oauth_errors import redirect_with_error
from utility.validation import (
    valid_code_challenge_method,
    valid_connection,
    valid_redirect_uri,
    valid_response_type,
    valid_scope,
)

authorize_bp = Blueprint("authorize", __name__)


@authorize_bp.route("/authorize", methods=["GET", "POST"])
def authorize():
    response_type = request.values.get("response_type")
    client_id = request.values.get("client_id")
    redirect_uri = request.values.get("redirect_uri")
    scope = request.values.get("scope", "openid email profile")
    state = request.values.get("state")
    connection = request.values.get("connection", "Username-Password-Authentication")
    code_challenge = request.values.get("code_challenge")
    code_challenge_method = request.values.get("code_challenge_method")

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

    tenant = get_tenant_from_application(application.client_id)
    
    match(connection):
        #Add OpenID providers as we expand
        #Look Over RFC spec for secure implementation here
        case "Username-Password-Authentication":
            username = request.form.get("username")
            password = request.form.get("password")

            if request.method == "POST":
                if authenticate_user_success(username, password):
                    #Create + store authorization code, redirect resource owner back to redirect_uri with state + code.
                    return f"Authenticated as {username}"

                return render_template(
                    "login.html",
                    title="Log In",
                    application=application,
                    tenant=tenant,
                    response_type=response_type,
                    client_id=client_id,
                    redirect_uri=redirect_uri,
                    scope=scope,
                    state=state,
                    connection=connection,
                    code_challenge=code_challenge,
                    code_challenge_method=code_challenge_method,
                    error="Incorrect username or password.",
                    username=username,
                ), 401

            return render_template(
                "login.html",
                title="Log In",
                application=application,
                tenant=tenant,
                response_type=response_type,
                client_id=client_id,
                redirect_uri=redirect_uri,
                scope=scope,
                state=state,
                connection=connection,
                code_challenge=code_challenge,
                code_challenge_method=code_challenge_method,
            )
        case "google-oauth2":
            server_state = prepare_redirect_to_oauth_server({
                "state": state,
                "redirect_uri": redirect_uri,
                "code_challenge_method": code_challenge_method,
                "code_challenge": code_challenge,
                "scope": scope,
                "client_id": client_id,
                "response_type": response_type
            })
            google_scope = "openid email"
            return redirect(build_google_authorization_url(server_state, google_scope))
        case "facebook":
            return "redirect to facebooks auth server"
        case "github":
            return "redirect to githubs auth server"
        case _:
            return "Hello World"
