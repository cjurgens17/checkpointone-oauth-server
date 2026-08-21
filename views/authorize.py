from flask import Blueprint, make_response, redirect, render_template, request

from repo.applications import (
    allowed_redirect_uri,
    get_application_from_client_id,
    get_tenant_from_application,
)
from repo.session import get_session_from_session_id
from repo.user import get_user_from_user_id
from services.connections.github import (
    GITHUB_AUTHORIZATION_ENDPOINT,
    GITHUB_CLIENT_ID,
    GITHUB_REDIRECT_URI,
    GITHUB_SCOPE,
)
from services.connections.google import (
    GOOGLE_AUTHORIZATION_ENDPOINT,
    GOOGLE_CLIENT_ID,
    GOOGLE_REDIRECT_URI,
    prepare_redirect_to_oauth_server,
)
from services.connections.username_password_authentication import (
    authenticate_user,
    email_already_registered,
    register_user,
    user_claims,
)
from services.session import (
    SESSION_COOKIE_NAME,
    end_session,
    generate_server_session_cookie,
    is_valid_session,
)
from services.tokens.authorization_code import create_auth_code
from utility.constants import SCREEN_HINTS, IdentityProvider, Prompt, ScreenHint
from utility.errors import SessionUserNotFoundError
from utility.helpers import build_encoded_url, retrieve_open_id_scope
from utility.oauth_errors import redirect_with_error
from utility.validation import (
    MIN_PASSWORD_LENGTH,
    valid_code_challenge_method,
    valid_connection,
    valid_email,
    valid_password,
    valid_prompt,
    valid_redirect_uri,
    valid_response_type,
    valid_scope,
)

authorize_bp = Blueprint("authorize", __name__)


def _issue_auth_code(oauth_params, user, connection):
    auth_code = create_auth_code(
        {**oauth_params, "sub": user.sub, "provider_claims": user_claims(user)}
    )
    response = redirect(
        build_encoded_url(
            oauth_params["redirect_uri"],
            {"state": oauth_params["state"], "code": auth_code},
        )
    )
    session_cookie_name, session_id, cookie_options = generate_server_session_cookie(
        user.user_id,
        client_id=oauth_params["client_id"],
        response_type=oauth_params["response_type"],
        scope=oauth_params["scope"],
        connection=connection,
        audience=oauth_params["audience"],
    )
    response.set_cookie(session_cookie_name, session_id, **cookie_options)
    return response


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
    audience = request.values.get("audience")
    screen_hint = request.values.get("screen_hint", ScreenHint.LOGIN)
    prompt = request.values.get("prompt")
    if screen_hint not in SCREEN_HINTS:
        screen_hint = ScreenHint.LOGIN

    application = get_application_from_client_id(client_id)

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

    if not valid_scope(scope, application.permissions):
        return redirect_with_error(
            redirect_uri,
            error="invalid_scope",
            error_description="The requested scope is invalid, unknown, or malformed.",
            state=state,
        )

    if not valid_code_challenge_method(code_challenge_method):
        return redirect_with_error(
            redirect_uri,
            error="invalid_code_challenge_method",
            error_description="The requested code challenge method is not supported.",
            state=state,
        )

    if not code_challenge:
        return redirect_with_error(
            redirect_uri,
            error="invalid_code_challenge",
            error_description="code challenge not detected and is required",
            state=state,
        )

    if not valid_connection(connection):
        return redirect_with_error(
            redirect_uri,
            error="invalid_connection",
            error_description="The connection is malformed or not supported",
            state=state,
        )

    if not valid_prompt(prompt, connection):
        return redirect_with_error(
            redirect_uri,
            error="invalid_prompt",
            error_description="The requested prompt is invalid or not supported for this connection.",
            state=state,
        )

    tenant = get_tenant_from_application(application.client_id)

    match connection:
        case IdentityProvider.NATIVE:
            try:
                oauth_params = {
                    "response_type": response_type,
                    "client_id": client_id,
                    "redirect_uri": redirect_uri,
                    "scope": scope,
                    "state": state,
                    "code_challenge": code_challenge,
                    "code_challenge_method": code_challenge_method,
                    "audience": audience,
                    "prompt": prompt,
                }
                form_context = {
                    **oauth_params,
                    "application": application,
                    "tenant": tenant,
                    "connection": connection,
                    "password_min_length": MIN_PASSWORD_LENGTH,
                }

                # screen_hint decides which template/flow applies; signup never
                # consults the existing session since it's always a fresh account.
                if screen_hint == ScreenHint.SIGNUP:
                    if request.method == "POST":
                        email = request.form.get("email", "")
                        password = request.form.get("password", "")
                        confirm_password = request.form.get("confirm_password", "")

                        error = None
                        if not valid_email(email):
                            error = "Enter a valid email address."
                        elif not valid_password(password):
                            error = (
                                f"Password must be at least {MIN_PASSWORD_LENGTH} characters "
                                "and include at least 2 of: a capital letter, a digit, a symbol."
                            )
                        elif password != confirm_password:
                            error = "Passwords do not match."
                        elif email_already_registered(email):
                            error = "An account with this email already exists."

                        if error:
                            return render_template(
                                "signup.html",
                                title="Sign Up",
                                **form_context,
                                error=error,
                                email=email,
                            ), 400

                        user = register_user(email, password, tenant.id)
                        return _issue_auth_code(oauth_params, user, connection)

                    return render_template(
                        "signup.html", title="Sign Up", **form_context
                    )

                if prompt != Prompt.LOGIN and is_valid_session():
                    session_id = request.cookies.get(SESSION_COOKIE_NAME)
                    session = get_session_from_session_id(session_id)
                    user = get_user_from_user_id(session.user_id)
                    if not user:
                        raise SessionUserNotFoundError(session_id)
                    return _issue_auth_code(oauth_params, user, connection)

                if request.method == "POST":
                    username = request.form.get("username", "")
                    password = request.form.get("password", "")
                    user = authenticate_user(username, password)

                    if not user:
                        return render_template(
                            "login.html",
                            title="Log In",
                            **form_context,
                            error="Incorrect username or password.",
                            username=username,
                        ), 401

                    return _issue_auth_code(oauth_params, user, connection)

                return render_template("login.html", title="Log In", **form_context)
            except SessionUserNotFoundError:
                response = make_response(
                    render_template("login.html", title="Log In", **form_context)
                )
                return end_session(response, session_id)
        case IdentityProvider.GOOGLE:
            if prompt != Prompt.LOGIN and is_valid_session():
                session_id = request.cookies.get(SESSION_COOKIE_NAME)
                session = get_session_from_session_id(session_id)
                user = get_user_from_user_id(session.user_id)
                if user:
                    oauth_params = {
                        "response_type": response_type,
                        "client_id": client_id,
                        "redirect_uri": redirect_uri,
                        "scope": scope,
                        "state": state,
                        "code_challenge": code_challenge,
                        "code_challenge_method": code_challenge_method,
                        "audience": audience,
                    }
                    return _issue_auth_code(oauth_params, user, connection)

            server_state = prepare_redirect_to_oauth_server(
                {
                    "state": state,
                    "redirect_uri": redirect_uri,
                    "code_challenge_method": code_challenge_method,
                    "code_challenge": code_challenge,
                    "scope": scope,
                    "client_id": client_id,
                    "response_type": response_type,
                    "audience": audience,
                    "prompt": prompt,
                }
            )
            open_id_scope = retrieve_open_id_scope(scope)
            params = {
                "client_id": GOOGLE_CLIENT_ID,
                "redirect_uri": GOOGLE_REDIRECT_URI,
                "response_type": "code",
                "scope": open_id_scope,
                "state": server_state,
            }
            params["prompt"] = prompt if prompt else Prompt.SELECT_ACCOUNT
            return redirect(build_encoded_url(GOOGLE_AUTHORIZATION_ENDPOINT, params))
        case IdentityProvider.GITHUB:
            if prompt != Prompt.LOGIN and is_valid_session():
                session_id = request.cookies.get(SESSION_COOKIE_NAME)
                session = get_session_from_session_id(session_id)
                user = get_user_from_user_id(session.user_id)
                if user:
                    oauth_params = {
                        "response_type": response_type,
                        "client_id": client_id,
                        "redirect_uri": redirect_uri,
                        "scope": scope,
                        "state": state,
                        "code_challenge": code_challenge,
                        "code_challenge_method": code_challenge_method,
                        "audience": audience,
                    }
                    return _issue_auth_code(oauth_params, user, connection)

            server_state = prepare_redirect_to_oauth_server(
                {
                    "state": state,
                    "redirect_uri": redirect_uri,
                    "code_challenge_method": code_challenge_method,
                    "code_challenge": code_challenge,
                    "scope": scope,
                    "client_id": client_id,
                    "response_type": response_type,
                    "audience": audience,
                }
            )
            # Force select_account for End-User convenience. Also matches google-oauth2 UX on signout. If external provider session is still active it interrupts the End-User to choose their account giving better insight into the fact they did logout from the Authorization server's session
            params = {
                "client_id": GITHUB_CLIENT_ID,
                "redirect_uri": GITHUB_REDIRECT_URI,
                "state": server_state,
                "scope": GITHUB_SCOPE,
                "prompt": Prompt.SELECT_ACCOUNT,
            }
            return redirect(build_encoded_url(GITHUB_AUTHORIZATION_ENDPOINT, params))
        case _:
            return redirect_with_error(
                redirect_uri,
                error="invalid_authorization",
                error_description="connection is not available",
                state=state,
            )
