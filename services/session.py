import os
from datetime import datetime, timezone

from flask import request

from repo.session import create_session, delete_session, get_session_from_session_id

SESSION_COOKIE_NAME = "cp1_auth"
SESSION_TTL_SECONDS = 60 * 60 * 24
IS_LOCAL_ENV = os.getenv("env", "production") == "local"


def generate_server_session_cookie(
    user_id, client_id, response_type, scope, connection, audience=None, ttl=SESSION_TTL_SECONDS
):

    session = create_session(user_id, ttl, client_id, response_type, scope, connection, audience)

    cookie_options = {
        "max_age": ttl,
        "samesite": "Lax",
        "secure": not IS_LOCAL_ENV,
        "httponly": True,
        "path": "/",
    }

    return SESSION_COOKIE_NAME, session.session_id, cookie_options

def is_valid_session():
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_id:
        return False

    session = get_session_from_session_id(session_id)
    if not session:
        return False

    expires_at = session.expires_at
    #Format timezones for equal comparison
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    else:
        expires_at = expires_at.astimezone(timezone.utc)

    return expires_at > datetime.now(timezone.utc)

def remove_session(session_id):
    delete_session(session_id)

def end_session(response, session_id):
    if session_id:
        remove_session(session_id)
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return response
