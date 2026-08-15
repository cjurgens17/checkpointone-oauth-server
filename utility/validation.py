import re
from urllib.parse import unquote, urlsplit

from utility.constants import VALID_OPEN_ID_SCOPE

# RFC 3986 unreserved + reserved characters, plus "%" for pct-encoded triples.
_ALLOWED_URI_CHARS = re.compile(r"^[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]*$")

# A "%" must always be followed by exactly two hex digits.
_INVALID_PERCENT_ENCODING = re.compile(r"%(?![0-9A-Fa-f]{2})")

# Raw control characters, including CR/LF, must never appear in a URI.
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")

# Scope values must be single-space-separated words with no leading, trailing, or repeated whitespace.
_VALID_SCOPE_FORMAT = re.compile(r"^\S+( \S+)*$")

# Lightweight shape check (local-part@domain.tld) - not full RFC 5322 compliance.
_VALID_EMAIL_FORMAT = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

MIN_PASSWORD_LENGTH = 8

_PASSWORD_HAS_UPPER = re.compile(r"[A-Z]")
_PASSWORD_HAS_DIGIT = re.compile(r"\d")
_PASSWORD_HAS_SYMBOL = re.compile(r"[^A-Za-z0-9]")

_VALID_CONNECTIONS = {"Username-Password-Authentication", "google-oauth2", "facebook", "github", "apple", "windowslive","sms", "email"}


def valid_redirect_uri(redirect_uri: str):
    if not redirect_uri or not isinstance(redirect_uri, str):
        return False

    if _CONTROL_CHARS.search(redirect_uri):
        return False

    if not _ALLOWED_URI_CHARS.match(redirect_uri):
        return False

    if _INVALID_PERCENT_ENCODING.search(redirect_uri):
        return False
    
    try:
        parsed = urlsplit(redirect_uri)
    except ValueError:
        return False

    if not parsed.scheme or not parsed.netloc:
        return False

    return not _CONTROL_CHARS.search(unquote(parsed.query))

def valid_response_type(response_type: str):
    return response_type.lower() in ["code", "token"]

def valid_scope(scope: str, application_permissions: list[str]):
    if not scope:
        return False

    if not _VALID_SCOPE_FORMAT.match(scope):
        return False

    scope_permissions = scope.split(" ")
    openid_scopes = {permission for permission in scope_permissions if permission in VALID_OPEN_ID_SCOPE}
    app_scopes = [permission for permission in scope_permissions if permission not in VALID_OPEN_ID_SCOPE]

    if "openid" not in openid_scopes:
        return False

    #RBAC is not implemented yet(will be a feature implementation at a later date), so app_scopes
    app_permissions = set(application_permissions)
    return all(permission in app_permissions for permission in app_scopes)

def valid_code_challenge_method(method: str):
    return method.lower() == "s256"

def valid_connection(connection: str):
    return connection in _VALID_CONNECTIONS

def valid_email(email: str):
    if not email or not isinstance(email, str):
        return False
    return bool(_VALID_EMAIL_FORMAT.match(email))

def valid_password(password: str):
    if not password or not isinstance(password, str):
        return False
    if len(password) < MIN_PASSWORD_LENGTH:
        return False

    criteria_met = sum([
        bool(_PASSWORD_HAS_UPPER.search(password)),
        bool(_PASSWORD_HAS_DIGIT.search(password)),
        bool(_PASSWORD_HAS_SYMBOL.search(password)),
    ])
    return criteria_met >= 2