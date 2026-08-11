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

def valid_scope(scope: str, application_scope: list[str]):
    if not scope:
        return False

    if not _VALID_SCOPE_FORMAT.match(scope):
        return False

    permissions = scope.split(" ")
    #Meta List of allowed scope excluding RBAC because were before authentication(RBAC will be a feature implementation at a later date)
    allowed_scope = set(application_scope).union(VALID_OPEN_ID_SCOPE)
    for permission in permissions:
        if permission not in allowed_scope:
            return False
    return True

def valid_code_challenge_method(method: str):
    return method.lower() == "s256"

def valid_connection(connection: str):
    return connection in _VALID_CONNECTIONS