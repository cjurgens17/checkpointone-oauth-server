import re
from urllib.parse import unquote, urlsplit

# RFC 3986 unreserved + reserved characters, plus "%" for pct-encoded triples.
_ALLOWED_URI_CHARS = re.compile(r"^[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]*$")

# A "%" must always be followed by exactly two hex digits.
_INVALID_PERCENT_ENCODING = re.compile(r"%(?![0-9A-Fa-f]{2})")

# Raw control characters, including CR/LF, must never appear in a URI.
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def valid_redirect_uri(redirect_uri):
    if not redirect_uri or not isinstance(redirect_uri, str):
        return False

    if _CONTROL_CHARS.search(redirect_uri):
        return False

    if not _ALLOWED_URI_CHARS.match(redirect_uri):
        return False

    if _INVALID_PERCENT_ENCODING.search(redirect_uri):
        return False
    
    # Valid:   "https://example.com" -> returns True
    # Invalid: "https://" or "/callback" or "invalid-url" -> returns False
    try:
        parsed = urlsplit(redirect_uri)
    except ValueError:
        return False

    if not parsed.scheme or not parsed.netloc:
        return False

    if _CONTROL_CHARS.search(unquote(parsed.query)):
        return False

    return True

def valid_response_type(response_type):
    return response_type in ["code", "token"]
