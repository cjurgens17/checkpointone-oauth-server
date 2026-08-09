from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from flask import redirect


def redirect_with_error(redirect_uri, error, error_description=None, state=None):
    params = {"error": error}
    if error_description:
        params["error_description"] = error_description
    if state:
        params["state"] = state

    parts = urlsplit(redirect_uri)
    query = parse_qsl(parts.query, keep_blank_values=True)
    query.extend(params.items())

    error_uri = urlunsplit(parts._replace(query=urlencode(query)))
    return redirect(error_uri)
