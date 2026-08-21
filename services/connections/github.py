import os

import requests

GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")
GITHUB_REDIRECT_URI = os.getenv("GITHUB_REDIRECT_URI")
GITHUB_AUTHORIZATION_ENDPOINT = os.getenv("GITHUB_AUTHORIZATION_ENDPOINT")
GITHUB_TOKEN_ENDPOINT = os.getenv("GITHUB_TOKEN_ENDPOINT")
GITHUB_USERINFO = os.getenv("GITHUB_USERINFO")

# GitHub has no OIDC scope model, so we always request the fixed set
GITHUB_SCOPE = "read:user user:email"


def exchange_code_for_access_token(code: str) -> str:
    payload = {
        "code": code,
        "client_id": GITHUB_CLIENT_ID,
        "client_secret": GITHUB_CLIENT_SECRET,
        "redirect_uri": GITHUB_REDIRECT_URI,
        "grant_type": "authorization_code",
    }

    headers = {"Accept": "application/json"}
    response = requests.post(GITHUB_TOKEN_ENDPOINT, data=payload, headers=headers)
    try:
        payload = response.json()
    except Exception as error:
        raise ValueError(f"Github Token Exchange failed: {response.text}") from error
    return payload.get("access_token")


def get_userinfo(access_token: str) -> dict:
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {access_token}",
    }
    response = requests.get(GITHUB_USERINFO, headers=headers)
    try:
        return response.json()
    except Exception as error:
        raise ValueError(f"Github userinfo request failed: {response.text}") from error


def normalize_userinfo_claims(userinfo: dict) -> dict:
    claims = {}
    if userinfo.get("name"):
        claims["name"] = userinfo["name"]
    if userinfo.get("login"):
        claims["preferred_username"] = userinfo["login"]
        claims["nickname"] = userinfo["login"]
    if userinfo.get("avatar_url"):
        claims["picture"] = userinfo["avatar_url"]
    if userinfo.get("html_url"):
        claims["profile"] = userinfo["html_url"]
    if userinfo.get("blog"):
        claims["website"] = userinfo["blog"]
    if userinfo.get("email"):
        claims["email"] = userinfo["email"]
    return claims
