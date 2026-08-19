from enum import StrEnum

VALID_OPEN_ID_SCOPE = ["openid", "profile", "email", "address", "phone"]


class GrantType(StrEnum):
    CODE_FLOW = "authorization_code"
    CONFIDENTIAL = "client_credentials"


class ClientType:
    WEB_APPLICATION = "Web Application"
    USER_AGENT = "User Agent"
    NATIVE = "Native"

class IdentityProvider(StrEnum):
    NATIVE = "Username-Password-Authentication"
    GOOGLE = "google-oauth2"
    FACEBOOK = "facebook"
    GITHUB = "github"
    CHECK_POINT_ONE = "cp1"

class ScreenHint:
    LOGIN = "login"
    SIGNUP = "signup"

SCREEN_HINTS = [ScreenHint.LOGIN, ScreenHint.SIGNUP]

class Prompt:
    LOGIN = "login"
    NONE = "none"
    CONSENT = "consent"
    SELECT_ACCOUNT = "select_account"

NATIVE_PROMPTS = [Prompt.NONE, Prompt.LOGIN, Prompt.SELECT_ACCOUNT, Prompt.CONSENT]
GOOGLE_PROMPTS = [Prompt.CONSENT, Prompt.NONE, Prompt.SELECT_ACCOUNT]

