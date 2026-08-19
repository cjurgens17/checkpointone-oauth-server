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
    GITHUB = "github"
    CHECK_POINT_ONE = "cp1" #Used for sub format on user_id when the connection type is Username-Password-Authentication

class ScreenHint:
    LOGIN = "login"
    SIGNUP = "signup"

class Prompt:
    LOGIN = "login"
    NONE = "none"
    CONSENT = "consent"
    SELECT_ACCOUNT = "select_account"
    
SCREEN_HINTS = [ScreenHint.LOGIN, ScreenHint.SIGNUP]
NATIVE_PROMPTS = [Prompt.NONE, Prompt.LOGIN, Prompt.SELECT_ACCOUNT, Prompt.CONSENT]
GOOGLE_PROMPTS = [Prompt.CONSENT, Prompt.NONE, Prompt.SELECT_ACCOUNT]

