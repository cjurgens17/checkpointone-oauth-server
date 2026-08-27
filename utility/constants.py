from enum import StrEnum


class GrantType(StrEnum):
    CODE_FLOW = "authorization_code"
    CONFIDENTIAL = "client_credentials"
    REFRESH = "refresh_token"
    TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"


class ClientType:
    WEB_APPLICATION = "Web Application"
    USER_AGENT = "User Agent"
    NATIVE = "Native"


class IdentityProvider(StrEnum):
    NATIVE = "Username-Password-Authentication"
    GOOGLE = "google-oauth2"
    GITHUB = "github"
    CHECK_POINT_ONE = "cp1"  # Used for sub format on user_id when the connection type is Username-Password-Authentication


class ScreenHint:
    LOGIN = "login"
    SIGNUP = "signup"
    REGISTER_PASSKEY = "passkey"


class Prompt:
    LOGIN = "login"
    NONE = "none"
    CONSENT = "consent"
    SELECT_ACCOUNT = "select_account"


class RevokeReason:
    LOGOUT = "logout"
    ADMIN = "admin_action"
    PASSWORD_CHANGE = "password_change"
    REUSE = "reuse_detected"
    ROTATE = "valid_rotation"

class TokenType(StrEnum):
    _base = "urn:ietf:oauth:params:oauth:token-type:"
    ACCESS = f"{_base}access_token"
    ID = f"{_base}id_token"
    REFRESH = f"{_base}:refresh_token"
    JWT = f"{_base}jwt"
    SAML_1 = f"{_base}saml1"
    SAML_2 = f"{_base}saml2"

VALID_OPEN_ID_SCOPE = ["openid", "profile", "email", "address", "phone"]
SCREEN_HINTS = [ScreenHint.LOGIN, ScreenHint.SIGNUP, ScreenHint.REGISTER_PASSKEY]
NATIVE_PROMPTS = [Prompt.NONE, Prompt.LOGIN, Prompt.SELECT_ACCOUNT, Prompt.CONSENT]
GOOGLE_PROMPTS = [Prompt.CONSENT, Prompt.NONE, Prompt.SELECT_ACCOUNT]
TOKEN_TYPES = [TokenType.ACCESS,TokenType.ID,TokenType.REFRESH,TokenType.JWT,TokenType.SAML_1,TokenType.SAML_2]
