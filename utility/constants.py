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
    GIHUB = "github"

