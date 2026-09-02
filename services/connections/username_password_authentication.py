import uuid

from werkzeug.security import check_password_hash, generate_password_hash

from repo.user import get_or_create_user_from_user_id, get_user_from_email
from utility.constants import IdentityProvider
from utility.helpers import generate_unique_sub_id

_PROFILE_CLAIM_FIELDS = [
    "name",
    "family_name",
    "given_name",
    "middle_name",
    "nickname",
    "preferred_username",
    "profile",
    "picture",
    "website",
    "gender",
    "birthdate",
    "zoneinfo",
    "locale",
    "phone_number",
    "phone_number_verified",
    "address",
]


def authenticate_user(email: str, password: str):
    if not email or not password:
        return None

    # A Google or GitHub account is stored with password=None. Submitting that
    # address through the native form used to reach check_password_hash(None, ...),
    # which raised and turned the request into a 500 - both a crash and a way to
    # tell a federated account apart from one that does not exist, since a wrong
    # password answers 401. Federated users now fail the same way as everyone else.
    user = get_user_from_email(email)
    if not user or not user.password:
        return None
    if not check_password_hash(user.password, password):
        return None
    return user


def email_already_registered(email: str) -> bool:
    return get_user_from_email(email) is not None


def register_user(email: str, password: str, tenant_id: uuid.UUID):
    user_id = f"{IdentityProvider.CHECK_POINT_ONE}|{generate_unique_sub_id()}"
    return get_or_create_user_from_user_id(
        user_id,
        {
            "username": email,
            "email": email,
            "email_verified": False,
            "connection": IdentityProvider.NATIVE,
            "password": generate_password_hash(password),
            "tenant_id": tenant_id,
            "sub": user_id,
            "user_id": user_id,
        },
    )


def user_claims(user) -> dict:
    claims = {"email": user.email, "email_verified": bool(user.email_verified)}
    for field in _PROFILE_CLAIM_FIELDS:
        value = getattr(user, field, None)
        if value is not None:
            claims[field] = value
    return claims
