from repo.user import get_user_from_email
from utility.helpers import hash_sha256


def authenticate_user_success(email: str, password: str):
    if not email or not password:
        return False
    
    user = get_user_from_email(email)

    if not user:
        return False
    verified = user.password == hash_sha256(password)
    print(f"Verified: {verified}")
    return verified
    