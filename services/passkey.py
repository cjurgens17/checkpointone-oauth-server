import secrets


def generate_passkey_user_handle():
    return secrets.token_bytes(32)