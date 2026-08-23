from webauthn.helpers import generate_challenge

from utility.redis.cache import cache_delete, cache_get, cache_set

PASSKEY_CHALLENGE = "passkey:"
PASSKEY_CHALLENGE_TTL = 300 # 5 Minutes is recommended standard from w3c

def generate_challenge_key(challenge):
    return f'{PASSKEY_CHALLENGE}{challenge}'

def set_passkey_challenge():
    challenge = generate_challenge()
    cache_set(generate_challenge_key(challenge), challenge, PASSKEY_CHALLENGE_TTL)

def get_passkey_challenge(challenge):
    return cache_get(generate_challenge_key(challenge))

def delete_passkey_challenge(challenge):
    cache_delete(generate_challenge_key(challenge))

