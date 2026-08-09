import hashlib


def hash_sha256(value):
    return hashlib.sha256(value.encode()).hexdigest()