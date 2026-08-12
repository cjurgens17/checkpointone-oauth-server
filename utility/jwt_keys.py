import base64
import os

from cryptography.hazmat.primitives import hashes, serialization
from dotenv import load_dotenv
from jwt.algorithms import RSAAlgorithm

load_dotenv()

JWT_PRIVATE_KEY = os.getenv("JWT_PRIVATE_KEY", "").replace("\\n", "\n")

_private_key = serialization.load_pem_private_key(JWT_PRIVATE_KEY.encode(), password=None)
_public_key = _private_key.public_key()

JWT_PUBLIC_KEY = _public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
).decode()

digest = hashes.Hash(hashes.SHA256())
digest.update(JWT_PUBLIC_KEY.encode())
JWT_KEY_ID = base64.urlsafe_b64encode(digest.finalize()).decode().rstrip("=")

JWT_JWK = {
    **RSAAlgorithm.to_jwk(_public_key, as_dict=True),
    "kid": JWT_KEY_ID,
    "use": "sig",
    "alg": "RS256",
}
