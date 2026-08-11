from flask import Blueprint, jsonify

from utility.jwt_keys import JWT_JWK

jwks_bp = Blueprint("jwks", __name__)


@jwks_bp.get("/.well-known/jwks.json")
def jwks():
    return jsonify({"keys": [JWT_JWK]})
