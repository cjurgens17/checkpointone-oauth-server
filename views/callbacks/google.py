from flask import Blueprint, request

google_callback_bp = Blueprint("callbacks_google", __name__)


@google_callback_bp.get("/callback/google")
def google_callback():
    params = request.args.to_dict()
    print(f"Received Google OAuth callback: {params}")
    return params
