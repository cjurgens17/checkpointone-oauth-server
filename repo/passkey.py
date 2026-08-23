from sqlalchemy import select

from database import SessionLocal
from models.passkey import Passkey


def user_has_passkey(user_id):
    with SessionLocal() as session:
        stmt = select(Passkey.id).where(Passkey.user_id == user_id).limit(1)
        return session.scalars(stmt).first() is not None
