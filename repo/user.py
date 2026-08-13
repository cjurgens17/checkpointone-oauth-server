from sqlalchemy import select

from database import SessionLocal
from models.user import User


def get_user_from_email(email: str):
    if not email:
        return None
    with SessionLocal() as session:
        stmt = select(User).where(User.email == email)
        return session.scalars(stmt).first()


def get_user_from_sub(sub: str):
    if not sub:
        return None
    with SessionLocal() as session:
        stmt = select(User).where(User.sub == sub)
        return session.scalars(stmt).first()

def get_user_from_user_id(user_id: str):
    if not user_id:
        return None
    with SessionLocal() as session:
        stmt = select(User).where(User.user_id == user_id)
        return session.scalars(stmt).first()


def get_or_create_user_from_user_id(user_id: str, defaults: dict):
    with SessionLocal() as session:
        stmt = select(User).where(User.user_id == user_id)
        user = session.scalars(stmt).first()
        if user:
            return user

        user = User(**defaults)
        session.add(user)
        session.commit()
        return user