from sqlalchemy import select

from database import SessionLocal
from models.user import User


def get_user_from_email(email: str):
    if not email:
        return None
    with SessionLocal() as session:
        stmt = select(User).where(User.email == email)
        return session.scalars(stmt).first()