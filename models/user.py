from sqlalchemy import CheckConstraint, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint(
            "connection != 'Username-Password-Authentication' OR password IS NOT NULL",
            name="ck_users_password_required_for_username_password_auth",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(255))
    email: Mapped[str] = mapped_column(String(255), index=True, unique=True)
    email_verified: Mapped[bool] = mapped_column(nullable=True)
    name: Mapped[str] = mapped_column(String(255), nullable=True)
    family_name: Mapped[str] = mapped_column(String(255), nullable=True)
    given_name: Mapped[str] = mapped_column(String(255), nullable=True)
    middle_name: Mapped[str] = mapped_column(String(255), nullable=True)
    nickname: Mapped[str] = mapped_column(String(255), nullable=True)
    preferred_username: Mapped[str] = mapped_column(String(255), nullable=True)
    profile: Mapped[str] = mapped_column(String(255), nullable=True)
    picture: Mapped[str] = mapped_column(String(255), nullable=True)
    website: Mapped[str] = mapped_column(String(255), nullable=True)
    gender: Mapped[str] = mapped_column(String(255), nullable=True)
    birthdate: Mapped[str] = mapped_column(String(10), nullable=True)
    zoneinfo: Mapped[str] = mapped_column(String(255), nullable=True)
    locale: Mapped[str] = mapped_column(String(255), nullable=True)
    updated_at: Mapped[int] = mapped_column(Integer, nullable=True)
    phone_number: Mapped[str] = mapped_column(String(32), nullable=True)
    phone_number_verified: Mapped[bool] = mapped_column(nullable=True)
    address: Mapped[dict] = mapped_column(JSONB, nullable=True)
    sub: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    connection: Mapped[str] = mapped_column(String(64))
    password: Mapped[str] = mapped_column(String(255), nullable=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenant.id"))
    user_id: Mapped[str] = mapped_column(String(326), unique=True, index=True)
