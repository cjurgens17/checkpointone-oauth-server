from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base

if TYPE_CHECKING:
    from .tenant import Tenant


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
    email: Mapped[str] = mapped_column(String(255))
    sub: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    connection: Mapped[str] = mapped_column(String(64))
    password: Mapped[str] = mapped_column(String(255), nullable=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenant.id"))

    tenant: Mapped["Tenant"] = relationship(back_populates="users")
