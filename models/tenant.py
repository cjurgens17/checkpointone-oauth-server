from typing import TYPE_CHECKING

from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base

if TYPE_CHECKING:
    from .application import Application
    from .user import User


class Tenant(Base):
    __tablename__ = "tenant"

    id: Mapped[int] = mapped_column(primary_key=True)
    slug: Mapped[str] = mapped_column(String(255), unique=True, index=True)

    users: Mapped[list["User"]] = relationship(back_populates="tenant")
    applications: Mapped[list["Application"]] = relationship(back_populates="tenant")
