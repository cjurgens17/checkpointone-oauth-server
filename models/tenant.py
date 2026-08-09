from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class Tenant(Base):
    __tablename__ = "tenant"

    id: Mapped[int] = mapped_column(primary_key=True)
    slug: Mapped[str] = mapped_column(String(255), unique=True, index=True)