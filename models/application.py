from datetime import datetime

from sqlalchemy import ForeignKey, String
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from .base import Base


class Application(Base):
    __tablename__ = "applications"

    id: Mapped[int] = mapped_column(primary_key=True)
    client_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    client_secret: Mapped[str] = mapped_column(String(255))
    name: Mapped[str] = mapped_column(String(255))
    redirect_uris: Mapped[list[str]] = mapped_column(ARRAY(String))
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    scope: Mapped[list[str]] = mapped_column(ARRAY(String(30)))
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenant.id"))
