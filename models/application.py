import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, ForeignKey, String
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from .base import Base


class Application(Base):
    __tablename__ = "applications"
    __table_args__ = (
        CheckConstraint(
            "client_type IN ('Web Application', 'User Agent', 'Native')",
            name="ck_required_client_type_registrations"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    client_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    client_secret: Mapped[str] = mapped_column(String(255))
    name: Mapped[str] = mapped_column(String(255))
    redirect_uris: Mapped[list[str]] = mapped_column(ARRAY(String))
    logout_uris: Mapped[list[str]] = mapped_column(ARRAY(String))
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    permissions: Mapped[list[str]] = mapped_column(ARRAY(String(30)))
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenant.id"))
    client_type: Mapped[str] = mapped_column(String(32))