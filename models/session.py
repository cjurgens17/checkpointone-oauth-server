from datetime import datetime

from sqlalchemy import ForeignKey, String
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column

from models.base import Base


class Session(Base):
    __tablename__ = "session"

    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[str] = mapped_column(String(64),nullable=False, index=True, unique=True)
    user_id: Mapped[str] = mapped_column(String(326), ForeignKey("users.user_id"), unique=True)
    expires_at: Mapped[datetime] = mapped_column(nullable=False)
    client_id: Mapped[str] = mapped_column(String(64), ForeignKey("applications.client_id"), nullable=False)
    response_type: Mapped[str] = mapped_column(String(16), nullable=False)
    scope: Mapped[str] = mapped_column(String(1200), nullable=False)
    connection: Mapped[str] = mapped_column(String(64), nullable=False)
    audience: Mapped[list[str]] = mapped_column(ARRAY(String(255)), nullable=True)
    
    
