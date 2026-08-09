from sqlalchemy import select

from database import SessionLocal
from models.tenant import Tenant


def get_tenant_by_slug(slug: str) -> Tenant | None:
    if not slug:
        return None
    with SessionLocal() as session:
        stmt = select(Tenant).where(Tenant.slug == slug)
        return session.scalars(stmt).first()
