from sqlalchemy import select

from database import SessionLocal
from models.application import Application
from models.tenant import Tenant


def get_application_from_client_id(client_id: str) -> Application | None:
    if not client_id:
        return None
    with SessionLocal() as session:
        stmt = select(Application).where(Application.client_id == client_id)
        return session.scalars(stmt).first()


def allowed_redirect_uri(redirect_uri: str, client_id: str) -> bool:
    application = get_application_from_client_id(client_id)
    if application is None:
        return False
    return redirect_uri in application.redirect_uris


def allowed_logout_uri(logout_uri: str, client_id: str) -> bool:
    application = get_application_from_client_id(client_id)
    if application is None:
        return False
    return logout_uri in application.logout_uris


def get_tenant_from_application(client_id: str):
    if not client_id:
        return None
    with SessionLocal() as session:
        stmt = (
            select(Tenant)
            .join(Application, Application.tenant_id == Tenant.id)
            .where(Application.client_id == client_id)
        )
        return session.scalars(stmt).first()
