from sqlalchemy import select

from database import SessionLocal
from models.application import Application


def get_application_by_client_id(client_id: str) -> Application | None:
    with SessionLocal() as session:
        stmt = select(Application).where(Application.client_id == client_id)
        return session.scalars(stmt).first()


def allowed_redirect_uri(redirect_uri: str, client_id: str) -> bool:
    application = get_application_by_client_id(client_id)
    if application is None:
        return False
    return redirect_uri in application.redirect_uris
