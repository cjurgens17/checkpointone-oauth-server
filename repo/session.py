import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert

from database import SessionLocal
from models.session import Session


def generate_session_id():
    return secrets.token_urlsafe(32)


def generate_session_expiration(ttl):
    return datetime.now(timezone.utc) + timedelta(seconds=ttl)


# Performs an upsert on the user_id
def create_session(
    user_id, ttl, client_id, response_type, scope, connection, audience=None
):
    session_metadata = {
        "session_id": generate_session_id(),
        "user_id": user_id,
        "expires_at": generate_session_expiration(ttl),
        "client_id": client_id,
        "response_type": response_type,
        "scope": scope,
        "connection": connection,
        "audience": audience,
    }
    with SessionLocal() as session:
        stmt = insert(Session).values(**session_metadata)
        stmt = stmt.on_conflict_do_update(
            index_elements=[Session.user_id],
            set_={
                "session_id": stmt.excluded.session_id,
                "expires_at": stmt.excluded.expires_at,
                "client_id": stmt.excluded.client_id,
                "response_type": stmt.excluded.response_type,
                "scope": stmt.excluded.scope,
                "connection": stmt.excluded.connection,
                "audience": stmt.excluded.audience,
            },
        ).returning(Session)
        user_session = session.scalars(stmt).one()
        session.commit()
        return user_session


def get_session_from_session_id(session_id):
    if not session_id:
        return None
    with SessionLocal() as session:
        stmt = select(Session).where(Session.session_id == session_id)
        return session.scalars(stmt).first()


def delete_session(session_id):
    with SessionLocal() as session:
        stmt = select(Session).where(Session.session_id == session_id)
        session_row = session.scalars(stmt).first()
        if session_row is None:
            return
        session.delete(session_row)
        session.commit()
