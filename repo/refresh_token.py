from datetime import datetime, timezone

from sqlalchemy import UUID, select, update

from database import SessionLocal
from models.refresh_token import RefreshToken


def create_refresh_token(
    sub: str,
    token_hash: str,
    scope: str,
    audience: str,
    client_id: str,
    iat: datetime,
    exp: datetime,
    absolute_exp: datetime,
    family_id: UUID,
    parent_id=None,
):
    refresh_token_metadata = {
        "sub": sub,
        "token_hash": token_hash,
        "scope": scope,
        "audience": audience,
        "client_id": client_id,
        "iat": iat,
        "exp": exp,
        "absolute_exp": absolute_exp,
        "family_id": family_id,
        "parent_id": parent_id,
    }

    with SessionLocal() as session:
        refresh_token = RefreshToken(**refresh_token_metadata)
        session.add(refresh_token)
        session.commit()
        return refresh_token


def get_refresh_token_from_token_hash(token_hash: str):
    if not token_hash:
        return None
    with SessionLocal() as session:
        stmt = select(RefreshToken).where(RefreshToken.token_hash == token_hash)
        return session.scalars(stmt).first()


def update_refresh_token_used_at(token_hash: str, used_at: datetime | None = None):
    if not token_hash:
        return None
    with SessionLocal() as session:
        stmt = (
            select(RefreshToken)
            .where(RefreshToken.token_hash == token_hash)
            .with_for_update()
        )
        refresh_token = session.scalars(stmt).first()
        if refresh_token is None:
            return None
        refresh_token.used_at = used_at or datetime.now(timezone.utc)
        session.commit()
        return refresh_token


def revoke_refresh_token(
    token_hash: str, revoke_reason: str, revoked_at: datetime | None = None
):
    if not token_hash:
        return None
    with SessionLocal() as session:
        stmt = (
            select(RefreshToken)
            .where(RefreshToken.token_hash == token_hash)
            .with_for_update()
        )
        refresh_token = session.scalars(stmt).first()
        if refresh_token is None:
            return None
        refresh_token.revoked_at = revoked_at or datetime.now(timezone.utc)
        refresh_token.revoke_reason = revoke_reason
        session.commit()
        return refresh_token


def revoke_refresh_token_family(
    family_id, revoke_reason: str, revoked_at: datetime | None = None
):
    if not family_id:
        raise ValueError("family_id is required to revoke_refresh_token_family")
    with SessionLocal() as session:
        stmt = (
            update(RefreshToken)
            .where(
                RefreshToken.family_id == family_id, RefreshToken.revoked_at.is_(None)
            )
            .values(
                revoked_at=revoked_at or datetime.now(timezone.utc),
                revoke_reason=revoke_reason,
            )
        )
        session.execute(stmt)
        session.commit()
