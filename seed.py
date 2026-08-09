from database import SessionLocal, engine
from models.application import Application
from models.base import Base
from models.tenant import Tenant
from models.user import User
from services.applications import get_application_by_client_id
from services.tenants import get_tenant_by_slug
from services.user import get_user_from_email

SEED_APPLICATION = [
    {
        "client_id": "client_sdlkfj234kdjf2l34",
        "client_secret": "bogus_client_secret_sldkfj234ks90df23lkjsdf092lksdffgj03jsdlkfgj",
        "name": "CheckPointOne",
        "redirect_uris": ["http://localhost:4200/callback"],
        "scope": ["profile", "openid", "email"],
    },
]

SEED_USER = [
    {
        "username": "test@checkpointone.com",
        "email": "test@checkpointone.com",
        "sub": "cp1 | slkj234lksjdfl2",
        "connection": "Username-Password-Authentication",
    }
]

SEED_TENANT = [
    {"slug": "CheckPointOne", "logo_url": "/static/assets/checkpointone_logo.svg"}
]


def seed_database():
    Base.metadata.create_all(engine)
    with SessionLocal() as session:
        for tenant in SEED_TENANT:
            if not get_tenant_by_slug(tenant["slug"]):
                session.add(Tenant(**tenant))
                # Force Insert to get id
                session.flush()
        for application in SEED_APPLICATION:
            if not get_application_by_client_id(application["client_id"]):
                session.add(Application(**application, tenant_id=tenant.id))
        for user in SEED_USER:
            if not get_user_from_email(user["email"]):
                session.add(User(**user), tenant_id=tenant.id)
        session.commit()
