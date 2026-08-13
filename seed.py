from werkzeug.security import generate_password_hash

from database import SessionLocal, engine
from models.application import Application
from models.base import Base
from models.tenant import Tenant
from models.user import User
from repo.applications import get_application_from_client_id
from repo.tenants import get_tenant_by_slug
from repo.user import get_user_from_email
from utility.constants import IdentityProvider

SEED_APPLICATION = [
    {
        "client_id": "client_sdlkfj234kdjf2l34",
        "client_secret": "bogus_client_secret_sldkfj234ks90df23lkjsdf092lksdffgj03jsdlkfgj",
        "client_type": "User Agent",
        "name": "CheckPointOne",
        "redirect_uris": ["http://localhost:4200/callback"],
        "permissions": [],
    },
    {
        "client_id": "client_confidential_sdfkj3l4kj",
        "client_secret": "bogus_client_secret_sldkfj0987kjklkjlknlsdldldldldldldldl",
        "client_type": "Web Application",
        "name": "Brute Force",
        "redirect_uris": [],
        "permissions": ["king", "owned", "taken", "sudo", "root", "pwned", "1337"]
    }
]

SEED_USER = [
    {
        "username": "test@checkpointone.com",
        "email": "test@checkpointone.com",
        "sub": f"{IdentityProvider.CHECK_POINT_ONE}|slkj234lksjdfl2",
        "connection": "Username-Password-Authentication",
        "password": generate_password_hash("Password123!"),
        "user_id": f"{IdentityProvider.CHECK_POINT_ONE}|slkj234lksjdfl2"
    }
]

SEED_TENANT = [
    {"slug": "CheckPointOne", "logo_url": "/static/assets/checkpointone_logo.svg"}
]


def seed_database():
    Base.metadata.create_all(engine)
    with SessionLocal() as session:
        tenant = None
        for tenant_data in SEED_TENANT:
            tenant = get_tenant_by_slug(tenant_data["slug"])
            if tenant is None:
                tenant = Tenant(**tenant_data)
                session.add(tenant)
                # Force Insert to get id
                session.flush()
        for application in SEED_APPLICATION:
            if not get_application_from_client_id(application["client_id"]):
                session.add(Application(**application, tenant_id=tenant.id))
        for user in SEED_USER:
            if not get_user_from_email(user["email"]):
                session.add(User(**user, tenant_id=tenant.id))
        session.commit()
