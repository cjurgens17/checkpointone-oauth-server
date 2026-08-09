from database import SessionLocal, engine
from models.application import Application
from models.base import Base
from models.tenant import Tenant
from services.applications import get_application_by_client_id
from services.tenants import get_tenant_by_slug

APPLICATION_DEFAULT_SCOPE = ["profile", "openid", "email"]

SEED_TENANT_SLUG = "hackathon"
SEED_TENANT_LOGO_URL = "/static/assets/checkpointone_logo.svg"

SEED_APPLICATIONS = [
    {
        "client_id": "client_sdlkfj234kdjf2l34",
        "client_secret": "bogus_client_secret_sldkfj234ks90df23lkjsdf092lksdffgj03jsdlkfgj",
        "name": "hackathon",
        "redirect_uris": ["http://localhost:4200/callback"],
        "scope": APPLICATION_DEFAULT_SCOPE
    },
]


def seed_applications():
    Base.metadata.create_all(engine)

    with SessionLocal() as session:
        tenant = get_tenant_by_slug(SEED_TENANT_SLUG)
        if tenant is None:
            tenant = Tenant(slug=SEED_TENANT_SLUG, logo_url=SEED_TENANT_LOGO_URL)
            session.add(tenant)
            session.flush()

        for data in SEED_APPLICATIONS:
            if get_application_by_client_id(data["client_id"]):
                continue
            session.add(Application(**data, tenant_id=tenant.id))
        session.commit()
