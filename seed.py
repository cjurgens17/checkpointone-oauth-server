from database import SessionLocal, engine
from models.application import Application
from models.base import Base
from services.applications import get_application_by_client_id

SEED_APPLICATIONS = [
    {
        "client_id": "client_sdlkfj234kdjf2l34",
        "client_secret": "bogus_client_secret_sldkfj234ks90df23lkjsdf092lksdffgj03jsdlkfgj",
        "name": "hackathon",
        "redirect_uris": ["http://localhost:4200/callback"],
    },
]


def seed_applications():
    Base.metadata.create_all(engine)

    with SessionLocal() as session:
        for data in SEED_APPLICATIONS:
            if get_application_by_client_id(data["client_id"]):
                continue
            session.add(Application(**data))
        session.commit()
