"""Fixtures for the repo layer's integration tests.

The repo layer is the one place where faking the database would test nothing.
Its whole job is SQL: a Postgres ``ON CONFLICT`` upsert, ``ARRAY`` and ``JSONB``
columns, ``SELECT ... FOR UPDATE`` row locks, and unique constraints. Those
behaviours only exist in a real server, and the models cannot even be created on
SQLite (``JSONB`` has no SQLite compiler), so these tests use PostgreSQL or do
not run at all.

Bring one up with the project's own compose file::

    docker compose up -d db

and point the suite at it if the defaults do not match::

    TEST_DATABASE_URL=postgresql+psycopg://user:pass@host:5432/checkpointone_test

The database is created automatically if it is missing, and every table is
truncated between tests so each one starts from a clean slate.
"""

import importlib
import os

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker

from models.base import Base

# Every test in this package needs a live database.
pytestmark = pytest.mark.integration

# Defaults line up with docker-compose.yml, but target a separate database so a
# test run can never truncate development data.
DEFAULT_TEST_DATABASE_URL = (
    "postgresql+psycopg://postgres:postgres@localhost:5433/checkpointone_test"
)

# Importing the models registers them on Base.metadata, which the schema
# creation and the per-test truncation both rely on.
for _model_module in (
    "models.tenant",
    "models.application",
    "models.user",
    "models.session",
    "models.refresh_token",
    "models.passkey",
):
    importlib.import_module(_model_module)

_REPO_MODULES = (
    "repo.applications",
    "repo.passkey",
    "repo.refresh_token",
    "repo.session",
    "repo.tenants",
    "repo.user",
)


def _ensure_database_exists(url: str) -> None:
    """Create the test database if the server is up but the database is absent."""
    from sqlalchemy.engine import make_url

    parsed = make_url(url)
    maintenance = create_engine(
        parsed.set(database="postgres"), isolation_level="AUTOCOMMIT"
    )
    try:
        with maintenance.connect() as connection:
            exists = connection.execute(
                text("SELECT 1 FROM pg_database WHERE datname = :name"),
                {"name": parsed.database},
            ).scalar()
            if not exists:
                connection.execute(text(f'CREATE DATABASE "{parsed.database}"'))
    finally:
        maintenance.dispose()


@pytest.fixture(scope="session")
def engine():
    url = os.getenv("TEST_DATABASE_URL", DEFAULT_TEST_DATABASE_URL)

    try:
        _ensure_database_exists(url)
        candidate = create_engine(url)
        with candidate.connect() as connection:
            connection.execute(text("SELECT 1"))
    except SQLAlchemyError as error:
        pytest.skip(
            f"no PostgreSQL at {url} ({type(error).__name__}); "
            "run `docker compose up -d db` or set TEST_DATABASE_URL",
            allow_module_level=True,
        )

    Base.metadata.create_all(candidate)
    yield candidate
    candidate.dispose()


@pytest.fixture(autouse=True)
def database(engine, monkeypatch):
    """Point every repo module at the test database and clean up afterwards.

    Repo functions open and commit their own sessions, so wrapping a test in an
    outer transaction would not contain them. Truncating after each test is the
    approach that actually isolates them.
    """
    TestSessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

    for module_name in ("database", *_REPO_MODULES):
        monkeypatch.setattr(
            importlib.import_module(module_name), "SessionLocal", TestSessionLocal
        )

    yield TestSessionLocal

    # DELETE rather than TRUNCATE: a test leaves a handful of rows behind, and
    # TRUNCATE's exclusive lock plus file truncation costs roughly 0.7s per table
    # set here, which dominated the runtime. sorted_tables is dependency-ordered,
    # so reversing it deletes children before parents and respects foreign keys.
    with engine.begin() as connection:
        for table in reversed(Base.metadata.sorted_tables):
            connection.execute(table.delete())


@pytest.fixture
def seeded_tenant(database):
    """A persisted tenant, since applications and users both require one."""
    from tests.factories import make_tenant

    tenant = make_tenant()
    with database() as session:
        session.add(tenant)
        session.commit()
        session.refresh(tenant)
    return tenant


@pytest.fixture
def seeded_application(database, seeded_tenant):
    from tests.factories import make_application

    application = make_application(tenant_id=seeded_tenant.id)
    with database() as session:
        session.add(application)
        session.commit()
        session.refresh(application)
    return application


@pytest.fixture
def seeded_user(database, seeded_tenant):
    from tests.factories import make_user

    user = make_user(tenant_id=seeded_tenant.id)
    with database() as session:
        session.add(user)
        session.commit()
        session.refresh(user)
    return user
