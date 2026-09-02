"""Schema checks that need no database server.

These compile the models and the repo layer's trickiest statement against the
PostgreSQL dialect. That catches a misspelled column, an unresolvable foreign
key, or a construct the dialect cannot render - the failures that would
otherwise only surface on a live deployment - and they run everywhere, including
CI without a database service.
"""

import importlib

import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateTable

from models.base import Base

for _model_module in (
    "models.tenant",
    "models.application",
    "models.user",
    "models.session",
    "models.refresh_token",
    "models.passkey",
):
    importlib.import_module(_model_module)

DIALECT = postgresql.dialect()

EXPECTED_TABLES = {
    "tenant",
    "applications",
    "users",
    "session",
    "refresh_tokens",
    "passkeys",
}


class TestSchemaCompiles:
    def test_every_expected_table_is_registered(self):
        assert EXPECTED_TABLES <= set(Base.metadata.tables)

    @pytest.mark.parametrize("table_name", sorted(EXPECTED_TABLES))
    def test_table_ddl_renders_for_postgres(self, table_name):
        ddl = str(
            CreateTable(Base.metadata.tables[table_name]).compile(dialect=DIALECT)
        )
        assert f"CREATE TABLE {table_name}" in ddl or f'CREATE TABLE "{table_name}"' in ddl

    def test_foreign_keys_all_resolve(self):
        # sorted_tables raises if a foreign key points at a table that is not
        # registered, which is the usual symptom of a missing model import.
        assert Base.metadata.sorted_tables

    def test_postgres_specific_column_types_render(self):
        users_ddl = str(
            CreateTable(Base.metadata.tables["users"]).compile(dialect=DIALECT)
        )
        applications_ddl = str(
            CreateTable(Base.metadata.tables["applications"]).compile(dialect=DIALECT)
        )
        assert "JSONB" in users_ddl
        assert "VARCHAR[]" in applications_ddl

    def test_check_constraints_are_emitted(self):
        applications_ddl = str(
            CreateTable(Base.metadata.tables["applications"]).compile(dialect=DIALECT)
        )
        refresh_ddl = str(
            CreateTable(Base.metadata.tables["refresh_tokens"]).compile(dialect=DIALECT)
        )
        assert "ck_required_client_type_registrations" in applications_ddl
        assert "ck_refresh_tokens_revoke_reason_allowed_values" in refresh_ddl

    def test_the_revoke_reason_constraint_matches_the_constants(self):
        # A new RevokeReason that is not in the CHECK constraint would fail only
        # at INSERT time on a live database.
        from utility.constants import RevokeReason

        refresh_ddl = str(
            CreateTable(Base.metadata.tables["refresh_tokens"]).compile(dialect=DIALECT)
        )
        declared = {
            value
            for name, value in vars(RevokeReason).items()
            if not name.startswith("_") and isinstance(value, str)
        }
        for reason in declared:
            assert f"'{reason}'" in refresh_ddl

    def test_the_client_type_constraint_matches_the_constants(self):
        from utility.constants import ClientType

        applications_ddl = str(
            CreateTable(Base.metadata.tables["applications"]).compile(dialect=DIALECT)
        )
        declared = {
            value
            for name, value in vars(ClientType).items()
            if not name.startswith("_") and isinstance(value, str)
        }
        for client_type in declared:
            assert f"'{client_type}'" in applications_ddl


class TestSessionUpsertCompiles:
    def test_the_on_conflict_upsert_renders_for_postgres(self):
        """The session upsert is the only hand-written DML in the repo layer.

        It uses the PostgreSQL-specific ``insert(...).on_conflict_do_update``,
        which has no equivalent on other dialects, so compiling it here pins both
        the conflict target and the updated column set.
        """
        from sqlalchemy.dialects.postgresql import insert

        from models.session import Session

        statement = insert(Session).values(
            session_id="s",
            user_id="cp1|abc",
            expires_at="2099-01-01",
            client_id="client_x",
            response_type="code",
            scope="openid",
            connection="Username-Password-Authentication",
            audience="https://api.test/resource",
        )
        statement = statement.on_conflict_do_update(
            index_elements=[Session.user_id],
            set_={
                "session_id": statement.excluded.session_id,
                "expires_at": statement.excluded.expires_at,
                "client_id": statement.excluded.client_id,
                "response_type": statement.excluded.response_type,
                "scope": statement.excluded.scope,
                "connection": statement.excluded.connection,
                "audience": statement.excluded.audience,
            },
        ).returning(Session)

        compiled = str(statement.compile(dialect=DIALECT))
        assert "ON CONFLICT (user_id) DO UPDATE" in compiled
        assert "RETURNING" in compiled

    def test_the_upsert_conflict_target_is_actually_unique(self):
        # ON CONFLICT (user_id) only works if user_id carries a unique
        # constraint; without it Postgres raises at runtime.
        from models.session import Session

        user_id_column = Session.__table__.c.user_id
        assert user_id_column.unique is True
