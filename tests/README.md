# Test suite

```bash
pip install -r requirements-dev.txt
pytest                       # everything
pytest --cov --cov-report=term-missing
pytest -m "not integration"  # skip the database tests
```

## Layout

| Path | What it covers | Needs |
|---|---|---|
| `tests/unit/` | `utility/` - validation, helpers, error redirects, Redis cache | nothing |
| `tests/services/` | token minting/verification, sessions, native + federated connections | nothing |
| `tests/resources/` | `POST /oauth/token` - all three grants | nothing |
| `tests/views/` | `/authorize`, callbacks, `/logout`, JWKS, passkey continue | nothing |
| `tests/models/` | schema and DDL compiled against the Postgres dialect | nothing |
| `tests/repo/` | the repo layer against real PostgreSQL | a database |

## The database tests

The repo layer is pure SQL - a Postgres `ON CONFLICT` upsert, `ARRAY` and `JSONB`
columns, `SELECT ... FOR UPDATE`, unique and check constraints. Faking that would
test nothing, and the models cannot even be created on SQLite because `JSONB` has
no SQLite compiler. So these run against a real server or not at all:

```bash
docker compose up -d db
pytest tests/repo/
```

They connect to `checkpointone_test` (created automatically), never the
development database, and every table is emptied between tests. Override the
target with `TEST_DATABASE_URL` if your setup differs. Without a reachable
server the whole package skips with a message saying so, rather than failing.

## How the doubles work

Nothing in this suite reaches the network, a real Redis, or the developer's
`.env`.

- **Signing keys** - `tests/conftest.py` generates a throwaway RSA key per
  session and sets `JWT_PRIVATE_KEY` before any application module is imported.
  Several modules read configuration at import time (`utility.jwt_keys` parses
  the key, `services.connections.google` builds a `PyJWKClient`), so the ordering
  is deliberate. `load_dotenv()` never overrides an existing variable, so these
  values also win over a real `.env`.
- **Redis** - `fakeredis`, patched onto `utility.redis.cache` (the cache module
  binds `redis_client` at import, so patching the client module would miss).
- **Outbound HTTP** - `responses` intercepts the Google and GitHub token and
  userinfo calls.
- **Clock** - `freezegun`, for token lifetimes and cache expiry.
- **Database** - an autouse fixture replaces `SessionLocal` in every repo module
  with something that raises. A unit test that forgets to stub a repo call fails
  immediately and says so, instead of hanging on a TCP connect. Tests marked
  `@pytest.mark.integration` opt out.

Views and resources import their collaborators by name
(`from repo.applications import get_application_from_client_id`), which rebinds
them into the importing module. Stubs therefore patch the **call site**
(`views.authorize.get_application_from_client_id`), not the source module.

## Tests that pin known defects

A few tests assert current, wrong behaviour so a fix is noticed rather than
silently changing an untested contract. Each carries a docstring explaining the
defect and says it should be rewritten once fixed. Search for
`rather than asserting intended behaviour` to find them all.
