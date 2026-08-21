import json
from typing import Any

from utility.redis.client import redis_client

# Current Cache consist of state, authorization codes, resource owner arguments - all short lived so far
DEFAULT_TTL_SECONDS = 900


def cache_set(key: str, value: Any, ttl: int = DEFAULT_TTL_SECONDS) -> None:
    redis_client.set(key, json.dumps(value), ex=ttl)


def cache_get(key: str) -> Any | None:
    raw = redis_client.get(key)
    if raw is None:
        return None
    return json.loads(raw)


def cache_delete(key: str) -> None:
    redis_client.delete(key)
