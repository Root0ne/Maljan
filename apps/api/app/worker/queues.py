"""What the two worker processes agree on: the queues and how to reach Redis.

``analysis_worker`` imports ``enrich_worker`` to register its task, so anything
both need lives here rather than in either of them.
"""

from __future__ import annotations

from urllib.parse import urlparse

from arq.connections import RedisSettings
from arq.constants import default_queue_name

# The queue each worker reads. The analyses stay on arq's default queue — the
# name every existing deployment's Redis already holds — and the enrichment
# gets one of its own, named after it so an operator listing keys sees the two
# side by side.
ANALYSIS_QUEUE = default_queue_name
ENRICHMENT_QUEUE = f"{default_queue_name}:enrichment"


def build_redis_settings(redis_url: str) -> RedisSettings:
    """Build arq's RedisSettings from a redis:// URL, credentials included.

    ``redis://:${REDIS_PASSWORD}@redis:6379/0`` (the compose default once Redis
    runs with --requirepass) carries a password. arq's own ``RedisSettings.
    from_dsn`` parses that password correctly; the bug this function fixed
    was in ``WorkerSettings``'s previous hand-rolled URL parsing, which
    dropped it — every queue command the worker issued then came back NOAUTH
    against a password-protected Redis.
    """
    parsed = urlparse(redis_url)
    return RedisSettings(
        host=parsed.hostname or "localhost",
        port=parsed.port or 6379,
        database=int((parsed.path or "/0").strip("/") or 0),
        username=parsed.username or None,
        password=parsed.password or None,
    )
