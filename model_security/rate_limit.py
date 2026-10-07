import os
import redis


REDIS_URL = os.getenv(
    "REDIS_URL",
    "redis://localhost:6379/0",
)

redis_client = redis.Redis.from_url(
    REDIS_URL,
    decode_responses=True,
)


def check_rate_limit(
    user_id: str,
    limit: int = 20,
    window_seconds: int = 60,
) -> bool:

    key = f"ai_rate_limit:{user_id}"

    count = redis_client.incr(key)

    if count == 1:
        redis_client.expire(
            key,
            window_seconds,
        )

    return count <= limit