import hashlib
import json

import redis


redis_client = redis.Redis(
    host="localhost",
    port=6379,
    db=2,
    decode_responses=True
)


CACHE_TTL = 60 * 60 * 24


def create_cache_key(
    question: str,
    file_ids=None
):

    question = question.strip().lower()

    file_ids = sorted(file_ids or [])

    raw_key = json.dumps(
        {
            "question": question,
            "file_ids": file_ids
        },
        sort_keys=True
    )

    hash_key = hashlib.sha256(
        raw_key.encode("utf-8")
    ).hexdigest()

    return f"chat:{hash_key}"


def get_cached_answer(
    question: str,
    file_ids=None
):

    key = create_cache_key(
        question,
        file_ids
    )

    value = redis_client.get(key)

    if value is None:
        return None

    return json.loads(value)


def save_cached_answer(
    question: str,
    answer: str,
    file_ids=None
):

    key = create_cache_key(
        question,
        file_ids
    )

    data = {
        "answer": answer
    }

    redis_client.setex(
        key,
        CACHE_TTL,
        json.dumps(data)
    )