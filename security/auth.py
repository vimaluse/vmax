
import os
import json
import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
import redis

from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBearer,
)


# ============================================================
# CONFIGURATION
# ============================================================

SECRET_KEY = os.getenv(
    "JWT_SECRET_KEY",
    "CHANGE_THIS_TO_A_LONG_RANDOM_SECRET",
)

ALGORITHM = "HS256"

ACCESS_TOKEN_EXPIRE_MINUTES = int(
    os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15")
)

REFRESH_TOKEN_EXPIRE_DAYS = int(
    os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "30")
)

REDIS_URL = os.getenv(
    "REDIS_URL",
    "redis://localhost:6379/0",
)

REFRESH_TOKEN_PREFIX = "auth:refresh:"

security = HTTPBearer(auto_error=False)


# ============================================================
# USER MODEL
# ============================================================

@dataclass
class User:
    user_id: str
    username: str
    role: str


# ============================================================
# REDIS CONNECTION
# ============================================================

_redis_client = None


def get_redis_client():
    global _redis_client

    if _redis_client is None:
        _redis_client = redis.Redis.from_url(
            REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=3,
            socket_timeout=3,
            health_check_interval=30,
        )

    return _redis_client


def refresh_token_key(token: str) -> str:
    token_hash = hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()

    return REFRESH_TOKEN_PREFIX + token_hash


# ============================================================
# PASSWORD
# ============================================================

def hash_password(password: str) -> str:
    password_bytes = password.encode("utf-8")

    if len(password_bytes) > 72:
        raise ValueError(
            "Password cannot be longer than 72 bytes."
        )

    hashed = bcrypt.hashpw(
        password_bytes,
        bcrypt.gensalt(),
    )

    return hashed.decode("utf-8")


def verify_password(
    plain_password: str,
    password_hash: str,
) -> bool:

    password_bytes = plain_password.encode("utf-8")

    if len(password_bytes) > 72:
        return False

    try:
        return bcrypt.checkpw(
            password_bytes,
            password_hash.encode("utf-8"),
        )

    except (ValueError, TypeError):
        return False


# ============================================================
# USERS
# ============================================================

USERS = {
    "admin": {
        "user_id": "admin-01",
        "username": "admin",
        "role": "admin",
        "password_hash": hash_password("Admin@123"),
    },

    "supervisor": {
        "user_id": "supervisor-01",
        "username": "supervisor",
        "role": "supervisor",
        "password_hash": hash_password("Supervisor@123"),
    },

    "user": {
        "user_id": "user-01",
        "username": "user",
        "role": "user",
        "password_hash": hash_password("User@123"),
    },
}


# ============================================================
# LOGIN
# ============================================================

def authenticate_user(
    username: str,
    password: str,
) -> Optional[User]:

    user_data = USERS.get(username)

    if not user_data:
        return None

    if not verify_password(
        password,
        user_data["password_hash"],
    ):
        return None

    return User(
        user_id=user_data["user_id"],
        username=user_data["username"],
        role=user_data["role"],
    )


# ============================================================
# ACCESS TOKEN
# ============================================================

def create_access_token(user: User) -> str:

    now = datetime.now(timezone.utc)

    expire = now + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )

    payload = {
        "sub": user.user_id,
        "username": user.username,
        "role": user.role,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }

    return jwt.encode(
        payload,
        SECRET_KEY,
        algorithm=ALGORITHM,
    )


# ============================================================
# REFRESH TOKEN
# ============================================================

def create_refresh_token(user: User) -> str:

    token = secrets.token_urlsafe(48)

    session_data = {
        "user_id": user.user_id,
        "username": user.username,
        "role": user.role,
    }

    client = get_redis_client()

    client.set(
        refresh_token_key(token),
        json.dumps(session_data),
        ex=REFRESH_TOKEN_EXPIRE_DAYS * 86400,
    )

    return token


def consume_refresh_token(token: str) -> Optional[User]:
    """
    Atomically consume a refresh token.

    A token can only be used once.
    """

    if not token or len(token) > 512:
        return None

    client = get_redis_client()

    stored_data = client.getdel(
        refresh_token_key(token)
    )

    if not stored_data:
        return None

    try:
        session = json.loads(stored_data)

        username = session.get("username")
        user_id = session.get("user_id")
        role = session.get("role")

        user_data = USERS.get(username)

        if not user_data:
            return None

        if user_data["user_id"] != user_id:
            return None

        if user_data["role"] != role:
            return None

        return User(
            user_id=user_id,
            username=username,
            role=role,
        )

    except (ValueError, TypeError, AttributeError):
        return None


def revoke_refresh_token(token: str) -> None:

    if not token or len(token) > 512:
        return

    get_redis_client().delete(
        refresh_token_key(token)
    )


# ============================================================
# CURRENT USER
# ============================================================

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(
        security
    ),
) -> User:

    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = jwt.decode(
            credentials.credentials,
            SECRET_KEY,
            algorithms=[ALGORITHM],
        )

        user_id = payload.get("sub")
        username = payload.get("username")
        role = payload.get("role")

        if not user_id or not username or not role:
            raise HTTPException(
                status_code=401,
                detail="Invalid authentication token.",
            )

        user_data = USERS.get(username)

        if not user_data:
            raise HTTPException(
                status_code=401,
                detail="User no longer exists.",
            )

        if user_data["user_id"] != user_id:
            raise HTTPException(
                status_code=401,
                detail="Invalid user identity.",
            )

        if user_data["role"] != role:
            raise HTTPException(
                status_code=401,
                detail="Invalid user role.",
            )

        return User(
            user_id=user_id,
            username=username,
            role=role,
        )

    except HTTPException:
        raise

    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
