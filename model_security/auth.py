from dataclasses import dataclass

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext


# ============================================================
# CONFIGURATION
# ============================================================

SECRET_KEY = "CHANGE_THIS_TO_A_LONG_RANDOM_SECRET"
ALGORITHM = "HS256"

security = HTTPBearer()

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
)


# ============================================================
# USER MODEL
# ============================================================

@dataclass
class User:
    user_id: str
    username: str
    role: str


# ============================================================
# USERS
# ============================================================
#
# IMPORTANT:
# These are demo users.
# Passwords are stored as hashes, NOT plaintext.
#
# Generate real hashes instead of using example hashes.
#

USERS = {
    "admin": {
        "user_id": "admin-01",
        "username": "admin",
        "role": "admin",
        "password_hash": pwd_context.hash("Admin@123"),
    },

    "supervisor": {
        "user_id": "supervisor-01",
        "username": "supervisor",
        "role": "supervisor",
        "password_hash": pwd_context.hash("Supervisor@123"),
    },

    "user": {
        "user_id": "user-01",
        "username": "user",
        "role": "user",
        "password_hash": pwd_context.hash("User@123"),
    },
}


# ============================================================
# PASSWORD
# ============================================================

def verify_password(
    plain_password: str,
    password_hash: str,
) -> bool:

    return pwd_context.verify(
        plain_password,
        password_hash,
    )


# ============================================================
# LOGIN
# ============================================================

def authenticate_user(
    username: str,
    password: str,
):

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
# JWT
# ============================================================

def create_access_token(
    user: User,
) -> str:

    payload = {
        "sub": user.user_id,
        "username": user.username,
        "role": user.role,
    }

    return jwt.encode(
        payload,
        SECRET_KEY,
        algorithm=ALGORITHM,
    )


# ============================================================
# CURRENT USER
# ============================================================

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> User:

    token = credentials.credentials

    try:

        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
        )

        user_id = payload.get("sub")
        username = payload.get("username")
        role = payload.get("role")

        if not user_id or not username or not role:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token.",
            )

        # IMPORTANT:
        # Do not blindly trust the role from the JWT.
        # Verify that the user still exists and that the
        # role matches the server-side record.

        user_data = USERS.get(username)

        if not user_data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User no longer exists.",
            )

        if user_data["user_id"] != user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid user identity.",
            )

        if user_data["role"] != role:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid user role.",
            )

        return User(
            user_id=user_id,
            username=username,
            role=role,
        )

    except JWTError:

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token.",
        )