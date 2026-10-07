
from model_security.config import (
    MODEL_POLICIES,
    ROLE_PERMISSIONS,
)

def has_permission(
    role: str,
    permission: str,
) -> bool:

    permissions = ROLE_PERMISSIONS.get(role, set())

    return permission in permissions


def can_use_model(
    role: str,
    model_name: str,
) -> bool:

    policy = MODEL_POLICIES.get(model_name)

    if not policy:
        return False

    return role in policy["allowed_roles"]


def get_model_policy(model_name: str):
    return MODEL_POLICIES.get(model_name)