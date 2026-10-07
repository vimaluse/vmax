from model_security.access_control import (
    has_permission,
    can_use_model,
)
from model_security.config import DEFAULT_MODEL


class SecurityDecision:
    def __init__(
        self,
        allowed: bool,
        reasons=None,
    ):
        self.allowed = allowed
        self.reasons = reasons or []


def authorize_chat(
    user,
    model_name: str = DEFAULT_MODEL,
) -> SecurityDecision:

    reasons = []

    if not has_permission(user.role, "chat"):
        reasons.append("chat_permission_denied")

    if not can_use_model(user.role, model_name):
        reasons.append("model_access_denied")

    return SecurityDecision(
        allowed=len(reasons) == 0,
        reasons=reasons,
    )


def authorize_upload(user):

    if not has_permission(user.role, "upload"):
        return SecurityDecision(
            False,
            ["upload_permission_denied"],
        )

    return SecurityDecision(True)


def authorize_delete(user):

    if not has_permission(user.role, "delete"):
        return SecurityDecision(
            False,
            ["delete_permission_denied"],
        )

    return SecurityDecision(True)


def authorize_web_search(user):

    if not has_permission(user.role, "web_search"):
        return SecurityDecision(
            False,
            ["web_search_permission_denied"],
        )

    return SecurityDecision(True)