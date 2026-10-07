"""
Central AI audit logger.

Writes one structured JSON object per line (JSONL).
The logger is deliberately non-blocking for application availability:
audit failures should never break the chatbot.

Security properties:
- no full prompts/documents/audio are logged by default
- sensitive keys are redacted
- long strings are truncated
- timestamps are UTC
- each event receives a unique event_id
"""

from __future__ import annotations

import json
import os
import re
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_ENABLED = os.getenv("AUDIT_LOG_ENABLED", "true").lower() == "true"
_LOG_PATH = Path(
    os.getenv(
        "AUDIT_LOG_PATH",
        "data/audit/guardrails.jsonl",
    )
)
_MAX_TEXT = int(os.getenv("MAX_AUDIT_TEXT", "500"))

_LOCK = threading.Lock()

_SENSITIVE_KEY_RE = re.compile(
    r"(password|passwd|secret|api[_-]?key|access[_-]?token|"
    r"refresh[_-]?token|authorization|credential|private[_-]?key|"
    r"cookie|session[_-]?id)",
    re.IGNORECASE,
)

_SECRET_VALUE_PATTERNS = [
    # Common bearer/API-key style values.
    (
        re.compile(
            r"(?i)\b(Bearer\s+)[A-Za-z0-9._~+/=-]+"
        ),
        r"\1[REDACTED]",
    ),
    (
        re.compile(
            r"(?i)\b(sk-[A-Za-z0-9_-]{10,})\b"
        ),
        "[REDACTED_API_KEY]",
    ),
    (
        re.compile(
            r"(?i)\b(api[_-]?key|access[_-]?token|secret)"
            r"(\s*[:=]\s*)[^\s,;]+"
        ),
        r"\1\2[REDACTED]",
    ),
]


def _safe_string(value: Any) -> str:
    text = str(value)

    for pattern, replacement in _SECRET_VALUE_PATTERNS:
        text = pattern.sub(replacement, text)

    if len(text) > _MAX_TEXT:
        text = text[:_MAX_TEXT] + "...[TRUNCATED]"

    return text


def _sanitize(value: Any, key: str | None = None) -> Any:
    if key and _SENSITIVE_KEY_RE.search(key):
        return "[REDACTED]"

    if value is None or isinstance(value, (bool, int, float)):
        return value

    if isinstance(value, str):
        return _safe_string(value)

    if isinstance(value, dict):
        return {
            str(k): _sanitize(v, str(k))
            for k, v in value.items()
        }

    if isinstance(value, (list, tuple, set)):
        return [
            _sanitize(item)
            for item in value
        ]

    return _safe_string(value)


def _status(
    action: str | None,
    allowed: bool | None,
) -> str:
    if allowed is False:
        return "blocked"

    if action:
        lowered = str(action).lower()
        if lowered in {
            "block",
            "blocked",
            "deny",
            "denied",
            "error",
            "failed",
            "failure",
        }:
            return "blocked" if lowered != "error" else "error"

    return "success"


def audit(
    event_type: str | None = None,
    action: str | None = None,
    allowed: bool | None = None,
    reasons: Any = None,
    metadata: dict[str, Any] | None = None,
    **kwargs: Any,
) -> None:
    """
    Record one audit event.

    Compatible with the existing project call styles:

        audit("file_upload", ...)
        audit(event_type="document_guard", ...)
    """
    if not _ENABLED:
        return

    # Existing code sometimes passes event metadata directly as kwargs.
    event_name = (
        event_type
        or kwargs.pop("event", None)
        or "unknown_event"
    )

    extra = dict(kwargs)

    if metadata is None:
        metadata = {}

    # Keep event-level fields separate from metadata where practical.
    record = {
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
        "event_id": str(uuid.uuid4()),
        "event_type": _safe_string(event_name),
        "action": _safe_string(action or "event"),
        "status": _status(action, allowed),
        "allowed": allowed,
        "reasons": _sanitize(
            reasons if reasons is not None else []
        ),
        "metadata": _sanitize(metadata),
    }

    if extra:
        record["details"] = _sanitize(extra)

    try:
        _LOG_PATH.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        line = json.dumps(
            record,
            ensure_ascii=False,
            separators=(",", ":"),
            default=str,
        )

        # One open/write operation keeps each JSONL event compact.
        with _LOCK:
            with _LOG_PATH.open(
                "a",
                encoding="utf-8",
                newline="\n",
            ) as handle:
                handle.write(line + "\n")

    except Exception as exc:
        # Never allow audit logging to break the chatbot.
        print(
            f"[Audit] Failed to write audit event "
            f"'{event_name}': {exc}"
        )


def get_audit_log_path() -> str:
    """Return the configured audit log path."""
    return str(_LOG_PATH)


def is_audit_enabled() -> bool:
    """Return whether audit logging is enabled."""
    return _ENABLED
