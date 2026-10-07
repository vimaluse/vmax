from dataclasses import dataclass, field


@dataclass
class DocumentGuardResult:
    allowed: bool
    text: str
    action: str
    reasons: list[str] = field(default_factory=list)


def guard_document_text(
    text: str,
    filename: str = "",
) -> DocumentGuardResult:

    if not text or not text.strip():

        return DocumentGuardResult(
            allowed=True,
            text=text,
            action="allow",
            reasons=[],
        )

    reasons = []

    suspicious_patterns = [
        "ignore previous instructions",
        "ignore all previous instructions",
        "system prompt",
        "developer message",
    ]

    lower_text = text.lower()

    for pattern in suspicious_patterns:

        if pattern in lower_text:

            reasons.append(
                f"Suspicious prompt-injection pattern: {pattern}"
            )

    if reasons:

        return DocumentGuardResult(
            allowed=False,
            text=text,
            action="block",
            reasons=reasons,
        )

    return DocumentGuardResult(
        allowed=True,
        text=text,
        action="allow",
        reasons=[],
    )