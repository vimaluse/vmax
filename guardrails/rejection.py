def get_guardrail_rejection_message(guard_result):
    detections = getattr(guard_result, "detections", []) or []
    reasons = getattr(guard_result, "reasons", []) or []

    detection_types = {
        str(detection.get("type", "")).lower()
        for detection in detections
        if isinstance(detection, dict) and detection.get("type")
    }

    reason_text = " ".join(
        str(reason).lower()
        for reason in reasons
    )

    if (
        "prompt_injection" in detection_types
        or "prompt injection" in reason_text
    ):
        return (
            "I can't process requests that attempt to override "
            "or manipulate my instructions."
        )

    if (
        "jailbreak" in detection_types
        or "jailbreak" in reason_text
    ):
        return (
            "I can't comply with attempts to bypass "
            "the chatbot's safety restrictions."
        )

    if (
        "secret" in detection_types
        or "credential" in detection_types
        or "api_key" in detection_types
        or "secret" in reason_text
        or "credential" in reason_text
        or "api key" in reason_text
    ):
        return (
            "I can't process or expose credentials, API keys, "
            "passwords, or other secrets."
        )

    if (
        "pii" in detection_types
        or "personal_information" in detection_types
        or "personal information" in reason_text
    ):
        return (
            "This request contains sensitive personal information. "
            "Please remove the sensitive information and try again."
        )

    if (
        "toxicity" in detection_types
        or "toxic" in detection_types
        or "toxicity" in reason_text
    ):
        return "I can't assist with harmful or abusive content."

    if len(detection_types) > 1:
        return (
            "I can't process this request because it triggered "
            "multiple safety protections."
        )

    return (
        "I can't process this request because it triggered "
        "an AI safety protection."
    )