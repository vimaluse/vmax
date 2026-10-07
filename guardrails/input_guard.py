from .config import *
from .result import GuardrailResult
from .pii import mask_pii
from .dlp import detect_dlp, mask_dlp
from .toxicity import score_toxicity
from .jailbreak import detect_jailbreak
from .prompt_injection import detect_prompt_injection


def guard_input(text: str, *, mask: bool = True) -> GuardrailResult:
    result = GuardrailResult(text=text)
    if not GUARDRAILS_ENABLED:
        return result

    current = text

    if PII_MASKING_ENABLED and mask:
        current, detections = mask_pii(current)
        result.detections.extend(detections)
        if detections:
            result.action = "mask"
            result.reasons.append("PII detected and masked")

    if DLP_ENABLED:
        dlp = detect_dlp(current)
        if dlp:
            result.allowed = False
            result.action = "block"
            result.reasons.append("Sensitive secret/credential pattern detected")
            result.detections.extend(dlp)

    if TOXICITY_ENABLED:
        tox = score_toxicity(current)
        result.metadata["toxicity"] = tox
        if tox["score"] >= TOXICITY_BLOCK_THRESHOLD:
            result.allowed = False
            result.action = "block"
            result.reasons.append("Toxicity threshold exceeded")

    if JAILBREAK_ENABLED:
        jb = detect_jailbreak(current)
        result.metadata["jailbreak"] = jb
        if jb["score"] >= JAILBREAK_BLOCK_THRESHOLD:
            result.allowed = False
            result.action = "block"
            result.reasons.append("Jailbreak pattern detected")

    if PROMPT_INJECTION_ENABLED:
        pi = detect_prompt_injection(current)
        result.metadata["prompt_injection"] = pi
        if pi["score"] >= PROMPT_INJECTION_BLOCK_THRESHOLD:
            result.allowed = False
            result.action = "block"
            result.reasons.append("Prompt injection pattern detected")

    result.text = current
    result.risk_score = max(
        result.metadata.get("toxicity", {}).get("score", 0),
        result.metadata.get("jailbreak", {}).get("score", 0),
        result.metadata.get("prompt_injection", {}).get("score", 0),
    )
    return result
