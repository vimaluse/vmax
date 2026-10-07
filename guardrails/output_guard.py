from .config import OUTPUT_GUARD_ENABLED, TOXICITY_BLOCK_THRESHOLD
from .result import GuardrailResult
from .pii import mask_pii
from .dlp import detect_dlp, mask_dlp
from .toxicity import score_toxicity


def guard_output(text: str) -> GuardrailResult:
    result = GuardrailResult(text=text)
    if not OUTPUT_GUARD_ENABLED:
        return result

    current, pii = mask_pii(text)
    if pii:
        result.action = "mask"
        result.reasons.append("PII detected and masked from model output")
        result.detections.extend(pii)

    dlp = detect_dlp(current)
    if dlp:
        result.action = "mask"
        result.reasons.append("Secret/credential pattern masked from model output")
        result.detections.extend(dlp)
        current = mask_dlp(current)

    tox = score_toxicity(current)
    result.metadata["toxicity"] = tox
    if tox["score"] >= TOXICITY_BLOCK_THRESHOLD:
        result.allowed = False
        result.action = "block"
        result.reasons.append("Toxicity threshold exceeded in model output")

    result.text = current
    result.risk_score = tox["score"]
    return result
