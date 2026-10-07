from .config import DOCUMENT_GUARD_ENABLED
from .result import GuardrailResult
from .pii import mask_pii
from .dlp import detect_dlp, mask_dlp
from .prompt_injection import detect_prompt_injection


def guard_document_text(text, filename=None):
    result = GuardrailResult(text=text)
    if not DOCUMENT_GUARD_ENABLED:
        return result

    current, pii = mask_pii(text)
    if pii:
        result.action = "mask"
        result.reasons.append("PII detected and masked in document content")
        result.detections.extend(pii)

    dlp = detect_dlp(current)
    if dlp:
        current = mask_dlp(current)
        result.action = "mask"
        result.reasons.append("Secret/credential patterns masked in document content")
        result.detections.extend(dlp)

    injection = detect_prompt_injection(current)
    result.metadata["prompt_injection"] = injection
    # Documents should normally remain searchable; do not delete the document merely
    # because it contains instruction-like text. Mark it as untrusted instead.
    if injection["matches"]:
        result.reasons.append("Instruction-like content detected; document remains untrusted data")
        result.metadata["untrusted_content"] = True

    result.text = current
    return result
