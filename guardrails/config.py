import os
from dotenv import load_dotenv

load_dotenv()

def _bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}

def _float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except ValueError:
        return default

GUARDRAILS_ENABLED = _bool("GUARDRAILS_ENABLED", True)
PII_MASKING_ENABLED = _bool("PII_MASKING_ENABLED", True)
DLP_ENABLED = _bool("DLP_ENABLED", True)
TOXICITY_ENABLED = _bool("TOXICITY_ENABLED", True)
JAILBREAK_ENABLED = _bool("JAILBREAK_ENABLED", True)
PROMPT_INJECTION_ENABLED = _bool("PROMPT_INJECTION_ENABLED", True)
OUTPUT_GUARD_ENABLED = _bool("OUTPUT_GUARD_ENABLED", True)
DOCUMENT_GUARD_ENABLED = _bool("DOCUMENT_GUARD_ENABLED", True)
AUDIT_LOG_ENABLED = _bool("AUDIT_LOG_ENABLED", True)

TOXICITY_BLOCK_THRESHOLD = _float("TOXICITY_BLOCK_THRESHOLD", 0.75)
JAILBREAK_BLOCK_THRESHOLD = _float("JAILBREAK_BLOCK_THRESHOLD", 0.70)
PROMPT_INJECTION_BLOCK_THRESHOLD = _float("PROMPT_INJECTION_BLOCK_THRESHOLD", 0.70)

# Never log raw secrets/PII by default.
AUDIT_LOG_PATH = os.getenv("AUDIT_LOG_PATH", "data/audit/guardrails.jsonl")
MAX_AUDIT_TEXT = int(os.getenv("MAX_AUDIT_TEXT", "500"))
