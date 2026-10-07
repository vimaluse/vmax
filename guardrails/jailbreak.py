import re
import unicodedata
from typing import Dict, List


# ============================================================
# CONFIGURATION
# ============================================================

JAILBREAK_THRESHOLD = 0.60

# Strong indicators
STRONG_PATTERNS = [
    r"\bignore\s+(all|any|the)?\s*(previous|prior|above|earlier)\s+instructions?\b",
    r"\bdisregard\s+(all|any|the)?\s*(previous|prior|above|earlier)\s+instructions?\b",
    r"\bforget\s+(all|any|the)?\s*(previous|prior|above|earlier)\s+instructions?\b",

    r"\bignore\s+your\s+(system|developer|safety)\s+instructions?\b",
    r"\bdisregard\s+your\s+(system|developer|safety)\s+instructions?\b",

    r"\breveal\s+(your|the)\s+(system|developer|hidden)\s+(prompt|instructions?)\b",
    r"\bshow\s+(me\s+)?(your|the)\s+(system|developer|hidden)\s+(prompt|instructions?)\b",

    r"\bwhat\s+is\s+your\s+system\s+prompt\b",
    r"\bprint\s+(your|the)\s+(system|developer)\s+prompt\b",

    r"\bdisable\s+(your|the)\s+(safety|security|guardrails?)\b",
    r"\bbypass\s+(your|the)\s+(safety|security|guardrails?)\b",

    r"\bturn\s+off\s+(your|the)\s+(safety|security|guardrails?)\b",

    r"\byou\s+are\s+now\s+(dan|an?\s+unrestricted|an?\s+unfiltered)\b",

    r"\benter\s+(developer|debug|god|admin|unrestricted)\s+mode\b",

    r"\bactivate\s+(developer|debug|god|admin|unrestricted)\s+mode\b",
]


# Medium-strength indicators
MEDIUM_PATTERNS = [
    r"\bignore\s+(the|your)\s+(rules|policy|policies|guidelines)\b",
    r"\bdisregard\s+(the|your)\s+(rules|policy|policies|guidelines)\b",

    r"\bdo\s+not\s+follow\s+(the|your)\s+(rules|policy|policies)\b",

    r"\bforget\s+(your|the)\s+(rules|policy|policies|guidelines)\b",

    r"\bpretend\s+(you\s+)?(have\s+)?no\s+(rules|restrictions|limitations)\b",

    r"\bact\s+as\s+(an?\s+)?unrestricted\s+(ai|assistant|model)\b",
    r"\bact\s+as\s+(an?\s+)?unfiltered\s+(ai|assistant|model)\b",

    r"\bremove\s+(all\s+)?(restrictions|limitations|safety)\b",

    r"\bno\s+(safety|security)\s+(rules|restrictions|limitations)\b",

    r"\bbypass\s+(the|your)\s+(restrictions|limitations|rules)\b",

    r"\bjailbreak\b",
    r"\bdeveloper\s+mode\b",
    r"\bunrestricted\s+mode\b",
    r"\bunfiltered\s+mode\b",
]


# Prompt-injection style patterns
INJECTION_PATTERNS = [
    r"\bsystem\s*:\s*",
    r"\bdeveloper\s*:\s*",
    r"\bassistant\s*:\s*",
    r"\buser\s*:\s*",

    r"\bnew\s+system\s+message\b",
    r"\bnew\s+developer\s+message\b",

    r"\bfrom\s+now\s+on\b.*\b(ignore|disregard|forget)\b",

    r"\bthe\s+following\s+instructions?\s+(override|replace)\b",

    r"\boverride\s+(the|your)\s+(system|developer|safety)\b",

    r"\breplace\s+(the|your)\s+(system|developer)\s+instructions?\b",
]


# ============================================================
# TEXT NORMALIZATION
# ============================================================

def normalize_text(text: str) -> str:
    """
    Normalize Unicode and whitespace so simple obfuscation
    becomes easier to detect.
    """

    if not text:
        return ""

    # Unicode normalization
    text = unicodedata.normalize("NFKC", text)

    # Convert zero-width characters to nothing
    text = re.sub(r"[\u200B-\u200D\uFEFF]", "", text)

    # Normalize whitespace
    text = re.sub(r"\s+", " ", text)

    return text.strip().lower()


# ============================================================
# PATTERN MATCHING
# ============================================================

def _find_matches(
    text: str,
    patterns: List[str]
) -> List[str]:

    matches = []

    for pattern in patterns:
        try:
            if re.search(pattern, text, re.IGNORECASE):
                matches.append(pattern)
        except re.error:
            continue

    return matches


# ============================================================
# OBFUSCATION DETECTION
# ============================================================

def detect_obfuscation(text: str) -> List[str]:

    matches = []

    # i.g.n.o.r.e
    if re.search(
        r"i[\W_]*g[\W_]*n[\W_]*o[\W_]*r[\W_]*e",
        text,
        re.IGNORECASE
    ):
        matches.append("obfuscated_ignore")

    # j-a-i-l-b-r-e-a-k
    if re.search(
        r"j[\W_]*a[\W_]*i[\W_]*l[\W_]*b[\W_]*r[\W_]*e[\W_]*a[\W_]*k",
        text,
        re.IGNORECASE
    ):
        matches.append("obfuscated_jailbreak")

    # s.y.s.t.e.m
    if re.search(
        r"s[\W_]*y[\W_]*s[\W_]*t[\W_]*e[\W_]*m",
        text,
        re.IGNORECASE
    ):
        matches.append("obfuscated_system")

    return matches


# ============================================================
# MAIN DETECTOR
# ============================================================

def detect_jailbreak(text: str) -> Dict:

    if not isinstance(text, str):
        return {
            "detected": False,
            "score": 0.0,
            "risk": "low",
            "matches": [],
            "categories": []
        }

    if not text.strip():
        return {
            "detected": False,
            "score": 0.0,
            "risk": "low",
            "matches": [],
            "categories": []
        }

    normalized = normalize_text(text)

    strong_matches = _find_matches(
        normalized,
        STRONG_PATTERNS
    )

    medium_matches = _find_matches(
        normalized,
        MEDIUM_PATTERNS
    )

    injection_matches = _find_matches(
        normalized,
        INJECTION_PATTERNS
    )

    obfuscation_matches = detect_obfuscation(normalized)

    # --------------------------------------------------------
    # Calculate score
    # --------------------------------------------------------

    score = 0.0

    score += len(strong_matches) * 0.45
    score += len(medium_matches) * 0.25
    score += len(injection_matches) * 0.30
    score += len(obfuscation_matches) * 0.30

    score = min(1.0, score)

    # --------------------------------------------------------
    # Categories
    # --------------------------------------------------------

    categories = []

    if strong_matches:
        categories.append("instruction_override")

    if medium_matches:
        categories.append("jailbreak")

    if injection_matches:
        categories.append("prompt_injection")

    if obfuscation_matches:
        categories.append("obfuscation")

    # --------------------------------------------------------
    # Risk
    # --------------------------------------------------------

    if score >= 0.75:
        risk = "high"
    elif score >= 0.40:
        risk = "medium"
    else:
        risk = "low"

    detected = score >= JAILBREAK_THRESHOLD

    return {
        "detected": detected,
        "score": round(score, 3),
        "risk": risk,
        "matches": (
            strong_matches
            + medium_matches
            + injection_matches
            + obfuscation_matches
        ),
        "categories": categories
    }