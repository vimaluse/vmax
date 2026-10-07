
import re
import unicodedata
from typing import Dict, List


# ============================================================
# CONFIGURATION
# ============================================================

TOXICITY_THRESHOLD = 0.60

HIGH_RISK_THRESHOLD = 0.80


# ============================================================
# TOXICITY PATTERNS
# ============================================================

TOXICITY_PATTERNS = {

    # --------------------------------------------------------
    # THREATS / VIOLENCE
    # --------------------------------------------------------

    "threat": [
        r"\b(?:i|we)\s+(?:will|'ll|am going to|are going to)\s+"
        r"(?:kill|murder|shoot|stab|attack|hurt|beat)\b",

        r"\b(?:i|we)\s+(?:will|'ll|am going to|are going to)\s+"
        r"(?:destroy|take you out)\b",

        r"\byou\s+(?:should|need to)\s+die\b",

        r"\bi\s+will\s+find\s+you\b",

        r"\byou\s+are\s+going\s+to\s+die\b",

        r"\b(?:kill|murder|shoot|stab)\s+(?:you|him|her|them)\b",
    ],


    # --------------------------------------------------------
    # SELF-HARM / SUICIDAL LANGUAGE
    # --------------------------------------------------------

    "self_harm": [
        r"\bkill\s+yourself\b",

        r"\bgo\s+die\b",

        r"\bend\s+your\s+life\b",

        r"\btake\s+your\s+own\s+life\b",

        r"\bi\s+(?:want|need|plan)\s+to\s+die\b",

        r"\bi\s+(?:want|need|plan)\s+to\s+kill\s+myself\b",

        r"\bi\s+(?:want|need|plan)\s+to\s+self[-\s]?harm\b",
    ],


    # --------------------------------------------------------
    # INSULTS
    # --------------------------------------------------------

    "insult": [
        r"\bidiot\b",
        r"\bstupid\b",
        r"\bmoron\b",
        r"\bdumb(?:ass)?\b",
        r"\bimbecile\b",
        r"\bincompetent\b",
        r"\bpathetic\b",
        r"\buseless\b",
        r"\bloser\b",
        r"\bclown\b",
        r"\bjackass\b",
        r"\bjerk\b",
    ],


    # --------------------------------------------------------
    # HARASSMENT
    # --------------------------------------------------------

    "harassment": [
        r"\bgo\s+to\s+hell\b",

        r"\bshut\s+(?:up|the\s+hell\s+up)\b",

        r"\bget\s+lost\b",

        r"\bget\s+out\s+of\s+here\b",

        r"\bi\s+hate\s+you\b",

        r"\byou\s+are\s+worthless\b",

        r"\byou\s+are\s+good\s+for\s+nothing\b",

        r"\bno\s+one\s+wants\s+you\b",
    ],


    # --------------------------------------------------------
    # PROFANITY
    # --------------------------------------------------------

    "profanity": [
        r"\bf+u+c+k+\b",
        r"\bs+h+i+t+\b",
        r"\bf+u+c+k+e+r+\b",
        r"\bb+i+t+c+h+\b",
        r"\ba+s+s+h+o+l+e\b",
        r"\bc+r+a+p+\b",
        r"\bd+a+m+n+\b",
    ],


    # --------------------------------------------------------
    # SEXUAL / EXPLICIT LANGUAGE
    # --------------------------------------------------------

    "sexual_explicit": [
        r"\b(?:porn|pornography)\b",
        r"\b(?:xxx)\b",
        r"\b(?:nude|nudes|nudity)\b",
        r"\b(?:explicit\s+sexual)\b",
        r"\b(?:sexual\s+content)\b",
    ],


    # --------------------------------------------------------
    # HATE / DEHUMANIZING LANGUAGE
    # --------------------------------------------------------

    "hate": [
        r"\b(?:racial\s+slur)\b",

        r"\b(?:they|those people)\s+are\s+animals\b",

        r"\b(?:they|those people)\s+are\s+subhuman\b",

        r"\b(?:they|those people)\s+are\s+vermin\b",

        r"\b(?:they|those people)\s+should\s+not\s+exist\b",
    ],


    # --------------------------------------------------------
    # AGGRESSIVE / ABUSIVE COMMANDS
    # --------------------------------------------------------

    "aggression": [
        r"\b(?:shut|shut\s+the)\s+(?:hell\s+)?up\b",

        r"\b(?:get|go)\s+(?:the\s+)?(?:hell|fuck)\s+out\b",

        r"\b(?:drop\s+dead)\b",

        r"\b(?:screw\s+you)\b",
    ],
}


# ============================================================
# CATEGORY WEIGHTS
# ============================================================

CATEGORY_WEIGHTS = {

    "threat": 0.70,

    "self_harm": 0.80,

    "hate": 0.70,

    "harassment": 0.35,

    "insult": 0.25,

    "profanity": 0.15,

    "sexual_explicit": 0.40,

    "aggression": 0.30,
}


# ============================================================
# NORMALIZATION
# ============================================================

def normalize_text(text: str) -> str:
    """
    Normalize Unicode and whitespace before detection.
    """

    if not isinstance(text, str):
        return ""

    # Unicode normalization
    text = unicodedata.normalize("NFKC", text)

    # Remove zero-width characters
    text = re.sub(
        r"[\u200B-\u200D\uFEFF]",
        "",
        text
    )

    # Normalize whitespace
    text = re.sub(
        r"\s+",
        " ",
        text
    )

    return text.strip().lower()


# ============================================================
# OBfuscation DETECTION
# ============================================================

def normalize_obfuscated_text(text: str) -> str:
    """
    Handle simple obfuscation such as:

        i.d.i.o.t
        s-t-u-p-i-d
        f.u.c.k
        k1ll

    This is intentionally conservative.
    """

    result = text.lower()

    # Remove punctuation between letters.

    result = re.sub(
        r"(?<=[a-z])[\W_]+(?=[a-z])",
        "",
        result
    )

    # Common number substitutions.

    replacements = {
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
    }

    for old, new in replacements.items():
        result = result.replace(old, new)

    return result


# ============================================================
# FIND MATCHES
# ============================================================

def _find_category_matches(
    text: str,
    patterns: List[str]
) -> List[str]:

    matches = []

    for pattern in patterns:

        try:

            if re.search(
                pattern,
                text,
                re.IGNORECASE
            ):
                matches.append(pattern)

        except re.error:
            continue

    return matches


# ============================================================
# TOXICITY SCORING
# ============================================================

def score_toxicity(text: str) -> Dict:
    """
    Analyze text for deterministic toxicity indicators.

    Returns:
        score
        categories
        matches
        risk
        detected
        action
    """

    if not isinstance(text, str) or not text.strip():

        return {
            "score": 0.0,
            "detected": False,
            "risk": "low",
            "action": "allow",
            "categories": [],
            "matches": [],
        }


    normalized = normalize_text(text)

    obfuscated = normalize_obfuscated_text(
        normalized
    )


    matches = []
    categories = set()

    total_score = 0.0


    # --------------------------------------------------------
    # Scan normal text
    # --------------------------------------------------------

    for category, patterns in TOXICITY_PATTERNS.items():

        category_matches = _find_category_matches(
            normalized,
            patterns
        )

        if category_matches:

            categories.add(category)

            for pattern in category_matches:

                matches.append({
                    "category": category,
                    "pattern": pattern,
                })

            total_score += (
                CATEGORY_WEIGHTS.get(
                    category,
                    0.20
                )
                * len(category_matches)
            )


    # --------------------------------------------------------
    # Scan obfuscated text
    # --------------------------------------------------------

    if obfuscated != normalized:

        for category, patterns in TOXICITY_PATTERNS.items():

            category_matches = _find_category_matches(
                obfuscated,
                patterns
            )

            for pattern in category_matches:

                # Don't duplicate exact matches.
                if any(
                    item["category"] == category
                    and item["pattern"] == pattern
                    for item in matches
                ):
                    continue

                categories.add(category)

                matches.append({
                    "category": category,
                    "pattern": pattern,
                    "obfuscated": True,
                })

                total_score += (
                    CATEGORY_WEIGHTS.get(
                        category,
                        0.20
                    )
                    * 0.75
                )


    # --------------------------------------------------------
    # Cap score
    # --------------------------------------------------------

    score = min(
        1.0,
        round(total_score, 3)
    )


    # --------------------------------------------------------
    # Risk classification
    # --------------------------------------------------------

    if score >= HIGH_RISK_THRESHOLD:

        risk = "high"

    elif score >= TOXICITY_THRESHOLD:

        risk = "medium"

    else:

        risk = "low"


    # --------------------------------------------------------
    # Action
    # --------------------------------------------------------

    if score >= HIGH_RISK_THRESHOLD:

        action = "block"

    elif score >= TOXICITY_THRESHOLD:

        action = "review"

    else:

        action = "allow"


    return {
        "score": score,
        "detected": score >= TOXICITY_THRESHOLD,
        "risk": risk,
        "action": action,
        "categories": sorted(categories),
        "matches": matches,
    }


# ============================================================
# SIMPLE BOOLEAN CHECK
# ============================================================

def is_toxic(text: str) -> bool:
    """
    Simple helper for the FastAPI pipeline.
    """

    result = score_toxicity(text)

    return result["detected"]


# ============================================================
# SAFE TEXT FILTER
# ============================================================

def guard_toxicity(text: str) -> Dict:
    """
    Run toxicity detection and return a complete
    guardrail decision.
    """

    result = score_toxicity(text)

    if result["action"] == "block":

        return {
            "allowed": False,
            "text": None,
            "result": result,
        }


    if result["action"] == "review":

        return {
            "allowed": False,
            "text": None,
            "result": result,
        }


    return {
        "allowed": True,
        "text": text,
        "result": result,
    }
