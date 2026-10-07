import base64
import binascii
import html
import re

from typing import Dict, List


# ============================================================
# CONFIGURATION
# ============================================================

PROMPT_INJECTION_THRESHOLD = 0.70
PROMPT_INJECTION_BLOCK_THRESHOLD = 0.70


# ============================================================
# PROMPT INJECTION PATTERNS
# ============================================================

PATTERNS = {

    # --------------------------------------------------------
    # Instruction override
    # --------------------------------------------------------

    "instruction_override": [
        r"\bignore\s+(all|any|the|previous|prior|above|earlier)\s+instructions?\b",
        r"\bdisregard\s+(all|any|the|previous|prior|above|earlier)\s+instructions?\b",
        r"\bforget\s+(all|any|the|previous|prior|above|earlier)\s+instructions?\b",
        r"\boverride\s+(the|all|previous|current)\s+(instructions?|rules?|policy|system\s+prompt)\b",
        r"\bfollow\s+(these|the|my)\s+instructions?\s+instead\b",
        r"\bdo\s+not\s+follow\s+(the|your|previous|system)\s+instructions?\b",
        r"\byour\s+new\s+instructions?\s+(are|is)\b",
        r"\bnew\s+instructions?\s*:",
        r"\breplace\s+(the|your)\s+(instructions?|rules?|system\s+prompt)\b",
        r"\bdisregard\s+your\s+rules\b",
        r"\bignore\s+your\s+rules\b",
        r"\bbypass\s+(the|your)\s+(rules?|restrictions?|safety)\b",
    ],


    # --------------------------------------------------------
    # System prompt manipulation
    # --------------------------------------------------------

    "system_prompt_manipulation": [
        r"\bsystem\s+prompt\b",
        r"\bsystem\s+message\b",
        r"\bsystem\s+instructions?\b",
        r"\bdeveloper\s+message\b",
        r"\bdeveloper\s+instructions?\b",
        r"\bdeveloper\s+prompt\b",
        r"\breveal\s+(the|your)\s+system\s+prompt\b",
        r"\bshow\s+(me\s+)?(the|your)\s+system\s+prompt\b",
        r"\bprint\s+(the|your)\s+system\s+prompt\b",
        r"\bdisplay\s+(the|your)\s+system\s+prompt\b",
        r"\bwhat\s+(is|are)\s+(your|the)\s+system\s+instructions?\b",
    ],


    # --------------------------------------------------------
    # Prompt extraction
    # --------------------------------------------------------

    "prompt_extraction": [
        r"\breveal\s+(your|the)\s+(prompt|instructions?|rules?)\b",
        r"\bshow\s+(your|the)\s+(prompt|instructions?|rules?)\b",
        r"\bprint\s+(your|the)\s+(prompt|instructions?|rules?)\b",
        r"\bdisplay\s+(your|the)\s+(prompt|instructions?|rules?)\b",
        r"\boutput\s+(your|the)\s+(prompt|instructions?|rules?)\b",
        r"\bwhat\s+were\s+you\s+told\b",
        r"\bwhat\s+instructions\s+were\s+you\s+given\b",
        r"\brepeat\s+(your|the)\s+(instructions?|prompt)\b",
        r"\bquote\s+(your|the)\s+(system|developer)\s+(prompt|message)\b",
        r"\bcopy\s+(your|the)\s+(system|developer)\s+(prompt|message)\b",
    ],


    # --------------------------------------------------------
    # Secret / sensitive information extraction
    # --------------------------------------------------------

    "secret_extraction": [
        r"\breveal\s+(all\s+)?secrets?\b",
        r"\bshow\s+(all\s+)?secrets?\b",
        r"\breveal\s+(the\s+)?credentials?\b",
        r"\bshow\s+(the\s+)?credentials?\b",
        r"\breveal\s+(the\s+)?api\s+keys?\b",
        r"\bshow\s+(the\s+)?api\s+keys?\b",
        r"\breveal\s+(the\s+)?passwords?\b",
        r"\bshow\s+(the\s+)?passwords?\b",
        r"\breveal\s+(private|confidential)\s+(information|data)\b",
        r"\bshow\s+(private|confidential)\s+(information|data)\b",
        r"\bexpose\s+(private|confidential|secret)\b",
        r"\bextract\s+(private|confidential|secret)\b",
    ],


    # --------------------------------------------------------
    # Role / identity manipulation
    # --------------------------------------------------------

    "role_manipulation": [
        r"\byou\s+are\s+now\s+(an?|the)\b",
        r"\bact\s+as\s+(an?|the)\b",
        r"\bpretend\s+(to\s+be|you\s+are)\b",
        r"\broleplay\s+as\b",
        r"\bfrom\s+now\s+on\s+you\s+are\b",
        r"\byour\s+role\s+is\s+now\b",
        r"\bforget\s+that\s+you\s+are\s+an?\s+ai\b",
        r"\bpretend\s+you\s+have\s+no\s+restrictions\b",
        r"\bact\s+without\s+restrictions\b",
        r"\bact\s+without\s+rules\b",
    ],


    # --------------------------------------------------------
    # Jailbreak language
    # --------------------------------------------------------

    "jailbreak": [
        r"\bjailbreak\b",
        r"\bbypass\s+safety\b",
        r"\bbypass\s+security\b",
        r"\bdisable\s+safety\b",
        r"\bdisable\s+security\b",
        r"\bremove\s+(all\s+)?restrictions?\b",
        r"\bremove\s+(all\s+)?safety\s+filters?\b",
        r"\bno\s+restrictions?\b",
        r"\bwithout\s+(any\s+)?restrictions?\b",
        r"\bunrestricted\s+mode\b",
        r"\bdeveloper\s+mode\b",
        r"\badmin\s+mode\b",
        r"\bgod\s+mode\b",
    ],


    # --------------------------------------------------------
    # Tool / command execution
    # --------------------------------------------------------

    "command_execution": [
        r"\bexecute\s+(this\s+)?command\b",
        r"\brun\s+(this\s+)?command\b",
        r"\bexecute\s+(this\s+)?code\b",
        r"\brun\s+(this\s+)?code\b",
        r"\bexecute\s+shell\b",
        r"\brun\s+shell\b",
        r"\bexecute\s+terminal\b",
        r"\brun\s+terminal\b",
        r"\bexecute\s+the\s+following\b",
        r"\brun\s+the\s+following\b",
        r"\buse\s+the\s+tool\s+to\b",
        r"\bcall\s+the\s+tool\s+and\b",
        r"\binvoke\s+the\s+tool\s+and\b",
    ],


    # --------------------------------------------------------
    # Credential exfiltration
    # --------------------------------------------------------

    "credential_exfiltration": [
        r"\bsend\s+.*credentials?\b",
        r"\bforward\s+.*credentials?\b",
        r"\bexport\s+.*credentials?\b",
        r"\bemail\s+.*credentials?\b",
        r"\bpost\s+.*credentials?\b",
        r"\bsend\s+.*password\b",
        r"\bsend\s+.*api\s+key\b",
        r"\bexport\s+.*api\s+key\b",
        r"\bcopy\s+.*secret\b",
        r"\btransfer\s+.*secret\b",
    ],


    # --------------------------------------------------------
    # Policy manipulation
    # --------------------------------------------------------

    "policy_manipulation": [
        r"\bignore\s+(the\s+)?safety\s+policy\b",
        r"\bignore\s+(the\s+)?security\s+policy\b",
        r"\bignore\s+(the\s+)?content\s+policy\b",
        r"\bviolate\s+(the\s+)?policy\b",
        r"\bbypass\s+(the\s+)?policy\b",
        r"\boverride\s+(the\s+)?policy\b",
        r"\bpolicy\s+does\s+not\s+apply\b",
        r"\brules\s+do\s+not\s+apply\b",
    ],


    # --------------------------------------------------------
    # Fake authority / authorization
    # --------------------------------------------------------

    "authority_manipulation": [
        r"\bthe\s+admin\s+said\b",
        r"\bthe\s+administrator\s+said\b",
        r"\bthe\s+developer\s+said\b",
        r"\bthe\s+system\s+administrator\s+authorized\b",
        r"\bi\s+am\s+the\s+administrator\b",
        r"\bi\s+am\s+the\s+developer\b",
        r"\bi\s+have\s+admin\s+permission\b",
        r"\bi\s+have\s+developer\s+permission\b",
        r"\bthis\s+is\s+an?\s+authorized\s+request\b",
        r"\bsecurity\s+team\s+approved\s+this\b",
    ],


    # --------------------------------------------------------
    # Instruction delimiter attacks
    # --------------------------------------------------------

    "delimiter_attack": [
        r"<\s*system\s*>",
        r"</\s*system\s*>",
        r"<\s*developer\s*>",
        r"</\s*developer\s*>",
        r"<\s*instruction\s*>",
        r"</\s*instruction\s*>",
        r"\[system\]",
        r"\[/system\]",
        r"\[developer\]",
        r"\[/developer\]",
        r"\[instruction\]",
        r"\[/instruction\]",
        r"###\s*system",
        r"###\s*developer",
        r"###\s*instruction",
    ],


    # --------------------------------------------------------
    # Context manipulation
    # --------------------------------------------------------

    "context_manipulation": [
        r"\bignore\s+the\s+context\b",
        r"\bignore\s+the\s+document\b",
        r"\bignore\s+the\s+retrieved\s+documents?\b",
        r"\bignore\s+the\s+knowledge\s+base\b",
        r"\bdo\s+not\s+use\s+the\s+retrieved\s+information\b",
        r"\bdo\s+not\s+use\s+the\s+knowledge\s+base\b",
        r"\breplace\s+the\s+context\b",
        r"\bmodify\s+the\s+context\b",
        r"\bchange\s+the\s+retrieved\s+information\b",
    ],
}


# ============================================================
# PATTERN WEIGHTS
# ============================================================

CATEGORY_WEIGHTS = {

    "instruction_override": 0.45,

    "system_prompt_manipulation": 0.40,

    "prompt_extraction": 0.45,

    "secret_extraction": 0.50,

    "role_manipulation": 0.30,

    "jailbreak": 0.50,

    "command_execution": 0.45,

    "credential_exfiltration": 0.60,

    "policy_manipulation": 0.45,

    "authority_manipulation": 0.25,

    "delimiter_attack": 0.40,

    "context_manipulation": 0.40,
}


# ============================================================
# TEXT NORMALIZATION
# ============================================================

def _normalize_text(text: str) -> str:
    """
    Normalize user input before detection.

    Handles:
    - HTML entities
    - excessive whitespace
    - unicode whitespace
    - case normalization
    """

    if not text:
        return ""

    text = html.unescape(text)

    text = text.replace(
        "\u200b",
        ""
    )

    text = text.replace(
        "\ufeff",
        ""
    )

    text = re.sub(
        r"\s+",
        " ",
        text
    )

    return text.strip().lower()


# ============================================================
# BASE64 DETECTION
# ============================================================

def _decode_base64_candidates(
    text: str
) -> List[str]:

    decoded = []

    candidates = re.findall(
        r"(?:[A-Za-z0-9+/]{20,}={0,2})",
        text
    )

    for candidate in candidates:

        try:

            raw = base64.b64decode(
                candidate,
                validate=True
            )

            value = raw.decode(
                "utf-8",
                errors="ignore"
            ).strip()

            if value:

                decoded.append(
                    value
                )

        except (
            ValueError,
            UnicodeDecodeError,
            binascii.Error
        ):

            continue

    return decoded


# ============================================================
# OBFUSCATION DETECTION
# ============================================================

def _normalize_obfuscated_text(
    text: str
) -> str:

    """
    Normalize simple obfuscation techniques such as:

    i.g.n.o.r.e
    i-g-n-o-r-e
    i_g_n_o_r_e
    """

    value = text.lower()

    value = re.sub(
        r"(?<=\w)[._\-](?=\w)",
        "",
        value
    )

    return value


# ============================================================
# CATEGORY DETECTION
# ============================================================

def _detect_categories(
    text: str
) -> Dict:

    categories = {}

    for category, patterns in PATTERNS.items():

        matches = []

        for pattern in patterns:

            try:

                if re.search(
                    pattern,
                    text,
                    flags=re.IGNORECASE
                ):

                    matches.append(
                        pattern
                    )

            except re.error:

                continue

        if matches:

            categories[category] = matches

    return categories


# ============================================================
# SCORE CALCULATION
# ============================================================

def _calculate_score(
    categories: Dict,
    obfuscated_detected: bool = False,
    encoded_detected: bool = False
) -> float:

    score = 0.0

    # --------------------------------------------------------
    # Category scores
    # --------------------------------------------------------

    for category in categories:

        score += CATEGORY_WEIGHTS.get(
            category,
            0.25
        )

    # --------------------------------------------------------
    # Multiple attack categories
    # --------------------------------------------------------

    category_count = len(
        categories
    )

    if category_count >= 2:

        score += 0.15

    if category_count >= 3:

        score += 0.15

    # --------------------------------------------------------
    # Obfuscation
    # --------------------------------------------------------

    if obfuscated_detected:

        score += 0.20

    # --------------------------------------------------------
    # Encoded payload
    # --------------------------------------------------------

    if encoded_detected:

        score += 0.25

    return min(
        1.0,
        score
    )


# ============================================================
# MAIN DETECTOR
# ============================================================

def detect_prompt_injection(
    text: str
) -> Dict:
    """
    Detect possible prompt injection attacks.

    Returns:

    {
        "detected": True/False,
        "score": 0.0-1.0,
        "threshold": 0.70,
        "action": "allow"/"block",
        "matches": [],
        "categories": [],
        "encoded_detected": False,
        "obfuscated_detected": False
    }
    """

    if not text:

        return {
            "detected": False,
            "score": 0.0,
            "threshold": PROMPT_INJECTION_THRESHOLD,
            "action": "allow",
            "matches": [],
            "categories": [],
            "encoded_detected": False,
            "obfuscated_detected": False,
        }

    # --------------------------------------------------------
    # Normalize
    # --------------------------------------------------------

    normalized = _normalize_text(
        text
    )

    # --------------------------------------------------------
    # Detect normal patterns
    # --------------------------------------------------------

    categories = _detect_categories(
        normalized
    )

    # --------------------------------------------------------
    # Detect obfuscation
    # --------------------------------------------------------

    obfuscated_text = (
        _normalize_obfuscated_text(
            normalized
        )
    )

    obfuscated_detected = (
        obfuscated_text != normalized
        and bool(
            _detect_categories(
                obfuscated_text
            )
        )
    )

    if obfuscated_detected:

        obfuscated_categories = (
            _detect_categories(
                obfuscated_text
            )
        )

        for category, matches in (
            obfuscated_categories.items()
        ):

            if category not in categories:

                categories[
                    category
                ] = matches

    # --------------------------------------------------------
    # Detect Base64 encoded payloads
    # --------------------------------------------------------

    decoded_candidates = (
        _decode_base64_candidates(
            text
        )
    )

    encoded_detected = False

    for decoded in decoded_candidates:

        decoded_normalized = (
            _normalize_text(
                decoded
            )
        )

        decoded_categories = (
            _detect_categories(
                decoded_normalized
            )
        )

        if decoded_categories:

            encoded_detected = True

            for category, matches in (
                decoded_categories.items()
            ):

                if category not in categories:

                    categories[
                        category
                    ] = matches

    # --------------------------------------------------------
    # Calculate score
    # --------------------------------------------------------

    score = _calculate_score(
        categories=categories,
        obfuscated_detected=obfuscated_detected,
        encoded_detected=encoded_detected
    )

    # --------------------------------------------------------
    # Flatten matches
    # --------------------------------------------------------

    matches = []

    for category, patterns in (
        categories.items()
    ):

        for pattern in patterns:

            matches.append(
                {
                    "category": category,
                    "pattern": pattern,
                }
            )

    # --------------------------------------------------------
    # Determine detection
    # --------------------------------------------------------

    detected = (
        score >= PROMPT_INJECTION_THRESHOLD
    )

    # --------------------------------------------------------
    # Block / allow
    # --------------------------------------------------------

    if score >= PROMPT_INJECTION_BLOCK_THRESHOLD:

        action = "block"

    else:

        action = "allow"

    # --------------------------------------------------------
    # Result
    # --------------------------------------------------------

    return {
        "detected": detected,
        "score": round(
            score,
            3
        ),
        "threshold": PROMPT_INJECTION_THRESHOLD,
        "action": action,
        "matches": matches,
        "categories": list(
            categories.keys()
        ),
        "encoded_detected": encoded_detected,
        "obfuscated_detected": obfuscated_detected,
    }


# ============================================================
# SIMPLE HELPER
# ============================================================

def is_prompt_injection(
    text: str
) -> bool:

    """
    Simple True/False helper.
    """

    result = detect_prompt_injection(
        text
    )

    return result["detected"]