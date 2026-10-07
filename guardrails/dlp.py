import re
from typing import Dict, List, Tuple


# ============================================================
# CONFIGURATION
# ============================================================

DLP_THRESHOLD = 1

REDACTION_TEMPLATE = "[REDACTED_{TYPE}]"


# ============================================================
# SECRET PATTERNS
# ============================================================

SECRET_PATTERNS = {

    # --------------------------------------------------------
    # API KEYS
    # --------------------------------------------------------

    "openai_api_key": re.compile(
        r"\bsk-[A-Za-z0-9_-]{20,}\b"
    ),

    "google_api_key": re.compile(
        r"\bAIza[0-9A-Za-z_-]{20,}\b"
    ),

    "github_token": re.compile(
        r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"
    ),

    "gitlab_token": re.compile(
        r"\bglpat-[A-Za-z0-9_-]{20,}\b"
    ),

    "slack_token": re.compile(
        r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"
    ),

    "stripe_key": re.compile(
        r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"
    ),

    "sendgrid_api_key": re.compile(
        r"\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b"
    ),


    # --------------------------------------------------------
    # AWS
    # --------------------------------------------------------

    "aws_access_key": re.compile(
        r"\bAKIA[0-9A-Z]{16}\b"
    ),

    "aws_temporary_access_key": re.compile(
        r"\bASIA[0-9A-Z]{16}\b"
    ),

    "aws_secret_key": re.compile(
        r"(?i)\b(?:aws[_-]?)?"
        r"secret[_-]?access[_-]?key\s*[:=]\s*"
        r"[A-Za-z0-9/+=]{30,}"
    ),


    # --------------------------------------------------------
    # PRIVATE KEYS
    # --------------------------------------------------------

    "private_key": re.compile(
        r"-----BEGIN "
        r"(?:RSA |EC |OPENSSH |DSA |PGP )?"
        r"PRIVATE KEY-----"
    ),

    "certificate_private_key": re.compile(
        r"-----BEGIN PRIVATE KEY-----"
    ),


    # --------------------------------------------------------
    # JWT
    # --------------------------------------------------------

    "jwt_token": re.compile(
        r"\beyJ[A-Za-z0-9_-]{5,}\."
        r"[A-Za-z0-9_-]{5,}\."
        r"[A-Za-z0-9_-]{5,}\b"
    ),


    # --------------------------------------------------------
    # BEARER / AUTH TOKENS
    # --------------------------------------------------------

    "bearer_token": re.compile(
        r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{20,}\b"
    ),

    "authorization_token": re.compile(
        r"(?i)\bauthorization\s*[:=]\s*"
        r"(?:bearer\s+)?[A-Za-z0-9._~+/=-]{20,}"
    ),

    "access_token": re.compile(
        r"(?i)\b(?:access[_-]?token|auth[_-]?token)"
        r"\s*[:=]\s*[A-Za-z0-9._~+/=-]{12,}"
    ),

    "refresh_token": re.compile(
        r"(?i)\brefresh[_-]?token"
        r"\s*[:=]\s*[A-Za-z0-9._~+/=-]{12,}"
    ),


    # --------------------------------------------------------
    # PASSWORDS / SECRETS
    # --------------------------------------------------------

    "password_assignment": re.compile(
        r"(?i)\b(?:password|passwd|pwd)"
        r"\s*[:=]\s*"
        r"(?:['\"])?[^\s,'\";]{4,}(?:['\"])?"
    ),

    "secret_assignment": re.compile(
        r"(?i)\b(?:secret|client_secret|app_secret)"
        r"\s*[:=]\s*"
        r"(?:['\"])?[^\s,'\";]{6,}(?:['\"])?"
    ),

    "token_assignment": re.compile(
        r"(?i)\b(?:token|api_token|auth_token)"
        r"\s*[:=]\s*"
        r"(?:['\"])?[A-Za-z0-9._~+/=-]{12,}(?:['\"])?"
    ),


    # --------------------------------------------------------
    # DATABASE CREDENTIALS
    # --------------------------------------------------------

    "database_url": re.compile(
        r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|"
        r"redis|mssql)://"
        r"[^/\s:@]+:"
        r"[^@\s]+@"
        r"[^/\s]+"
    ),

    "database_password": re.compile(
        r"(?i)\b(?:db[_-]?password|database[_-]?password)"
        r"\s*[:=]\s*"
        r"[^\s,;]+"
    ),


    # --------------------------------------------------------
    # CONNECTION STRINGS
    # --------------------------------------------------------

    "connection_string": re.compile(
        r"(?i)\b(?:server|data source|host)\s*="
        r"[^;]+;"
        r"[^;]*(?:password|pwd)\s*="
        r"[^;]+"
    ),


    # --------------------------------------------------------
    # GOOGLE SERVICE ACCOUNT
    # --------------------------------------------------------

    "google_private_key": re.compile(
        r"(?i)\"private_key\"\s*:\s*\"-----BEGIN"
    ),

    "google_client_secret": re.compile(
        r"(?i)\"client_secret\"\s*:\s*\"[^\"]+\""
    ),


    # --------------------------------------------------------
    # EMAIL / PHONE
    # --------------------------------------------------------

    "email": re.compile(
        r"\b[A-Za-z0-9._%+-]+@"
        r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    ),

    "phone_number": re.compile(
        r"(?<!\d)"
        r"(?:\+?\d{1,3}[-.\s]?)?"
        r"(?:\(?\d{2,4}\)?[-.\s]?)?"
        r"\d{3,4}[-.\s]?\d{4}"
        r"(?!\d)"
    ),


    # --------------------------------------------------------
    # IP / NETWORK SECRETS
    # --------------------------------------------------------

    "ipv4_private": re.compile(
        r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
        r"192\.168\.\d{1,3}\.\d{1,3}|"
        r"172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b"
    ),
}


# ============================================================
# HIGH-RISK PATTERNS
# ============================================================

HIGH_RISK_TYPES = {
    "openai_api_key",
    "google_api_key",
    "github_token",
    "gitlab_token",
    "slack_token",
    "stripe_key",
    "sendgrid_api_key",
    "aws_access_key",
    "aws_temporary_access_key",
    "aws_secret_key",
    "private_key",
    "certificate_private_key",
    "jwt_token",
    "bearer_token",
    "authorization_token",
    "access_token",
    "refresh_token",
    "database_url",
    "database_password",
    "connection_string",
    "google_private_key",
    "google_client_secret",
}


# ============================================================
# NORMALIZATION
# ============================================================

def normalize_text(text: str) -> str:
    """
    Normalize text before scanning.
    """

    if not isinstance(text, str):
        return ""

    # Remove null characters
    text = text.replace("\x00", "")

    # Normalize line endings
    text = text.replace("\r\n", "\n")
    text = text.replace("\r", "\n")

    return text


# ============================================================
# DETECT DLP
# ============================================================

def detect_dlp(text: str) -> List[Dict]:
    """
    Detect sensitive information.

    Returns one result per detected type.
    """

    if not text:
        return []

    text = normalize_text(text)

    findings = []

    for kind, pattern in SECRET_PATTERNS.items():

        matches = list(pattern.finditer(text))

        if not matches:
            continue

        # Avoid storing actual secret values.
        findings.append({
            "type": kind,
            "action": "blocked",
            "severity": (
                "high"
                if kind in HIGH_RISK_TYPES
                else "medium"
            ),
            "count": len(matches),
        })

    return findings


# ============================================================
# DETECT WITH POSITIONS
# ============================================================

def detect_dlp_with_positions(
    text: str
) -> List[Dict]:
    """
    Detect sensitive information and return positions.

    Secret values themselves are NOT returned.
    """

    if not text:
        return []

    findings = []

    for kind, pattern in SECRET_PATTERNS.items():

        for match in pattern.finditer(text):

            findings.append({
                "type": kind,
                "severity": (
                    "high"
                    if kind in HIGH_RISK_TYPES
                    else "medium"
                ),
                "start": match.start(),
                "end": match.end(),
                "length": match.end() - match.start(),
            })

    return findings


# ============================================================
# MASK DLP
# ============================================================

def mask_dlp(text: str) -> str:
    """
    Replace detected sensitive information with
    [REDACTED_TYPE].
    """

    if not text:
        return text

    result = normalize_text(text)

    for kind, pattern in SECRET_PATTERNS.items():

        replacement = REDACTION_TEMPLATE.format(
            TYPE=kind.upper()
        )

        result = pattern.sub(
            replacement,
            result
        )

    return result


# ============================================================
# MASK ONLY HIGH-RISK DATA
# ============================================================

def mask_high_risk_dlp(text: str) -> str:
    """
    Mask only credentials and high-risk secrets.
    """

    if not text:
        return text

    result = normalize_text(text)

    for kind in HIGH_RISK_TYPES:

        pattern = SECRET_PATTERNS.get(kind)

        if pattern is None:
            continue

        replacement = REDACTION_TEMPLATE.format(
            TYPE=kind.upper()
        )

        result = pattern.sub(
            replacement,
            result
        )

    return result


# ============================================================
# DLP SUMMARY
# ============================================================

def dlp_summary(text: str) -> Dict:
    """
    Return a high-level DLP decision.
    """

    findings = detect_dlp(text)

    if not findings:
        return {
            "detected": False,
            "blocked": False,
            "risk": "low",
            "count": 0,
            "findings": [],
        }

    high_risk = any(
        item["severity"] == "high"
        for item in findings
    )

    return {
        "detected": True,
        "blocked": True,
        "risk": "high" if high_risk else "medium",
        "count": sum(
            item["count"]
            for item in findings
        ),
        "findings": findings,
    }


# ============================================================
# SAFE PROCESSING FUNCTION
# ============================================================

def guard_dlp(
    text: str,
    mask: bool = True
) -> Tuple[str, Dict]:
    """
    Main DLP entry point.

    Returns:
        processed_text
        dlp_result
    """

    result = dlp_summary(text)

    if not result["detected"]:
        return text, result

    if mask:
        processed_text = mask_dlp(text)
    else:
        processed_text = text

    return processed_text, result
