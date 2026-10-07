import re

from typing import Dict, List, Tuple


# ============================================================
# CONFIGURATION
# ============================================================

PII_MASK_ENABLED = True


# ============================================================
# REGEX PATTERNS
# ============================================================

PATTERNS = {

    # --------------------------------------------------------
    # EMAIL
    # --------------------------------------------------------

    "email": re.compile(
        r"\b[A-Za-z0-9._%+-]+"
        r"@[A-Za-z0-9.-]+\."
        r"[A-Za-z]{2,}\b",
        re.I,
    ),


    # --------------------------------------------------------
    # PHONE
    # --------------------------------------------------------

    "phone": re.compile(
        r"(?<!\d)"
        r"(?:\+?\d{1,3}[\s.-]?)?"
        r"(?:\(?\d{2,5}\)?[\s.-]?)?"
        r"\d{3,5}[\s.-]?\d{4}"
        r"(?!\d)"
    ),


    # --------------------------------------------------------
    # INDIAN AADHAAR
    # --------------------------------------------------------

    "aadhaar": re.compile(
        r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"
    ),


    # --------------------------------------------------------
    # INDIAN PAN
    # --------------------------------------------------------

    "pan": re.compile(
        r"\b[A-Z]{5}\d{4}[A-Z]\b",
        re.I,
    ),


    # --------------------------------------------------------
    # CREDIT / DEBIT CARD
    # --------------------------------------------------------

    "credit_card": re.compile(
        r"\b(?:\d[ -]?){13,19}\b"
    ),


    # --------------------------------------------------------
    # CVV
    # --------------------------------------------------------

    "cvv": re.compile(
        r"\b(?:CVV|CVC|CVV2)"
        r"\s*[:=-]?\s*\d{3,4}\b",
        re.I,
    ),


    # --------------------------------------------------------
    # BANK ACCOUNT
    # --------------------------------------------------------

    "bank_account": re.compile(
        r"\b(?:account|a/c|acct)"
        r"\s*(?:number|no|#)?"
        r"\s*[:=-]?\s*"
        r"\d{8,18}\b",
        re.I,
    ),


    # --------------------------------------------------------
    # IFSC
    # --------------------------------------------------------

    "ifsc": re.compile(
        r"\b[A-Z]{4}0[A-Z0-9]{6}\b",
        re.I,
    ),


    # --------------------------------------------------------
    # UPI ID
    # --------------------------------------------------------

    "upi": re.compile(
        r"\b[A-Za-z0-9._-]{2,}"
        r"@[A-Za-z]{2,}\b",
        re.I,
    ),


    # --------------------------------------------------------
    # DATE OF BIRTH
    # --------------------------------------------------------

    "date_of_birth": re.compile(
        r"\b(?:dob|date\s+of\s+birth|birth\s+date)"
        r"\s*[:=-]?\s*"
        r"(?:"
        r"\d{1,2}[/-]\d{1,2}[/-]\d{2,4}"
        r"|"
        r"\d{4}[/-]\d{1,2}[/-]\d{1,2}"
        r")\b",
        re.I,
    ),


    # --------------------------------------------------------
    # PASSPORT
    # --------------------------------------------------------

    "passport": re.compile(
        r"\b[A-Z]\d{7}\b",
        re.I,
    ),


    # --------------------------------------------------------
    # DRIVER LICENSE
    # --------------------------------------------------------

    "driving_license": re.compile(
        r"\b(?:DL|DL\s*NO|DRIVING\s*LICENSE)"
        r"\s*[:=-]?\s*"
        r"[A-Z0-9 -]{8,20}\b",
        re.I,
    ),


    # --------------------------------------------------------
    # EMPLOYEE ID
    # --------------------------------------------------------

    "employee_id": re.compile(
        r"\b(?:employee|emp|staff|worker)"
        r"\s*(?:id|number|no)"
        r"\s*[:=-]?\s*"
        r"[A-Z0-9_-]{3,20}\b",
        re.I,
    ),


    # --------------------------------------------------------
    # IP ADDRESS
    # --------------------------------------------------------

    "ip_address": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|"
        r"1?\d?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
    ),


    # --------------------------------------------------------
    # SALARY / COMPENSATION
    # --------------------------------------------------------

    "salary": re.compile(
        r"\b(?:"
        r"salary"
        r"|basic\s+salary"
        r"|gross\s+salary"
        r"|net\s+salary"
        r"|annual\s+salary"
        r"|monthly\s+salary"
        r"|ctc"
        r"|compensation"
        r"|pay"
        r"|wages?"
        r")"
        r"\s*[:=-]?\s*"
        r"(?:"
        r"(?:₹|rs\.?|inr|\$|usd|€|eur|£|gbp)"
        r"\s*[\d,]+(?:\.\d+)?"
        r"|"
        r"[\d,]+(?:\.\d+)?"
        r"\s*(?:lpa|lakhs?|lakh|k|per\s+month|per\s+year)"
        r")",
        re.I,
    ),


    # --------------------------------------------------------
    # BANK / FINANCIAL DETAILS
    # --------------------------------------------------------

    "financial_information": re.compile(
        r"\b(?:"
        r"bank\s+account"
        r"|account\s+number"
        r"|credit\s+limit"
        r"|loan\s+account"
        r"|investment\s+account"
        r"|salary\s+account"
        r"|bank\s+details?"
        r")"
        r"\s*[:=-]?\s*"
        r"(?:[A-Z0-9* -]{4,30})",
        re.I,
    ),


    # --------------------------------------------------------
    # HOME ADDRESS
    # --------------------------------------------------------

    "address": re.compile(
        r"\b(?:"
        r"home\s+address"
        r"|residential\s+address"
        r"|permanent\s+address"
        r"|current\s+address"
        r"|address"
        r")"
        r"\s*[:=-]\s*"
        r"[^\n,]{3,100}"
        r"(?:,\s*[^\n]{2,100})?",
        re.I,
    ),


    # --------------------------------------------------------
    # ZIP / PIN CODE WITH CONTEXT
    # --------------------------------------------------------

    "pincode": re.compile(
        r"\b(?:"
        r"pin\s*code"
        r"|postal\s*code"
        r"|zip\s*code"
        r")"
        r"\s*[:=-]?\s*\d{5,6}\b",
        re.I,
    ),


    # --------------------------------------------------------
    # NATIONAL INSURANCE / SOCIAL SECURITY STYLE NUMBERS
    # --------------------------------------------------------

    "ssn": re.compile(
        r"\b(?:SSN|social\s+security\s+number)"
        r"\s*[:=-]?\s*"
        r"\d{3}-\d{2}-\d{4}\b",
        re.I,
    ),
}


# ============================================================
# PRIORITY
# ============================================================

# More specific patterns should run first.
# This reduces accidental matching by generic patterns.

PATTERN_ORDER = [
    "email",
    "aadhaar",
    "pan",
    "credit_card",
    "cvv",
    "upi",
    "ifsc",
    "bank_account",
    "ssn",
    "passport",
    "driving_license",
    "employee_id",
    "date_of_birth",
    "salary",
    "financial_information",
    "address",
    "pincode",
    "phone",
    "ip_address",
]


# ============================================================
# CREDIT CARD VALIDATION
# ============================================================

def _luhn_check(number: str) -> bool:
    """
    Validate a possible credit/debit card number
    using the Luhn algorithm.
    """

    digits = re.sub(
        r"\D",
        "",
        number,
    )

    if not 13 <= len(digits) <= 19:
        return False

    total = 0
    reverse_digits = digits[::-1]

    for index, digit in enumerate(
        reverse_digits
    ):

        value = int(digit)

        if index % 2 == 1:

            value *= 2

            if value > 9:
                value -= 9

        total += value

    return total % 10 == 0


# ============================================================
# PHONE VALIDATION
# ============================================================

def _is_valid_phone(
    value: str
) -> bool:

    digits = re.sub(
        r"\D",
        "",
        value,
    )

    # Avoid treating random numbers as phone numbers.
    return 10 <= len(digits) <= 15


# ============================================================
# PII VALIDATION
# ============================================================

def _is_valid_match(
    kind: str,
    value: str
) -> bool:

    if kind == "credit_card":

        return _luhn_check(
            value
        )

    if kind == "phone":

        return _is_valid_phone(
            value
        )

    return True


# ============================================================
# MASK VALUE
# ============================================================

def _mask_value(
    kind: str
) -> str:

    return (
        f"[REDACTED_{kind.upper()}]"
    )


# ============================================================
# MASK PII
# ============================================================

def mask_pii(
    text: str
) -> Tuple[str, List[Dict]]:

    """
    Detect and mask PII / sensitive information.

    Returns:

        masked_text
        detections
    """

    if not text:

        return (
            text,
            []
        )

    masked = text

    detections = []

    # --------------------------------------------------------
    # Process patterns in priority order
    # --------------------------------------------------------

    for kind in PATTERN_ORDER:

        pattern = PATTERNS[kind]

        matches = list(
            pattern.finditer(
                masked
            )
        )

        if not matches:
            continue

        # Reverse order prevents indexes from shifting.
        for match in reversed(matches):

            value = match.group(0)

            # -----------------------------------------------
            # Validate
            # -----------------------------------------------

            if not _is_valid_match(
                kind,
                value
            ):
                continue

            # -----------------------------------------------
            # Replace
            # -----------------------------------------------

            replacement = _mask_value(
                kind
            )

            masked = (
                masked[:match.start()]
                + replacement
                + masked[match.end():]
            )

            detections.append(
                {
                    "type": kind,
                    "action": "masked",
                }
            )

    return (
        masked,
        list(reversed(detections))
    )


# ============================================================
# DETECT WITHOUT MASKING
# ============================================================

def detect_pii(
    text: str
) -> Dict:

    """
    Detect PII without modifying the original text.

    Useful for audit logging and validation.
    """

    if not text:

        return {
            "detected": False,
            "count": 0,
            "types": [],
            "detections": [],
        }

    detections = []

    for kind in PATTERN_ORDER:

        pattern = PATTERNS[kind]

        for match in pattern.finditer(
            text
        ):

            value = match.group(0)

            if not _is_valid_match(
                kind,
                value
            ):
                continue

            detections.append(
                {
                    "type": kind,
                    "value": value,
                    "start": match.start(),
                    "end": match.end(),
                }
            )

    types = sorted(
        {
            item["type"]
            for item in detections
        }
    )

    return {
        "detected": bool(
            detections
        ),
        "count": len(
            detections
        ),
        "types": types,
        "detections": detections,
    }


# ============================================================
# SAFE DETECTION
# ============================================================

def scan_and_mask_pii(
    text: str
) -> Dict:

    """
    Complete PII pipeline.

    This is the recommended function for
    chatbot input and document text.
    """

    masked_text, detections = mask_pii(
        text
    )

    types = sorted(
        {
            item["type"]
            for item in detections
        }
    )

    return {
        "original_text": text,
        "masked_text": masked_text,
        "detected": bool(
            detections
        ),
        "count": len(
            detections
        ),
        "types": types,
        "detections": detections,
    }


# ============================================================
# HELPER
# ============================================================

def contains_pii(
    text: str
) -> bool:

    result = detect_pii(
        text
    )

    return result["detected"]