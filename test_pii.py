from guardrails.pii import (
    detect_pii,
    mask_pii,
    scan_and_mask_pii,
)


TEST_CASES = [

    # --------------------------------------------------------
    # Email
    # --------------------------------------------------------

    (
        "My email is vimal@example.com"
    ),

    # --------------------------------------------------------
    # Phone
    # --------------------------------------------------------

    (
        "My phone number is +91 9876543210"
    ),

    # --------------------------------------------------------
    # Aadhaar
    # --------------------------------------------------------

    (
        "My Aadhaar number is 1234 5678 9012"
    ),

    # --------------------------------------------------------
    # PAN
    # --------------------------------------------------------

    (
        "My PAN number is ABCDE1234F"
    ),

    # --------------------------------------------------------
    # Credit card
    # --------------------------------------------------------

    (
        "My card number is 4111 1111 1111 1111"
    ),

    # --------------------------------------------------------
    # CVV
    # --------------------------------------------------------

    (
        "CVV: 123"
    ),

    # --------------------------------------------------------
    # IFSC
    # --------------------------------------------------------

    (
        "My bank IFSC is SBIN0001234"
    ),

    # --------------------------------------------------------
    # UPI
    # --------------------------------------------------------

    (
        "My UPI ID is vimal@upi"
    ),

    # --------------------------------------------------------
    # Date of birth
    # --------------------------------------------------------

    (
        "DOB: 15/08/1999"
    ),

    # --------------------------------------------------------
    # Employee ID
    # --------------------------------------------------------

    (
        "Employee ID: EMP12345"
    ),

    # --------------------------------------------------------
    # Salary
    # --------------------------------------------------------

    (
        "My monthly salary is ₹75,000"
    ),

    # --------------------------------------------------------
    # CTC
    # --------------------------------------------------------

    (
        "My CTC is 8 LPA"
    ),

    # --------------------------------------------------------
    # Address
    # --------------------------------------------------------

    (
        "Home Address: 123 Anna Street, Chennai"
    ),

    # --------------------------------------------------------
    # IP
    # --------------------------------------------------------

    (
        "My server IP is 192.168.1.100"
    ),

    # --------------------------------------------------------
    # Normal text
    # --------------------------------------------------------

    (
        "What is the company leave policy?"
    ),
]


print()
print("=" * 70)
print("PII DETECTION TEST")
print("=" * 70)


for index, text in enumerate(
    TEST_CASES,
    start=1
):

    print()
    print(f"TEST {index}")
    print("-" * 70)

    print(
        "INPUT:"
    )

    print(
        text
    )

    result = scan_and_mask_pii(
        text
    )

    print()
    print(
        "PII DETECTED:",
        result["detected"]
    )

    print(
        "COUNT:",
        result["count"]
    )

    print(
        "TYPES:",
        result["types"]
    )

    print()
    print(
        "MASKED:"
    )

    print(
        result["masked_text"]
    )


print()
print("=" * 70)
print("DIRECT DETECTION TEST")
print("=" * 70)

test_text = """
Employee: Vimal
Email: vimal@example.com
Phone: +91 9876543210
PAN: ABCDE1234F
Aadhaar: 1234 5678 9012
Salary: ₹75,000 per month
CTC: 8 LPA
UPI: vimal@upi
DOB: 15/08/1999
"""

result = detect_pii(
    test_text
)

print(
    result
)


print()
print("=" * 70)
print("MASKING TEST")
print("=" * 70)

masked, detections = mask_pii(
    test_text
)

print(
    "ORIGINAL:"
)

print(
    test_text
)

print(
    "\nMASKED:"
)

print(
    masked
)

print(
    "\nDETECTIONS:"
)

print(
    detections
)

print()
print("=" * 70)
print("TEST COMPLETE")
print("=" * 70)