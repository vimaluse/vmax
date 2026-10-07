
"""
Content Moderation Detector
============================

Purpose
-------

Allow:
    - General questions
    - Technical learning
    - Programming
    - Cybersecurity education
    - Academic/research questions
    - Historical discussions
    - Safety and prevention questions
    - Explanations of crime, hacking, malware, etc.

Block:
    - Actionable criminal instructions
    - Credential theft
    - Unauthorized access
    - Authentication bypass
    - Fraud and forgery
    - Evasion of law enforcement
    - Harmful physical attacks
    - Weapon/explosive construction
    - Self-harm instructions
    - Explicit malicious activity
    - Requests to facilitate illegal activity

Important
---------

This is a deterministic baseline detector.

The detector intentionally does NOT block a topic merely because
the topic itself is sensitive.

For example:

    "What is hacking?"
    "Explain ransomware."
    "How does SQL injection work?"
    "What are common cyber attacks?"
    "How can companies prevent phishing?"

are allowed.

However:

    "How do I hack someone's account?"
    "How do I steal a password?"
    "How do I bypass authentication?"
    "How do I deploy ransomware?"

are blocked.

For production-grade moderation, combine this layer with a
semantic safety classifier or another content-safety model.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Tuple
import re
import unicodedata

from .config import ModerationConfig


# ============================================================
# CATEGORY SEVERITY
# ============================================================

CATEGORY_SEVERITY: Dict[str, float] = {
    "self_harm": 1.00,
    "dangerous_instructions": 1.00,
    "violent_crime": 1.00,
    "credential_theft": 1.00,
    "unauthorized_access": 1.00,
    "fraud": 0.95,
    "evasion": 0.95,
    "illegal_activity": 0.95,
    "malware_abuse": 0.95,
    "harassment": 0.85,
    "hate": 0.95,
    "sexual": 0.90,
    "graphic_content": 0.75,
    "toxicity": 0.55,
}


# ============================================================
# ACTIONABLE DANGEROUS PATTERNS
# ============================================================

CATEGORY_PATTERNS: Dict[str, List[str]] = {

    # --------------------------------------------------------
    # SELF HARM
    #
    # Only actionable self-harm requests are blocked.
    # General educational discussion remains allowed.
    # --------------------------------------------------------

    "self_harm": [

        r"\bhow\s+(?:do\s+i|can\s+i|would\s+i|could\s+i|to)\s+"
        r"(?:hurt|harm|injure)\s+myself\b",

        r"\bhow\s+(?:do\s+i|can\s+i|would\s+i|could\s+i|to)\s+"
        r"(?:kill\s+myself|commit\s+suicide|end\s+my\s+life)\b",

        r"\b(?:ways|methods?|instructions|steps|guide|procedure)"
        r"\s+(?:to\s+)?"
        r"(?:hurt|harm|injure|kill)\s+myself\b",

        r"\b(?:best|easiest|quickest|painless)\s+"
        r"(?:way|method)\s+(?:to\s+)?"
        r"(?:kill|hurt|harm)\s+myself\b",

        r"\bi\s+(?:want|plan|intend)\s+to\s+"
        r"(?:kill|hurt|harm|injure)\s+myself\b",
    ],


    # --------------------------------------------------------
    # VIOLENT CRIME
    # --------------------------------------------------------

    "violent_crime": [

        r"\bhow\s+(?:do\s+i|can\s+i|would\s+i|could\s+i|to)\s+"
        r"(?:attack|assault|stab|shoot|strangle|beat|injure)\b",

        r"\b(?:instructions|steps|guide|ways|methods?|procedure)"
        r"\s+(?:to\s+)?"
        r"(?:attack|assault|stab|shoot|strangle|beat|injure)\b",

        r"\b(?:how\s+to|ways\s+to|methods?\s+to)\s+"
        r"(?:kill|murder)\s+(?:someone|somebody|a\s+person|him|her|them)\b",

        r"\b(?:attack|assault|stab|shoot|strangle|beat)\s+"
        r"(?:someone|somebody|a\s+person|him|her|them)\b",

        r"\bhow\s+(?:do\s+i|can\s+i|would\s+i|to)\s+"
        r"(?:use|fire)\s+(?:a\s+)?"
        r"(?:gun|weapon|firearm)\s+(?:against|at)\s+"
        r"(?:someone|somebody|him|her|them)\b",
    ],


    # --------------------------------------------------------
    # CREDENTIAL THEFT
    #
    # Technical discussion about passwords is allowed.
    # Requests to steal or obtain another person's credentials
    # are blocked.
    # --------------------------------------------------------

    "credential_theft": [

        r"\b(?:steal|take|obtain|get|grab|extract|dump)\s+"
        r"(?:someone'?s|another\s+person'?s|user'?s|victim'?s)?\s*"
        r"(?:password|passwords|credentials?|login|logins|"
        r"access\s+token|tokens?|session\s+cookie|cookies?)\b",

        r"\bhow\s+(?:do\s+i|can\s+i|would\s+i|to)\s+"
        r"(?:steal|obtain|get|extract|capture|harvest|dump)\s+"
        r"(?:passwords?|credentials?|login\s+credentials?|"
        r"tokens?|session\s+cookies?)\b",

        r"\bhow\s+(?:do\s+i|can\s+i|would\s+i|to)\s+"
        r"(?:phish|phishing)\s+"
        r"(?:someone|users?|victims?)\b",

        r"\bhow\s+(?:do\s+i|can\s+i|would\s+i|to)\s+"
        r"(?:create|build|make)\s+"
        r"(?:a\s+)?phishing\s+(?:page|site|website|email)\b",

        r"\b(?:steal|harvest|capture)\s+"
        r"(?:login|credentials?|passwords?|tokens?)\b",
    ],


    # --------------------------------------------------------
    # UNAUTHORIZED ACCESS
    #
    # "What is hacking?" -> allowed
    # "How does hacking work?" -> allowed
    #
    # "How do I hack someone's account?" -> blocked
    # --------------------------------------------------------

    "unauthorized_access": [

        r"\bhow\s+(?:do\s+i|can\s+i|would\s+i|could\s+i|to)\s+"
        r"(?:hack|break\s+into|access)\s+"
        r"(?:someone'?s|another\s+person'?s|someone|somebody|"
        r"another\s+user'?s|a\s+user'?s)"
        r"\s*(?:account|computer|phone|device|server|system|email|"
        r"instagram|facebook|whatsapp|website|database)\b",

        r"\bhow\s+(?:do\s+i|can\s+i|would\s+i|to)\s+"
        r"(?:gain|get|obtain)\s+"
        r"(?:unauthorized|illegal|unlawful)\s+access\b",

        r"\bhow\s+(?:do\s+i|can\s+i|would\s+i|to)\s+"
        r"(?:break\s+into|compromise|take\s+over)\s+"
        r"(?:an?\s+)?"
        r"(?:account|server|computer|device|system|network|website)\b",

        r"\bhow\s+(?:do\s+i|can\s+i|would\s+i|to)\s+"
        r"(?:hack|break\s+into|compromise)\s+"
        r"(?:a\s+)?"
        r"(?:website|server|database|network)\b"
        r"(?:\s+(?:without|illegally|without\s+permission))?",
    ],


    # --------------------------------------------------------
    # AUTHENTICATION / SECURITY BYPASS
    # --------------------------------------------------------

    "unauthorized_access": [

        r"\bhow\s+(?:do\s+i|can\s+i|would\s+i|to)\s+"
        r"(?:bypass|circumvent|disable|defeat|break)\s+"
        r"(?:authentication|authorization|login|password|"
        r"security|access\s+control)\b",

        r"\bhow\s+(?:do\s+i|can\s+i|would\s+i|to)\s+"
        r"(?:bypass|circumvent)\s+"
        r"(?:2fa|mfa|two[-\s]?factor|multi[-\s]?factor)\b",

        r"\bhow\s+(?:do\s+i|can\s+i|would\s+i|to)\s+"
        r"(?:bypass|disable)\s+"
        r"(?:firewall|security\s+controls?|endpoint\s+protection)\b",

        r"\bhow\s+(?:do\s+i|can\s+i|would\s+i|to)\s+"
        r"(?:evade|avoid)\s+"
        r"(?:detection|security\s+monitoring|antivirus|edr|ids|ips)\b",
    ],


    # --------------------------------------------------------
    # MALWARE ABUSE
    #
    # Malware education remains allowed.
    # Deployment/abuse requests are blocked.
    # --------------------------------------------------------

    "malware_abuse": [

        r"\bhow\s+(?:do\s+i|can\s+i|would\s+i|to)\s+"
        r"(?:deploy|spread|install|execute|distribute)\s+"
        r"(?:malware|ransomware|spyware|trojan|worm|virus)\b",

        r"\bhow\s+(?:do\s+i|can\s+i|would\s+i|to)\s+"
        r"(?:create|build|write|develop)\s+"
        r"(?:ransomware|spyware|trojan|malware|keylogger)\b"
        r"(?:\s+for\s+(?:attack|victims?|targets?))?\b",

        r"\bhow\s+(?:do\s+i|can\s+i|would\s+i|to)\s+"
        r"(?:infect|compromise)\s+"
        r"(?:someone|users?|victims?|computers?|devices?|systems?)\b",

        r"\bhow\s+(?:do\s+i|can\s+i|would\s+i|to)\s+"
        r"(?:encrypt|lock)\s+"
        r"(?:someone'?s|victim'?s)\s+files?\b",
    ],


    # --------------------------------------------------------
    # FRAUD / FORGERY
    # --------------------------------------------------------

    "fraud": [

        r"\bhow\s+(?:do\s+i|can\s+i|would\s+i|to)\s+"
        r"(?:commit|perform|carry\s+out)\s+"
        r"(?:fraud|scam|financial\s+fraud)\b",

        r"\bhow\s+(?:do\s+i|can\s+i|would\s+i|to)\s+"
        r"(?:forge|counterfeit|fake)\s+"
        r"(?:documents?|ids?|identity|signatures?|certificates?)\b",

        r"\bhow\s+(?:do\s+i|can\s+i|would\s+i|to)\s+"
        r"(?:create|make|use)\s+"
        r"(?:fake|forged|counterfeit)\s+"
        r"(?:documents?|ids?|identity|certificates?)\b",

        r"\bhow\s+(?:do\s+i|can\s+i|would\s+i|to)\s+"
        r"(?:steal|use)\s+"
        r"(?:someone'?s|another\s+person'?s)\s+identity\b",

        r"\bhow\s+(?:do\s+i|can\s+i|would\s+i|to)\s+"
        r"(?:scam|defraud|con)\s+"
        r"(?:someone|people|users?|customers?)\b",
    ],


    # --------------------------------------------------------
    # LAW ENFORCEMENT EVASION
    # --------------------------------------------------------

    "evasion": [

        r"\bhow\s+(?:do\s+i|can\s+i|would\s+i|to)\s+"
        r"(?:evade|escape|avoid|bypass)\s+"
        r"(?:police|law\s+enforcement|the\s+police)\b",

        r"\bhow\s+(?:do\s+i|can\s+i|would\s+i|to)\s+"
        r"(?:avoid|escape)\s+"
        r"(?:arrest|detection|being\s+caught)\b",

        r"\bhow\s+(?:do\s+i|can\s+i|would\s+i|to)\s+"
        r"(?:hide|destroy|remove)\s+"
        r"(?:evidence|proof)\s+"
        r"(?:from|before)\s+"
        r"(?:police|investigators?)\b",
    ],


    # --------------------------------------------------------
    # ILLEGAL ACTIVITY
    # --------------------------------------------------------

    "illegal_activity": [

        r"\bhow\s+(?:do\s+i|can\s+i|would\s+i|could\s+i|to)\s+"
        r"(?:steal|rob|burglarize|break\s+into)\b",

        r"\bhow\s+(?:do\s+i|can\s+i|would\s+i|to)\s+"
        r"(?:sell|distribute|traffic)\s+"
        r"(?:illegal\s+drugs?|stolen\s+goods?)\b",

        r"\bhow\s+(?:do\s+i|can\s+i|would\s+i|to)\s+"
        r"(?:launder|hide)\s+"
        r"(?:money|illegal\s+funds?)\b",

        r"\bhow\s+(?:do\s+i|can\s+i|would\s+i|to)\s+"
        r"(?:make|obtain|use)\s+"
        r"(?:illegal\s+documents?|fake\s+ids?)\b",
    ],


    # --------------------------------------------------------
    # DANGEROUS INSTRUCTIONS
    # --------------------------------------------------------

    "dangerous_instructions": [

        r"\bhow\s+(?:do\s+i|can\s+i|would\s+i|could\s+i|to)\s+"
        r"(?:make|build|construct|prepare|create)\s+"
        r"(?:a\s+|an\s+)?"
        r"(?:bomb|explosive|poison)\b",

        r"\b(?:instructions|steps|recipe|procedure|guide|formula)"
        r"\s+(?:to\s+)?"
        r"(?:make|build|construct|prepare|create)\s+"
        r"(?:a\s+|an\s+)?"
        r"(?:bomb|explosive|poison)\b",

        r"\bhow\s+to\s+(?:weaponize|weaponise)\b",

        r"\bhow\s+(?:do\s+i|can\s+i|would\s+i|to)\s+"
        r"(?:make|create|produce)\s+"
        r"(?:a\s+)?"
        r"(?:chemical\s+weapon|biological\s+weapon)\b",
    ],


    # --------------------------------------------------------
    # HATE / TARGETED VIOLENCE
    # --------------------------------------------------------

    "hate": [

        r"\b(?:exterminate|wipe\s+out|eradicate)\s+"
        r"(?:a\s+|an\s+|the\s+)?"
        r"(?:race|ethnicity|religion|religious\s+group|"
        r"ethnic\s+group)\b",

        r"\b(?:kill|attack|harm)\s+"
        r"(?:all|every)\s+"
        r"(?:members?\s+of\s+)?"
        r"(?:a\s+|the\s+)?"
        r"(?:race|ethnicity|religion|religious\s+group|"
        r"ethnic\s+group)\b",
    ],


    # --------------------------------------------------------
    # HARASSMENT
    # --------------------------------------------------------

    "harassment": [

        r"\bhow\s+(?:do\s+i|can\s+i|would\s+i|to)\s+"
        r"(?:bully|harass|stalk|intimidate)\s+"
        r"(?:someone|somebody|a\s+person|him|her|them)\b",

        r"\bhow\s+(?:do\s+i|can\s+i|would\s+i|to)\s+"
        r"(?:repeatedly|continuously)\s+"
        r"(?:contact|harass|threaten|stalk)\s+"
        r"(?:someone|somebody|a\s+person)\b",
    ],


    # --------------------------------------------------------
    # GRAPHIC CONTENT
    # --------------------------------------------------------

    "graphic_content": [

        r"\b(?:generate|write|create|describe)\s+"
        r"(?:extremely\s+|highly\s+)?"
        r"(?:graphic|gory)\s+"
        r"(?:violence|injuries|mutilation|death)\b",
    ],


    # --------------------------------------------------------
    # TOXICITY
    #
    # Kept low severity so ordinary technical questions are not
    # accidentally blocked.
    # --------------------------------------------------------

    "toxicity": [

        r"\b(?:idiot|moron|stupid|dumbass|loser)\b",

        r"\b(?:you\s+are|you're)\s+"
        r"(?:useless|stupid|an?\s+idiot)\b",
    ],
}


# ============================================================
# SAFE / EDUCATIONAL CONTEXT
# ============================================================

SAFE_CONTEXT_PATTERNS = [

    # General educational questions
    r"\bwhat\s+is\b",
    r"\bwhat\s+are\b",
    r"\bwhat\s+does\b",
    r"\bwhy\s+does\b",
    r"\bexplain\b",
    r"\bdefine\b",
    r"\bdefinition\s+of\b",

    # Technical learning
    r"\bhow\s+does\s+.*\s+work\b",
    r"\bhow\s+do\s+.*\s+work\b",
    r"\barchitecture\s+of\b",
    r"\bconcept\s+of\b",
    r"\bprinciple\s+of\b",
    r"\bexample\s+of\b",
    r"\btutorial\s+about\b",
    r"\blearn\s+about\b",

    # Defensive/security learning
    r"\bhow\s+to\s+prevent\b",
    r"\bhow\s+to\s+protect\b",
    r"\bhow\s+to\s+defend\b",
    r"\bhow\s+to\s+detect\b",
    r"\bhow\s+to\s+mitigate\b",
    r"\bsecurity\s+best\s+practices\b",
    r"\bcybersecurity\s+defense\b",
    r"\bcybersecurity\s+defensive\b",
    r"\bincident\s+response\b",
    r"\bvulnerability\s+assessment\b",
    r"\bpenetration\s+testing\b",
    r"\bsecurity\s+testing\b",

    # Academic / research
    r"\bacademic\b",
    r"\bresearch\b",
    r"\bresearch\s+paper\b",
    r"\bstudy\b",
    r"\bhistorical\b",
    r"\bhistory\s+of\b",

    # Awareness / safety
    r"\bsafety\b",
    r"\bprevention\b",
    r"\bawareness\b",
    r"\bsecurity\s+awareness\b",
]


# ============================================================
# RESULT
# ============================================================

@dataclass
class ModerationResult:

    allowed: bool = True

    action: str = "allow"

    category: str = ""

    categories: List[str] = field(
        default_factory=list
    )

    score: float = 0.0

    threshold: float = 0.80

    matched_rules: List[str] = field(
        default_factory=list
    )

    match_count: int = 0

    safe_context_detected: bool = False

    reason: str = ""

    normalized_text: str = ""

    def to_dict(self) -> Dict:

        return {
            "allowed": self.allowed,
            "action": self.action,
            "category": self.category,
            "categories": self.categories,
            "score": round(self.score, 4),
            "threshold": self.threshold,
            "matched_rules": self.matched_rules,
            "match_count": self.match_count,
            "safe_context_detected": self.safe_context_detected,
            "reason": self.reason,
        }


# ============================================================
# NORMALIZATION
# ============================================================

def normalize_text(text: str) -> str:
    """
    Normalize simple obfuscation.

    Examples:

        HACK
        h.a.c.k
        h-a-c-k
        h_a_c_k
        h4ck
        HAAAAACK
    """

    if not text:
        return ""

    # Unicode normalization
    text = unicodedata.normalize(
        "NFKC",
        text,
    )

    # Lowercase
    text = text.lower()

    # Common leetspeak
    leet_map = str.maketrans(
        {
            "0": "o",
            "1": "i",
            "3": "e",
            "4": "a",
            "5": "s",
            "7": "t",
            "@": "a",
            "$": "s",
        }
    )

    text = text.translate(leet_map)

    # Remove separators between words/letters.

    # h.a.c.k -> hack
    # h-a-c-k -> hack
    # h_a_c_k -> hack

    text = re.sub(
        r"(?<=\w)[._\-]+(?=\w)",
        "",
        text,
    )

    # Collapse excessive repeated characters.

    # haaaack -> haack
    # stuuuupid -> stuupid

    text = re.sub(
        r"(.)\1{2,}",
        r"\1\1",
        text,
    )

    # Normalize whitespace
    text = re.sub(
        r"\s+",
        " ",
        text,
    ).strip()

    return text


# ============================================================
# DETECTOR
# ============================================================

class ModerationDetector:

    def __init__(
        self,
        config: ModerationConfig | None = None,
    ):

        self.config = config or ModerationConfig()

    # ========================================================
    # SAFE CONTEXT
    # ========================================================

    def _detect_safe_context(
        self,
        text: str,
    ) -> bool:
        """
        Detect educational, technical, defensive,
        academic, historical, or safety context.

        IMPORTANT:

        Safe context does NOT automatically override a
        strong actionable harmful request.

        Example:

            "Explain how to hack someone."

        contains educational language but is still blocked
        because the request is actionable and targets another
        person's system/account.
        """

        return any(
            re.search(
                pattern,
                text,
                flags=re.IGNORECASE,
            )
            for pattern in SAFE_CONTEXT_PATTERNS
        )

    # ========================================================
    # FIND MATCHES
    # ========================================================

    def _find_matches(
        self,
        text: str,
    ) -> List[Tuple[str, str]]:

        matches: List[Tuple[str, str]] = []

        for category, patterns in CATEGORY_PATTERNS.items():

            for pattern in patterns:

                if re.search(
                    pattern,
                    text,
                    flags=re.IGNORECASE,
                ):

                    matches.append(
                        (
                            category,
                            pattern,
                        )
                    )

        return matches

    # ========================================================
    # CALCULATE SCORE
    # ========================================================

    def _calculate_score(
        self,
        matches: List[Tuple[str, str]],
    ) -> float:

        if not matches:
            return 0.0

        categories = {
            category
            for category, _ in matches
        }

        # Highest severity category
        severity = max(
            CATEGORY_SEVERITY.get(
                category,
                0.50,
            )
            for category in categories
        )

        # Multiple independent matches increase confidence.
        match_bonus = min(
            0.15,
            max(
                0,
                len(matches) - 1
            ) * 0.05,
        )

        score = severity + match_bonus

        return max(
            0.0,
            min(
                1.0,
                score,
            ),
        )

    # ========================================================
    # DETECT
    # ========================================================

    def detect(
        self,
        text: str,
    ) -> ModerationResult:

        # ----------------------------------------------------
        # MODERATION DISABLED
        # ----------------------------------------------------

        if not self.config.enabled:

            return ModerationResult(
                allowed=True,
                action="disabled",
                reason="Content moderation is disabled.",
            )

        # ----------------------------------------------------
        # EMPTY CONTENT
        # ----------------------------------------------------

        if not text or not text.strip():

            return ModerationResult(
                allowed=True,
                action="allow",
                reason="Empty content.",
            )

        # ----------------------------------------------------
        # NORMALIZE
        # ----------------------------------------------------

        normalized = normalize_text(text)

        # ----------------------------------------------------
        # SAFE CONTEXT
        # ----------------------------------------------------

        safe_context = self._detect_safe_context(
            normalized
        )

        # ----------------------------------------------------
        # FIND ACTIONABLE MATCHES
        # ----------------------------------------------------

        matches = self._find_matches(
            normalized
        )

        # ----------------------------------------------------
        # NO DANGEROUS MATCH
        #
        # This means normal/general/technical queries are
        # allowed.
        # ----------------------------------------------------

        if not matches:

            return ModerationResult(
                allowed=True,
                action="allow",
                threshold=self.config.block_threshold,
                safe_context_detected=safe_context,
                reason=(
                    "No actionable harmful or suspicious "
                    "moderation rule matched."
                ),
            )

        # ----------------------------------------------------
        # CATEGORIES
        # ----------------------------------------------------

        categories = list(
            dict.fromkeys(
                category
                for category, _ in matches
            )
        )

        # ----------------------------------------------------
        # PRIMARY CATEGORY
        # ----------------------------------------------------

        category = max(
            categories,
            key=lambda item: CATEGORY_SEVERITY.get(
                item,
                0.50,
            ),
        )

        # ----------------------------------------------------
        # MATCHED RULES
        # ----------------------------------------------------

        matched_rules = [
            f"{cat}:{pattern}"
            for cat, pattern in matches
        ]

        # ----------------------------------------------------
        # SCORE
        # ----------------------------------------------------

        score = self._calculate_score(
            matches
        )

        # ----------------------------------------------------
        # BLOCK
        #
        # Important:
        #
        # The detector does NOT return HTTP 400/403.
        #
        # The integration layer should return a normal chatbot
        # response containing a safe refusal.
        # ----------------------------------------------------

        if score >= self.config.block_threshold:

            return ModerationResult(
                allowed=False,
                action="safe_refuse",
                category=category,
                categories=categories,
                score=score,
                threshold=self.config.block_threshold,
                matched_rules=matched_rules,
                match_count=len(matches),
                safe_context_detected=safe_context,
                reason=(
                    "The request contains actionable harmful, "
                    "illegal, unauthorized, or suspicious "
                    "instructions."
                ),
            )

        # ----------------------------------------------------
        # WARN
        # ----------------------------------------------------

        if score >= self.config.warn_threshold:

            return ModerationResult(
                allowed=True,
                action="warn",
                category=category,
                categories=categories,
                score=score,
                threshold=self.config.block_threshold,
                matched_rules=matched_rules,
                match_count=len(matches),
                safe_context_detected=safe_context,
                reason=(
                    "The request matched a moderation rule "
                    "but did not reach the blocking threshold."
                ),
            )

        # ----------------------------------------------------
        # ALLOW
        # ----------------------------------------------------

        return ModerationResult(
            allowed=True,
            action="allow",
            category=category,
            categories=categories,
            score=score,
            threshold=self.config.block_threshold,
            matched_rules=matched_rules,
            match_count=len(matches),
            safe_context_detected=safe_context,
            reason=(
                "Moderation match was below the configured "
                "threshold."
            ),
        )


# ============================================================
# SIMPLE FUNCTION API
# ============================================================

def moderate_text(
    text: str,
    config: ModerationConfig | None = None,
) -> Dict:
    """
    Convenience function for testing and integration.
    """

    detector = ModerationDetector(
        config
    )

    return detector.detect(
        text
    ).to_dict()
