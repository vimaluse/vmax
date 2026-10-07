"""
High-level Content Moderation Service.
"""

from typing import Any, Dict, Optional

from .config import ModerationConfig
from .detector import (
    ModerationDetector,
    ModerationResult,
)


SAFE_REFUSAL = (
    "I can't help with that request. "
    "I can help with a safe, non-harmful alternative."
)


class ContentModerator:

    def __init__(
        self,
        config: Optional[ModerationConfig] = None,
    ):

        self.config = config or ModerationConfig()

        self.detector = ModerationDetector(
            self.config
        )

    # ========================================================
    # INPUT MODERATION
    # ========================================================

    def moderate_input(
        self,
        text: str,
    ) -> ModerationResult:

        if not self.config.input_enabled:

            return ModerationResult(
                allowed=True,
                action="disabled",
                reason="Input moderation is disabled.",
            )

        return self.detector.detect(text)

    # ========================================================
    # OUTPUT MODERATION
    # ========================================================

    def moderate_output(
        self,
        text: str,
    ) -> ModerationResult:

        if not self.config.output_enabled:

            return ModerationResult(
                allowed=True,
                action="disabled",
                reason="Output moderation is disabled.",
            )

        return self.detector.detect(text)

    # ========================================================
    # PROCESS INPUT
    # ========================================================

    def process_input(
        self,
        text: str,
    ) -> Dict[str, Any]:

        result = self.moderate_input(text)

        if result.action == "safe_refuse":

            return {
                "allowed": False,
                "response": SAFE_REFUSAL,
                "moderation": result.to_dict(),
            }

        return {
            "allowed": True,
            "response": text,
            "moderation": result.to_dict(),
        }

    # ========================================================
    # PROCESS OUTPUT
    # ========================================================

    def process_output(
        self,
        text: str,
    ) -> Dict[str, Any]:

        result = self.moderate_output(text)

        if result.action == "safe_refuse":

            return {
                "allowed": False,
                "response": SAFE_REFUSAL,
                "moderation": result.to_dict(),
            }

        return {
            "allowed": True,
            "response": text,
            "moderation": result.to_dict(),
        }
