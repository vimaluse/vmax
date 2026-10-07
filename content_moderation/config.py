"""
Content Moderation Configuration
"""

from dataclasses import dataclass
import os


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)

    if value is None:
        return default

    return value.strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


@dataclass
class ModerationConfig:

    # Master switch
    enabled: bool = _env_bool(
        "CONTENT_MODERATION_ENABLED",
        True,
    )

    # Input moderation
    input_enabled: bool = _env_bool(
        "CONTENT_MODERATION_INPUT_ENABLED",
        True,
    )

    # Output moderation
    output_enabled: bool = _env_bool(
        "CONTENT_MODERATION_OUTPUT_ENABLED",
        True,
    )

    # Thresholds
    block_threshold: float = _env_float(
        "CONTENT_MODERATION_BLOCK_THRESHOLD",
        0.80,
    )

    warn_threshold: float = _env_float(
        "CONTENT_MODERATION_WARN_THRESHOLD",
        0.50,
    )

    def __post_init__(self):

        self.block_threshold = min(
            max(float(self.block_threshold), 0.0),
            1.0,
        )

        self.warn_threshold = min(
            max(float(self.warn_threshold), 0.0),
            1.0,
        )

        # Warn threshold should never be higher
        # than the block threshold.
        if self.warn_threshold > self.block_threshold:
            self.warn_threshold = self.block_threshold


def get_moderation_config() -> ModerationConfig:
    return ModerationConfig()
