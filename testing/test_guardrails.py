"""Tests for the guardrail rejection wrapper and document-text guard.

Run from the project root:
    python -m pytest testing/test_guardrails.py -v
"""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import main

from guardrails.document_guard import guard_document_text
from guardrails.result import GuardrailResult


CATEGORY_MESSAGES = {
    "prompt_injection": (
        "I can't follow that request because it contains "
        "an instruction-injection pattern."
    ),
    "jailbreak": (
        "I can't follow requests intended to bypass "
        "the chatbot's safety controls."
    ),
    "credential_leakage": (
        "I can't provide credentials, secrets, API keys, "
        "passwords, or access tokens."
    ),
    "secret": (
        "I can't provide secrets, credentials, "
        "or authentication information."
    ),
    "pii": "I can't expose sensitive personal information.",
    "toxicity": "I can't assist with abusive or harmful content.",
}

DEFAULT_MESSAGE = "I can't comply with that request."


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def imported_helper_fails(monkeypatch):
    """Force the rejection wrapper to use its fallback messages."""
    helper = Mock(side_effect=RuntimeError("helper unavailable"))

    monkeypatch.setattr(
        main,
        "imported_guardrail_rejection_message",
        helper,
        raising=False,
    )

    return helper


# ---------------------------------------------------------------------------
# get_guardrail_rejection_message tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "category, expected",
    CATEGORY_MESSAGES.items(),
)
def test_known_category_fallback(
    imported_helper_fails,
    category,
    expected,
):
    result = main.get_guardrail_rejection_message(
        SimpleNamespace(category=category)
    )

    assert result == expected


@pytest.mark.parametrize(
    "category",
    [
        None,
        "",
        "unknown",
        "PII",
        "Prompt_Injection",
        "pii ",
        123,
        (),
    ],
)
def test_unknown_category_returns_default(
    imported_helper_fails,
    category,
):
    result = main.get_guardrail_rejection_message(
        SimpleNamespace(category=category)
    )

    assert result == DEFAULT_MESSAGE


@pytest.mark.parametrize("category", [[], {}])
def test_unhashable_category_currently_raises_type_error(
    imported_helper_fails,
    category,
):
    """Document the current behavior for unhashable category values."""
    with pytest.raises(TypeError):
        main.get_guardrail_rejection_message(
            SimpleNamespace(category=category)
        )


def test_missing_category_returns_default(imported_helper_fails):
    result = main.get_guardrail_rejection_message(object())

    assert result == DEFAULT_MESSAGE


def test_none_guard_result_returns_default(imported_helper_fails):
    result = main.get_guardrail_rejection_message(None)

    assert result == DEFAULT_MESSAGE


def test_imported_helper_result_is_returned(monkeypatch):
    guard_result = SimpleNamespace(category="jailbreak")
    helper = Mock(return_value="custom message")

    monkeypatch.setattr(
        main,
        "imported_guardrail_rejection_message",
        helper,
        raising=False,
    )

    result = main.get_guardrail_rejection_message(guard_result)

    assert result == "custom message"
    helper.assert_called_once_with(guard_result)


def test_imported_helper_empty_string_is_returned(monkeypatch):
    helper = Mock(return_value="")

    monkeypatch.setattr(
        main,
        "imported_guardrail_rejection_message",
        helper,
        raising=False,
    )

    result = main.get_guardrail_rejection_message(
        SimpleNamespace(category="pii")
    )

    assert result == ""


# ---------------------------------------------------------------------------
# Document guard tests
# ---------------------------------------------------------------------------

def test_document_guard_returns_guardrail_result():
    result = guard_document_text("This is a normal document.")

    assert isinstance(result, GuardrailResult)


def test_document_guard_preserves_text_when_guard_is_disabled(
    monkeypatch,
):
    import guardrails.document_guard as document_guard_module

    monkeypatch.setattr(
        document_guard_module,
        "DOCUMENT_GUARD_ENABLED",
        False,
    )

    text = "This is a normal document."
    result = guard_document_text(text)

    assert isinstance(result, GuardrailResult)
    assert result.text == text


def test_document_guard_accepts_empty_text():
    result = guard_document_text("")

    assert isinstance(result, GuardrailResult)
    assert result.text == ""


def test_document_guard_records_filename_independently():
    text = "This is a normal document."
    result = guard_document_text(
        text,
        filename="example.txt",
    )

    assert isinstance(result, GuardrailResult)
    assert result.text is not None

