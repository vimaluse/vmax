"""
Unit tests for get_rag_relevance() in main.py.

Run from the project root:
    python -m pip install pytest
    python -m pytest tests/test_rag_relevance.py -v

These tests import main.py, so the project's normal dependencies must be installed.
The tests override RAG_SIMILARITY_THRESHOLD to 0.55 for deterministic behavior.
"""

import math

import pytest
import main


@pytest.fixture
def threshold(monkeypatch):
    """Use a fixed threshold so tests do not depend on local .env values."""
    monkeypatch.setattr(main, "RAG_SIMILARITY_THRESHOLD", 0.55)
    return 0.55


@pytest.mark.parametrize(
    ("item", "explicit_file_ids", "expected"),
    [
        pytest.param(None, None, False, id="item-is-none"),
        pytest.param("not-a-dict", None, False, id="item-is-string"),
        pytest.param([], None, False, id="item-is-list"),
        pytest.param(123, None, False, id="item-is-integer"),
        pytest.param({}, None, False, id="empty-dictionary-no-score"),
        pytest.param({"score": 0.90}, None, True, id="score-above-threshold-no-file-id"),
        pytest.param({"file_id": "doc-1", "score": 0.80}, None, True, id="score-above-threshold"),
        pytest.param({"file_id": "doc-1", "score": 0.55}, None, True, id="score-equals-threshold"),
        pytest.param({"file_id": "doc-1", "score": 0.5499}, None, False, id="score-just-below-threshold"),
        pytest.param({"file_id": "doc-1", "score": 0.10}, None, False, id="low-score"),
        pytest.param({"file_id": "doc-1"}, None, False, id="score-missing"),
        pytest.param({"file_id": "doc-1", "score": None}, None, False, id="score-is-none"),
        pytest.param({"file_id": "doc-1", "score": "0.80"}, None, True, id="numeric-string-score"),
        pytest.param({"file_id": "doc-1", "score": "invalid"}, None, False, id="invalid-string-score"),
        pytest.param({"file_id": "doc-1", "score": ""}, None, False, id="empty-string-score"),
        pytest.param({"file_id": "doc-1", "score": []}, None, False, id="unconvertible-list-score"),
        pytest.param({"file_id": "doc-1", "score": 0.01}, ["doc-1"], True, id="explicit-file-overrides-low-score"),
        pytest.param({"file_id": "doc-1"}, ["doc-1"], True, id="explicit-file-overrides-missing-score"),
        pytest.param({"file_id": "doc-2", "score": 0.90}, ["doc-1"], True, id="unselected-file-can-pass-score"),
        pytest.param({"file_id": "doc-2", "score": 0.40}, ["doc-1"], False, id="unselected-file-low-score"),
        pytest.param({"file_id": "doc-1", "score": 0.10}, [], False, id="empty-selection-list-does-not-override"),
        pytest.param({"file_id": "doc-1", "score": 0.10}, None, False, id="no-selection-does-not-override"),
        pytest.param({"file_id": "doc-1", "score": math.nan}, None, False, id="nan-score-is-not-relevant"),
        pytest.param({"file_id": "doc-1", "score": math.inf}, None, True, id="positive-infinity-currently-passes"),
    ],
)
def test_get_rag_relevance_cases(item, explicit_file_ids, expected, threshold):
    assert main.get_rag_relevance(item, explicit_file_ids) is expected


def test_threshold_is_read_from_main_configuration(monkeypatch):
    """Confirm that changing the configured threshold changes the decision."""
    monkeypatch.setattr(main, "RAG_SIMILARITY_THRESHOLD", 0.70)

    assert main.get_rag_relevance({"file_id": "doc-1", "score": 0.69}) is False
    assert main.get_rag_relevance({"file_id": "doc-1", "score": 0.70}) is True


def test_explicit_file_id_match_is_exact(threshold):
    """A different file ID must not receive the explicit-selection override."""
    item = {"file_id": "doc-10", "score": 0.10}

    assert main.get_rag_relevance(item, ["doc-1"]) is False


def test_explicit_file_id_match_with_multiple_selected_files(threshold):
    item = {"file_id": "doc-3", "score": 0.01}

    assert main.get_rag_relevance(item, ["doc-1", "doc-2", "doc-3"]) is True
