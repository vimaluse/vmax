
from types import SimpleNamespace
from unittest.mock import AsyncMock

from fastapi.testclient import TestClient
import main


client = TestClient(main.app)


def setup_chat_test(monkeypatch):
    # Use a test user instead of requiring a real login.
    main.app.dependency_overrides[main.get_current_user] = (
        lambda: SimpleNamespace(
            user_id="integration-test-admin",
            username="integration-test",
            role="admin",
        )
    )

    # Keep authorization and rate limiting outside this test's scope.
    monkeypatch.setattr(
        main,
        "authorize_model_request",
        lambda **kwargs: None,
    )
    monkeypatch.setattr(
        main,
        "check_rate_limit",
        lambda **kwargs: True,
    )

    # Avoid requiring documents in Qdrant for a general question.
    monkeypatch.setattr(
        main,
        "retrieve",
        lambda *args, **kwargs: [],
    )


def teardown_chat_test():
    main.app.dependency_overrides.clear()


def test_guardrails_allow_normal_query_and_ollama_responds(monkeypatch):
    setup_chat_test(monkeypatch)

    try:
        response = client.post(
            "/api/chat",
            json={
                "message": "What is Python? Answer in two sentences.",
                "history": [],
                "file_ids": [],
                "use_web": False,
            },
        )

        assert response.status_code == 200

        data = response.json()

        assert "answer" in data
        assert isinstance(data["answer"], str)
        assert data["answer"].strip() != ""
        assert data["used_rag"] is False
        assert data["used_web"] is False

    finally:
        teardown_chat_test()


def test_guardrail_blocks_disallowed_input_without_calling_ollama(
    monkeypatch,
):
    setup_chat_test(monkeypatch)

    # Simulate a guardrail returning a blocked result.
    # This tests the endpoint's blocking behavior.
    monkeypatch.setattr(
        main,
        "guard_input",
        lambda *args, **kwargs: SimpleNamespace(
            allowed=False,
            text="Blocked test input",
        ),
    )

    monkeypatch.setattr(
        main,
        "get_guardrail_rejection_message",
        lambda result: "Request blocked by guardrail.",
    )

    ollama_mock = AsyncMock()
    monkeypatch.setattr(main, "call_ollama", ollama_mock)

    try:
        response = client.post(
            "/api/chat",
            json={
                "message": "Test input that the simulated guardrail blocks",
                "history": [],
                "file_ids": [],
                "use_web": False,
            },
        )

        assert response.status_code == 200

        data = response.json()
        assert data["answer"] == "Request blocked by guardrail."

        # Ollama must not be called after input is blocked.
        ollama_mock.assert_not_awaited()

    finally:
        teardown_chat_test()
