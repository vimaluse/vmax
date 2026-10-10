
from fastapi.testclient import TestClient
import main

client = TestClient(main.app)


def test_health_check_integrates_all_services():
    response = client.get("/api/health")

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "ok"
    assert data["services"]["redis"] == "connected"
    assert data["services"]["qdrant"] == "connected"
    assert data["services"]["ollama"] == "connected"
