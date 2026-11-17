import asyncio
from pathlib import Path

from okf_jev.service import OKFJEVService


def build_service():
    root = Path(__file__).resolve().parents[1] / "knowledge"
    instance = OKFJEVService(root, enabled=False)
    instance.validate_bundle()
    return instance


def test_bundle_validates_without_errors():
    service = build_service()
    result = service.validate_bundle()
    assert result["valid"], result["errors"]
    assert result["documents"] >= 4


def test_local_retrieval_returns_qdrant_knowledge():
    service = build_service()
    result = asyncio.run(service.retrieve("How do I troubleshoot Qdrant vector retrieval?"))
    assert result["context"]
    assert any("qdrant" in item["path"].lower() for item in result["sources"])


def test_local_fallback_works_without_jev_key():
    service = build_service()
    result = asyncio.run(service.retrieve("What is Jev Model and OKF routing?"))
    assert result["decision"]["provider"] in {"local-fallback", "none"}
    assert result["context"]
