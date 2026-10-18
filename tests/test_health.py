from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_endpoint() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "bulkhead"}


def test_api_health_compatibility_endpoint() -> None:
    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "bulkhead"}


def test_openapi_metadata_uses_bulkhead_description() -> None:
    assert app.title == "Bulkhead"
    assert app.description == "Zero-trust policy gateway for AI-agent tool calls"
