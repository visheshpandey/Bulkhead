from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient

from app.main import app


def test_evaluate_requires_a_non_blank_target() -> None:
    response = TestClient(app).post("/api/evaluate", json={"action_type": "read_file"})

    assert response.status_code == 422
    assert "target" in response.text.lower()


def test_evaluate_rejects_oversized_content() -> None:
    response = TestClient(app).post(
        "/api/evaluate",
        json={"action_type": "read_file", "target": "/workspace/a", "content": "x" * 200_001},
    )

    assert response.status_code == 422


def test_evaluate_rejects_oversized_payload_json() -> None:
    response = TestClient(app).post(
        "/api/evaluate",
        json={"action_type": "read_file", "target": "/workspace/a", "payload": {"blob": "x" * 200_001}},
    )

    assert response.status_code == 422


def test_evaluate_rejects_unknown_flat_fields() -> None:
    response = TestClient(app).post(
        "/api/evaluate",
        json={"action_type": "read_file", "target": "/workspace/a", "unexpected": "value"},
    )

    assert response.status_code == 422


def test_two_hundred_distinct_agents_can_evaluate_without_errors() -> None:
    client = TestClient(app)
    client.post("/api/reset-demo")

    def submit(index: int) -> int:
        return client.post(
            "/api/evaluate",
            headers={"X-Agent-Id": f"parallel-agent-{index}"},
            json={"action_type": "read_file", "target": "/workspace/README.md"},
        ).status_code

    with ThreadPoolExecutor(max_workers=20) as executor:
        statuses = list(executor.map(submit, range(200)))

    assert statuses == [200] * 200
    assert TestClient(app).get("/api/stats").json()["events"] == 200
