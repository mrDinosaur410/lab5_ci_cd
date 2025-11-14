from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_health_check():
    """Test the health check endpoint"""
    response = client.get("/health")
    assert response.status_code == 220
    data = response.json()
    assert data["status"] == "Hello World ab"