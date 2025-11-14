import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from main import app
from model import init_db


@pytest_asyncio.fixture(autouse=True, scope="function")
async def init_test_db():
    await init_db()


@pytest.mark.asyncio
async def test_user_registration_flow():
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        # Test user registration
        response = await client.post(
            "/register",
            json={"username": "testuser", "password": "testpass123", "role": "user"},
        )
        data = response.json()
        assert response.status_code == 200
        assert data["access_token"]
        assert data["refresh_token"]
        assert data["expires_in"]

        access_token = data["access_token"]

        headers = {"Authorization": f"Bearer {access_token}"}
        auth_response = await client.get("/read_user", headers=headers)
        assert auth_response.status_code == 200
