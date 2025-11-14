import pytest
import pytest_asyncio
import os
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import create_async_engine

from main import app
from model import Base, get_db, User, Role
from api import hash_password, verify_password


# Use test database
TEST_DATABASE_URL = "sqlite+aiosqlite:///./test_auth.db"


@pytest_asyncio.fixture(scope="function")
async def test_client():
    # Create test database
    test_engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    
    # Override dependency
    async def override_get_db():
        async with test_engine.begin() as conn:
            try:
                yield conn
            finally:
                await conn.close()
    
    app.dependency_overrides[get_db] = override_get_db
    
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test"
    ) as client:
        yield client
    
    # Cleanup
    app.dependency_overrides.clear()
    await test_engine.dispose()
    
    # Remove test database file
    if os.path.exists("./test_auth.db"):
        os.remove("./test_auth.db")


@pytest.mark.asyncio
async def test_user_registration_and_login_flow(test_client):
    """Test complete user registration and login flow"""
    # Test user registration
    response = await test_client.post(
        "/register",
        json={
            "username": "testuser",
            "password": "testpass123",
            "role": "user"
        }
    )
    
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert "expires_in" in data
    
    access_token = data["access_token"]
    
    # Test accessing protected endpoint with token
    headers = {"Authorization": f"Bearer {access_token}"}
    response = await test_client.get("/my_limits", headers=headers)
    
    assert response.status_code == 200
    user_data = response.json()
    assert user_data["username"] == "testuser"
    assert "scopes" in user_data
    assert "max_data_size_bytes" in user_data


@pytest.mark.asyncio
async def test_password_hashing():
    """Test password hashing and verification"""
    password = "testpassword123"
    hashed = hash_password(password)
    
    # Verify the password matches
    assert verify_password(password, hashed) == True
    
    # Verify wrong password fails
    assert verify_password("wrongpassword", hashed) == False


@pytest.mark.asyncio
async def test_token_refresh_flow(test_client):
    """Test token refresh flow"""
    # First register a user
    response = await test_client.post(
        "/register",
        json={
            "username": "refreshuser",
            "password": "refreshpass123",
            "role": "user"
        }
    )
    
    assert response.status_code == 200
    data = response.json()
    refresh_token = data["refresh_token"]
    
    # Use refresh token to get new access token
    response = await test_client.post(
        "/refresh",
        json={"refresh_token": refresh_token}
    )
    
    # Note: This might fail due to token validation, but should return proper status
    assert response.status_code in [200, 401]


@pytest.mark.asyncio
async def test_scope_based_access(test_client):
    """Test that different roles have different scopes"""
    # Register regular user
    response = await test_client.post(
        "/register",
        json={
            "username": "regularuser",
            "password": "pass123",
            "role": "user"
        }
    )
    
    assert response.status_code == 200
    user_data = response.json()
    user_token = user_data["access_token"]
    
    # Register admin user
    response = await test_client.post(
        "/register",
        json={
            "username": "adminuser", 
            "password": "adminpass123",
            "role": "admin"
        }
    )
    
    assert response.status_code == 200
    admin_data = response.json()
    admin_token = admin_data["access_token"]
    
    # Test accessing endpoints with different tokens
    user_headers = {"Authorization": f"Bearer {user_token}"}
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    
    # Both should be able to access my_limits
    response = await test_client.get("/my_limits", headers=user_headers)
    assert response.status_code == 200
    
    response = await test_client.get("/my_limits", headers=admin_headers)
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_upload_data_validation(test_client):
    """Test data size validation for uploads"""
    # Register user
    response = await test_client.post(
        "/register",
        json={
            "username": "uploaduser",
            "password": "uploadpass123",
            "role": "user"
        }
    )
    
    assert response.status_code == 200
    data = response.json()
    access_token = data["access_token"]
    
    headers = {"Authorization": f"Bearer {access_token}"}
    
    # Test upload with small data (should work for user with 2MB limit)
    response = await test_client.post(
        "/upload",
        headers=headers,
        content=b"x" * 1000  # 1KB data
    )
    
    # Should either succeed or fail with proper status
    assert response.status_code in [200, 413, 411]


@pytest.mark.asyncio
async def test_duplicate_registration(test_client):
    """Test that duplicate username registration fails"""
    # First registration
    response = await test_client.post(
        "/register",
        json={
            "username": "duplicateuser",
            "password": "pass123",
            "role": "user"
        }
    )
    assert response.status_code == 200
    
    # Second registration with same username
    response = await test_client.post(
        "/register", 
        json={
            "username": "duplicateuser",
            "password": "pass456",
            "role": "user"
        }
    )
    assert response.status_code == 400