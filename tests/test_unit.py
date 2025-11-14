import pytest
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, patch

from main import app
from schema import TokenScope, UserModel
from model import Role

client = TestClient(app)


def test_health_check():
    """Test the health check endpoint"""
    response = client.get("/")
    assert response.status_code == 200


def test_token_scopes():
    """Test token scope enum values"""
    assert TokenScope.data_0mb == "data:0mb"
    assert TokenScope.data_2mb == "data:2mb"
    assert TokenScope.data_10mb == "data:10mb"
    assert TokenScope.data_unlimited == "data:unlimited"


def test_user_model_creation():
    """Test user model creation and validation"""
    user = UserModel(
        username="testuser",
        password="testpass123",
        role=Role.user
    )
    
    assert user.username == "testuser"
    assert user.password == "testpass123"
    assert user.role == Role.user


def test_user_model_default_role():
    """Test user model default role"""
    user = UserModel(
        username="testuser",
        password="testpass123"
    )
    
    assert user.role == Role.user


@patch('api.get_db')
def test_register_endpoint(mock_get_db):
    """Test user registration endpoint"""
    # Mock database session
    mock_session = AsyncMock()
    mock_get_db.return_value = mock_session
    
    # Mock database operations
    mock_session.execute.return_value.scalar_one_or_none.return_value = None
    mock_session.execute.return_value.scalar_one_or_none.return_value = None
    
    response = client.post(
        "/register",
        json={
            "username": "newuser",
            "password": "newpass123",
            "role": "user"
        }
    )
    
    # Should either succeed or fail with appropriate status
    assert response.status_code in [200, 400]


@patch('api.get_db')
def test_login_endpoint(mock_get_db):
    """Test user login endpoint"""
    # Mock database session
    mock_session = AsyncMock()
    mock_get_db.return_value = mock_session
    
    # Mock user not found
    mock_session.execute.return_value.scalar_one_or_none.return_value = None
    
    response = client.post(
        "/login",
        json={
            "username": "nonexistent",
            "password": "password"
        }
    )
    
    assert response.status_code == 401


def test_refresh_token_endpoint():
    """Test refresh token endpoint with invalid token"""
    response = client.post(
        "/refresh",
        json={"refresh_token": "invalid_token"}
    )
    
    # Should fail with authentication error
    assert response.status_code in [401, 422]


def test_protected_endpoints_without_token():
    """Test accessing protected endpoints without token"""
    endpoints = [
        "/my_limits",
        "/data_2mb",
        "/data_10mb",
        "/data_unlimited",
        "/upload"
    ]
    
    for endpoint in endpoints:
        if endpoint == "/upload":
            response = client.post(endpoint)
        else:
            response = client.get(endpoint)
        assert response.status_code == 401  # Unauthorized


def test_token_scope_validation():
    """Test token scope validation logic"""
    from api import get_max_data_size
    
    # Test user scopes
    user_scopes = [TokenScope.data_2mb]
    assert get_max_data_size(user_scopes) == 2 * 1024 * 1024
    
    # Test admin scopes
    admin_scopes = [
        TokenScope.data_0mb,
        TokenScope.data_2mb,
        TokenScope.data_10mb,
        TokenScope.data_unlimited
    ]
    assert get_max_data_size(admin_scopes) == -1  # unlimited
    
    # Test empty scopes
    assert get_max_data_size([]) == 0
    
    # Test mixed scopes
    mixed_scopes = [TokenScope.data_2mb, TokenScope.data_10mb]
    assert get_max_data_size(mixed_scopes) == 10 * 1024 * 1024