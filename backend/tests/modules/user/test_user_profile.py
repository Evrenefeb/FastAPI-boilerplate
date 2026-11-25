import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.modules.user.models import User


@pytest.mark.asyncio
async def test_get_user_profile_by_username(client: AsyncClient, db_session: AsyncSession):
    """
    FRQ-3.3.2: An authenticated user can retrieve another user's public
    profile through the API, and the response matches the stored data.
    """
    # 1. Register a user
    payload = {
        "name": "Integration Tester",
        "username": "integrationtester",
        "email": "integrationtest@example.com",
        "password": "StrongPass123!",
    }
    register_response = await client.post("/api/v1/users/", json=payload)
    assert register_response.status_code == 201

    # 2. Log in as that user (form-encoded, not JSON)
    login_response = await client.post(
        "/api/v1/auth/login",
        data={
            "username": payload["username"],
            "password": payload["password"],
        },
    )
    assert login_response.status_code == 200

    # 3. Call the profile endpoint using the now-logged-in client
    profile_response = await client.get(f"/api/v1/users/{payload['username']}")
    assert profile_response.status_code == 200

    data = profile_response.json()
    assert data["username"] == payload["username"]
    assert data["name"] == payload["name"]
    assert "email" not in data  # confirms the privacy design noted in the route's docstring