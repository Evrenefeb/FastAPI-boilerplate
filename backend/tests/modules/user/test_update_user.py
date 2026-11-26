import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_update_user_profile(client: AsyncClient):
    """
    FRQ-3.3.3: An authenticated user can update their own profile,
    and the change is correctly persisted and reflected on retrieval.
    """
    payload = {
        "name": "Integration Tester",
        "username": "integrationtester",
        "email": "integrationtest@example.com",
        "password": "StrongPass123!",
    }
    register_response = await client.post("/api/v1/users/", json=payload)
    assert register_response.status_code == 201

    login_response = await client.post(
        "/api/v1/auth/login",
        data={"username": payload["username"], "password": payload["password"]},
    )
    assert login_response.status_code == 200
    csrf_token = login_response.json()["csrf_token"]

    update_response = await client.patch(
        f"/api/v1/users/{payload['username']}",
        json={"name": "Updated Tester Name"},
        headers={"X-CSRF-Token": csrf_token},
    )
    assert update_response.status_code == 200

    profile_response = await client.get(f"/api/v1/users/{payload['username']}")
    assert profile_response.json()["name"] == "Updated Tester Name"