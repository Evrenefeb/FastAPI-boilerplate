import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_duplicate_registration_does_not_leak_existence(client: AsyncClient):
    """
    FRQ-3.3.5a: Registering with an already-used email returns the same
    response as a successful registration, preventing user enumeration.
    """
    payload = {
        "name": "Integration Tester",
        "username": "integrationtester",
        "email": "integrationtest@example.com",
        "password": "StrongPass123!",
    }
    first_response = await client.post("/api/v1/users/", json=payload)
    assert first_response.status_code == 201

    duplicate_payload = {**payload, "username": "differentusername"}
    second_response = await client.post("/api/v1/users/", json=duplicate_payload)

    assert second_response.status_code == 201
    assert second_response.json() == first_response.json()


@pytest.mark.asyncio
async def test_registration_rejects_invalid_password(client: AsyncClient):
    """
    FRQ-3.3.5b: Registration with a password that violates the configured
    password policy is rejected with a validation error.
    """
    payload = {
        "name": "Integration Tester",
        "username": "shortpassworduser",
        "email": "shortpassword@example.com",
        "password": "a",
    }
    response = await client.post("/api/v1/users/", json=payload)
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_get_nonexistent_user_returns_404(client: AsyncClient, test_user: dict):
    """
    FRQ-3.3.5c: Requesting a profile for a username that doesn't exist
    returns a generic 404, without revealing which usernames are valid.
    """
    login_response = await client.post(
        "/api/v1/auth/login",
        data={"username": test_user["username"], "password": test_user["password"]},
    )
    assert login_response.status_code == 200

    response = await client.get("/api/v1/users/this-username-does-not-exist")
    assert response.status_code == 404
    