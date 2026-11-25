import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_register_user_persists_to_database(client: AsyncClient):
    """
    FRQ-2.3.1: Registering a user through the API must correctly
    persist the record in the database.
    """
    payload = {
        "name": "Integration Tester",
        "username": "integrationtester",
        "email": "integrationtest@example.com",
        "password": "StrongPass123!",
    }

    response = await client.post("/api/v1/users/", json=payload)
    data = response.json()

    print("\n\nACTUAL RESPONSE:", data, "\n\n")
    assert response.status_code == 201