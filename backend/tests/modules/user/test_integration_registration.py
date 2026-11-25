import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.modules.user.models import User


@pytest.mark.asyncio
async def test_register_user_persists_to_database(client: AsyncClient, db_session: AsyncSession):
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
    assert response.status_code == 201

    result = await db_session.execute(select(User).where(User.email == payload["email"]))
    created_user = result.scalar_one()

    assert created_user.username == payload["username"]
    assert created_user.name == payload["name"]