import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_deactivate_own_account(client: AsyncClient, test_user: dict):
    """
    FRQ-3.3.4: An authenticated user can deactivate their own account,
    and the account can no longer be used to log in afterward.
    """
    login_response = await client.post(
        "/api/v1/auth/login",
        data={"username": test_user["username"], "password": test_user["password"]},
    )
    assert login_response.status_code == 200
    csrf_token = login_response.json()["csrf_token"]

    delete_response = await client.delete(
        f"/api/v1/users/{test_user['username']}",
        headers={"X-CSRF-Token": csrf_token},
    )
    assert delete_response.status_code == 200

    second_login_response = await client.post(
        "/api/v1/auth/login",
        data={"username": test_user["username"], "password": test_user["password"]},
    )
    assert second_login_response.status_code != 200