"""Revised Phase A: disposable PostgreSQL, real login/session authentication.

Only the existing client database dependency is overridden. No auth_client,
principal, permission or current-user overrides are used in these six tests.
"""
import json
import os
from pathlib import Path

import pytest

if 'PHASE_A_OUTPUT' not in os.environ:
    pytest.skip('Step 6 suite is opt-in: set PHASE_A_OUTPUT to an output folder (see tests/STEP6-ACCEPTANCE.md)', allow_module_level=True)
from jsonschema import Draft202012Validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from src.infrastructure.database.session import async_session
from src.interfaces.main import app
from src.modules.user.models import User
from src.modules.user.routes import SIGNUP_ACCEPTED

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]
OUT = Path(os.environ['PHASE_A_OUTPUT'])
OBSERVATIONS = []


def verify(case, stage, checks):
    OBSERVATIONS.append({'case': case, 'stage': stage, 'criteria': checks})
    (OUT/'database-criteria.json').write_text(json.dumps(OBSERVATIONS, indent=2), encoding='utf-8')
    assert all(checks.values()), {'stage': stage, 'criteria': checks}


def conforms(response, path, method, status):
    spec = app.openapi()
    response_spec = spec['paths'][path][method]['responses'].get(str(status), {})
    schema = response_spec.get('content', {}).get('application/json', {}).get('schema')
    return (response.status_code == status and schema is not None
            and response.headers.get('content-type', '').startswith('application/json')
            and Draft202012Validator({**schema, 'components': spec['components']}).is_valid(response.json()))


async def stored(engine, user_id=None, username=None):
    # A new session sees committed state, not the request session's identity map.
    async with async_sessionmaker(engine, expire_on_commit=False)() as db:
        query = select(User)
        query = query.where(User.id == user_id) if user_id is not None else query.where(User.username == username)
        return (await db.execute(query)).scalar_one_or_none()


async def sign_in(case, client, user):
    verify(case, 'authentication-isolation', {
        'only_database_dependency_overridden': set(app.dependency_overrides) == {async_session}})
    response = await client.post('/api/v1/auth/login', data={'username': user['username'], 'password': user['password']})
    body = response.json()
    token = body.get('csrf_token')
    verify(case, 'real-password-login', {
        '200_and_schema': conforms(response, '/api/v1/auth/login', 'post', 200),
        'exact_response_fields': set(body) == {'id', 'username', 'csrf_token'},
        'correct_id': body.get('id') == user['id'],
        'correct_username': body.get('username') == user['username'],
        'csrf_nonempty_string': isinstance(token, str) and bool(token),
        'session_cookie_nonempty': bool(response.cookies.get('session_id')),
        'session_cookie_httponly': any(h.lower().startswith('session_id=') and 'httponly' in h.lower() for h in response.headers.get_list('set-cookie')),
        'csrf_cookie_equals_response': bool(token) and response.cookies.get('csrf_token') == token,
        'no_password_echo': user['password'] not in response.text,
    })
    client.headers['X-CSRF-Token'] = token
    profile = await client.get('/api/v1/users/me')
    verify(case, 'session-round-trip', {
        'protected_profile_200_schema': conforms(profile, '/api/v1/users/me', 'get', 200),
        'session_resolves_correct_identity': profile.json().get('id') == user['id'] and profile.json().get('username') == user['username'],
    })
    return response


async def test_A15_registration_success(client, test_db_engine):
    """Valid signup: exact confirmation, committed identity/hash, real login works."""
    values = {'name': 'Contract User', 'username': 'phasea_user', 'email': 'phasea@example.com', 'password': 'Password123!'}
    before = await stored(test_db_engine, username=values['username'])
    response = await client.post('/api/v1/users/', json=values)
    row = await stored(test_db_engine, username=values['username'])
    verify('A15', 'signup-response-and-persistence', {
        'account_absent_before': before is None,
        '201_and_schema': conforms(response, '/api/v1/users/', 'post', 201),
        'exact_confirmation': response.json() == {'message': SIGNUP_ACCEPTED},
        'committed_row_exists': row is not None,
        'committed_identity': row is not None and row.username == values['username'] and row.email == values['email'] and row.name == values['name'],
        'active_non_superuser': row is not None and not row.is_deleted and not row.is_superuser,
        'password_not_stored_plaintext': row is not None and bool(row.hashed_password) and row.hashed_password != values['password'],
        'no_password_or_hash_in_response': values['password'] not in response.text and 'hashed_password' not in response.text,
    })
    await sign_in('A15', client, {**values, 'id': row.id})


async def test_A16_login_success(client, test_user, test_db_engine):
    """Login binds the response and cookie session to the persisted test account."""
    row = await stored(test_db_engine, user_id=test_user['id'])
    verify('A16', 'persisted-fixture-identity', {'same_account': row is not None and row.username == test_user['username'] and row.email == test_user['email']})
    await sign_in('A16', client, test_user)


async def test_A17_read_profile(client, test_user, test_user_2, test_db_engine):
    """A real session reads another user's exact public profile without private data."""
    await sign_in('A17', client, test_user)
    row = await stored(test_db_engine, user_id=test_user_2['id'])
    response = await client.get('/api/v1/users/' + test_user_2['username'])
    expected = {key: getattr(row, key) for key in ('id', 'name', 'username', 'profile_image_url')}
    verify('A17', 'public-profile', {
        '200_and_schema': conforms(response, '/api/v1/users/{username}', 'get', 200),
        'exact_persisted_target_fields': response.json() == expected,
        'different_from_caller': response.json().get('id') != test_user['id'],
        'no_private_fields': not {'email', 'password', 'hashed_password', 'is_superuser'} & response.json().keys(),
    })


async def test_A18_update_profile(client, test_user, test_user_2, test_db_engine):
    """Real session + CSRF update only the caller and persist only requested changes."""
    await sign_in('A18', client, test_user)
    before = await stored(test_db_engine, user_id=test_user['id'])
    other_before = await stored(test_db_engine, user_id=test_user_2['id'])
    response = await client.patch('/api/v1/users/' + test_user['username'], json={'name': 'Updated User'})
    after = await stored(test_db_engine, user_id=test_user['id'])
    other_after = await stored(test_db_engine, user_id=test_user_2['id'])
    readback = await client.get('/api/v1/users/me')
    verify('A18', 'update-persistence', {
        '200_and_schema': conforms(response, '/api/v1/users/{username}', 'patch', 200),
        'exact_confirmation': response.json() == {'message': 'User updated successfully'},
        'committed_name_changed': after.name == 'Updated User' and before.name != after.name,
        'same_identity_and_untouched_fields': all(getattr(before,k) == getattr(after,k) for k in ('id','username','email','hashed_password','is_superuser','profile_image_url')),
        'other_account_unchanged': all(getattr(other_before,k) == getattr(other_after,k) for k in ('id','name','username','email','hashed_password','is_deleted')),
        'api_readback_matches': readback.status_code == 200 and readback.json().get('id') == after.id and readback.json().get('name') == after.name,
    })


async def test_A19_delete_profile(client, test_user, test_user_2, test_db_engine):
    """Real session deactivation persists soft deletion and prevents later login."""
    await sign_in('A19', client, test_user)
    response = await client.delete('/api/v1/users/' + test_user['username'])
    row = await stored(test_db_engine, user_id=test_user['id'])
    other = await stored(test_db_engine, user_id=test_user_2['id'])
    client.cookies.clear()
    client.headers.pop('X-CSRF-Token', None)
    login = await client.post('/api/v1/auth/login', data={'username': test_user['username'], 'password': test_user['password']})
    verify('A19', 'deactivation-persistence', {
        '200_and_schema': conforms(response, '/api/v1/users/{username}', 'delete', 200),
        'exact_confirmation': response.json() == {'message': 'User account deactivated'},
        'row_retained_same_identity': row is not None and row.id == test_user['id'] and row.username == test_user['username'],
        'committed_soft_delete_and_timestamp': row is not None and row.is_deleted is True and row.deleted_at is not None,
        'other_account_still_active': other is not None and not other.is_deleted,
        'fresh_login_denied': login.status_code == 401,
        'no_new_session': not login.cookies.get('session_id'),
    })


async def test_A20_list_permission_denied(client, test_user, test_db_engine):
    """A real signed-in user without user.read gets 403, not an identity failure."""
    await sign_in('A20', client, test_user)
    permission_response = await client.get('/api/v1/permissions/me')
    response = await client.get('/api/v1/users/')
    row = await stored(test_db_engine, user_id=test_user['id'])
    verify('A20', 'permission-denial', {
        'permission_query_succeeded': permission_response.status_code == 200,
        'user_read_not_granted': 'permissions' in permission_response.json() and 'user.read' not in permission_response.json()['permissions'],
        '403_not_401': response.status_code == 403,
        'exact_error_no_user_list': response.json() == {'detail': 'Insufficient permissions'},
        'json_media': response.headers.get('content-type','').startswith('application/json'),
        '403_documented': '403' in app.openapi()['paths']['/api/v1/users/']['get']['responses'],
        'account_unchanged': row is not None and row.name == test_user['name'] and row.username == test_user['username'] and row.email == test_user['email'] and not row.is_deleted and not row.is_superuser,
    })
