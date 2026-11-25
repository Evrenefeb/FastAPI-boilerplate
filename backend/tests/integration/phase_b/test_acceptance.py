"""Black-box API workflows; DB reads are independent persistence oracles.

Controlled setup: new tables, disjoint generated-ID ranges, outbound email sink,
and test-only admin bootstrap for B19. Authentication/CSRF are never bypassed.
"""

import asyncio
import hashlib
import json
import os
import time
from datetime import UTC, datetime
from http.cookies import SimpleCookie
from pathlib import Path

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, text, update
from sqlalchemy.ext.asyncio import async_sessionmaker

from src.infrastructure.config.settings import get_settings
from src.infrastructure.database.session import async_session
from src.infrastructure.taskiq.email import queued_sender
from src.interfaces.main import app
from src.modules.role.models import Role, RolePermission, UserRole
from src.modules.user.models import User

from .cases import CASES

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]
if "PHASE_B_OUTPUT" not in os.environ:
    pytest.skip(
        "Step 6 suite is opt-in: set PHASE_B_OUTPUT to an output folder (see tests/STEP6-ACCEPTANCE.md)",
        allow_module_level=True,
    )
OUT = Path(os.environ["PHASE_B_OUTPUT"])
PASSWORD = "Password123!"
SIGNUP = "If the address is available, the account has been created."


def fingerprint(value):
    return "sha256:" + hashlib.sha256(str(value).encode()).hexdigest()[:16] if value else ""


def safe(value):
    if isinstance(value, dict):
        return {
            k: (
                "<synthetic password omitted>"
                if k == "password"
                else fingerprint(v)
                if k in ("csrf_token", "session_id", "hashed_password") or (k == "csrf" and isinstance(v, str))
                else safe(v)
            )
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [safe(v) for v in value]
    return value


def safe_headers(headers):
    result = []
    for k, v in headers.multi_items():
        if k.lower() in ("cookie", "set-cookie"):
            parsed = SimpleCookie()
            parsed.load(v)
            for name in parsed:
                parsed[name] = fingerprint(parsed[name].value)
            v = parsed.output(header="").strip()
        elif k.lower() in ("x-csrf-token", "authorization", "x-api-key"):
            v = fingerprint(v)
        result.append([k, v])
    return result


class Trace:
    def __init__(self, case, engine):
        self.case = case
        self.engine = engine
        self.clients = []
        self.emails = []
        self.data = {**case, "status": "Running", "requests": [], "observations": [], "checks": []}
        self.save()

    def save(self):
        (OUT / (self.case["id"] + ".json")).write_text(
            json.dumps(self.data, indent=2, ensure_ascii=False, default=str), encoding="utf-8"
        )

    def observe(self, label, actual):
        self.data["observations"].append({"label": label, "actual": safe(actual)})
        self.save()

    def check(self, label, condition, actual=None):
        self.data["checks"].append({"criterion": label, "passed": bool(condition), "actual": safe(actual)})
        self.save()
        assert condition, {"criterion": label, "actual": safe(actual)}

    def client(self, label):
        c = AsyncClient(
            transport=ASGITransport(app=app, client=(f"198.51.100.{self.case['sequence']}", 12345)),
            base_url="http://test",
            follow_redirects=False,
        )
        c.acceptance_label = label  # type: ignore[attr-defined]
        self.clients.append(c)
        return c

    async def request(self, c, method, path, expected=None, **kwargs):
        start = time.monotonic()
        r = await c.request(method, path, **kwargs)
        try:
            body = r.json()
        except ValueError:
            body = r.text
        self.data["requests"].append(
            {
                "step": len(self.data["requests"]) + 1,
                "client": c.acceptance_label,
                "timestamp_utc": datetime.now(UTC).isoformat(),
                "method": method,
                "url": str(r.request.url),
                "request_headers": safe_headers(r.request.headers),
                "input": safe(kwargs.get("json", kwargs.get("data"))),
                "response_status": r.status_code,
                "response_headers": safe_headers(r.headers),
                "response_body": safe(body),
                "elapsed_seconds": round(time.monotonic() - start, 5),
            }
        )
        self.save()
        if expected is not None:
            self.check(
                f"{method} {path} returns {expected}", r.status_code == expected, {"status": r.status_code, "body": body}
            )
        return r

    async def rows(self, model=User, label=None):
        async with async_sessionmaker(self.engine, expire_on_commit=False)() as db:
            objs = (await db.execute(select(model).order_by(*model.__table__.primary_key.columns))).scalars().all()
            rows = [{col.key: getattr(row, col.key) for col in model.__table__.columns} for row in objs]
        rows = json.loads(json.dumps(safe(rows), default=str))
        if label:
            self.observe(label, rows)
        return rows

    def values(self, alias="a", **changes):
        username = f"b{self.case['sequence']}_{alias}"
        return {
            "name": f"Test User {alias}",
            "username": username,
            "email": username + "@example.com",
            "password": PASSWORD,
            **changes,
        }

    async def register(self, c, alias="a", **changes):
        values = self.values(alias, **changes)
        r = await self.request(c, "POST", "/api/v1/users/", 201, json=values)
        self.check("accepted signup confirmation", r.json() == {"message": SIGNUP}, r.json())
        rows = await self.rows(label="committed users after signup")
        row = next((u for u in rows if u["username"] == values["username"]), None)
        self.check("created identity is persisted", row is not None, rows)
        return {**values, "id": row["id"]}  # type: ignore[index]

    async def login(self, c, user, identifier=None):
        r = await self.request(
            c,
            "POST",
            "/api/v1/auth/login",
            200,
            data={"username": identifier or user["username"], "password": user["password"]},
        )
        body = r.json()
        self.check(
            "login resolves intended identity", body.get("id") == user["id"] and body.get("username") == user["username"], body
        )
        self.check(
            "session and CSRF credentials issued",
            bool(c.cookies.get("session_id")) and isinstance(body.get("csrf_token"), str) and bool(body["csrf_token"]),
            {"session": bool(c.cookies.get("session_id")), "csrf": body.get("csrf_token")},
        )
        c.headers["X-CSRF-Token"] = body["csrf_token"]
        return body

    async def profile(self, c, user):
        r = await self.request(c, "GET", "/api/v1/users/me", 200)
        self.check(
            "protected profile resolves cookie identity",
            r.json().get("id") == user["id"] and r.json().get("username") == user["username"],
            r.json(),
        )
        return r


@pytest_asyncio.fixture
async def t(case, test_db_engine, monkeypatch):
    tracer = Trace(case, test_db_engine)
    # No account ID is reused by a later case in this process. This isolates
    # process-local session storage without mocking the authentication engine.
    async with test_db_engine.begin() as connection:
        await connection.execute(
            text("SELECT setval(pg_get_serial_sequence('\"user\"','id'), :start, false)"), {"start": case["sequence"] * 1000}
        )
    sessions = async_sessionmaker(test_db_engine, expire_on_commit=False)

    async def isolated_database():
        async with sessions() as db:
            yield db

    assert not app.dependency_overrides
    app.dependency_overrides[async_session] = isolated_database

    async def capture_email(**message):
        record = {"to": message["to"], "kind": str(message["kind"]), "subject": message["subject"]}
        tracer.emails.append(record)
        tracer.observe("outbound email captured locally; not delivered", record)

    monkeypatch.setattr(queued_sender, "send", capture_email)
    cfg = get_settings()
    tracer.check(
        "CSRF enabled; only database dependency redirected",
        cfg.CSRF_ENABLED and set(app.dependency_overrides) == {async_session},
        {"csrf": cfg.CSRF_ENABLED, "overrides": ["async_session"]},
    )
    tracer.observe(
        "environment",
        {
            "idle_minutes": cfg.SESSION_TIMEOUT_MINUTES,
            "session_backend": cfg.SESSION_BACKEND,
            "rate_limiter_backend": cfg.RATE_LIMITER_BACKEND,
            "database": "disposable PostgreSQL; fresh tables",
            "synthetic_client_ip": f"198.51.100.{case['sequence']}",
            "unique_user_id_start": case["sequence"] * 1000,
        },
    )
    try:
        yield tracer
    finally:
        for c in tracer.clients:
            await c.aclose()
        app.dependency_overrides.clear()


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
async def test_functional_acceptance(case, t):
    scenario = case["scenario"]
    values = case["input"]
    a = t.client("A")
    b = t.client("B")
    if scenario == "invalid_registration":
        before = await t.rows(label="before invalid signup")
        body = t.values(**{k: v for k, v in values.items() if k != "omit"})
        if "omit" in values:
            body.pop(values["omit"])
        r = await t.request(a, "POST", "/api/v1/users/", 422, json=body)
        t.check("invalid signup has no persistent side effects", await t.rows(label="after invalid signup") == before)
        t.check(
            "no session or password echo",
            not a.cookies.get("session_id") and body.get("password", "__not_present__") not in r.text,
        )
        return
    if scenario == "registration":
        u = await t.register(a, **values)
        rows = await t.rows(label="registration durable state")
        t.check(
            "exact ordinary active account stored",
            len(rows) == 1
            and all(rows[0][k] == u[k] for k in ("name", "username", "email"))
            and not rows[0]["is_superuser"]
            and not rows[0]["is_deleted"],
            rows,
        )
        await t.login(a, u)
        p = await t.profile(a, u)
        t.check("own profile carries correct email", p.json().get("email") == u["email"], p.json())
        return

    u = await t.register(a)
    if scenario in ("duplicate_username", "duplicate_email"):
        before = await t.rows(label="before duplicate")
        body = t.values("duplicate")
        field = "username" if scenario == "duplicate_username" else "email"
        body[field] = u[field]
        r = await t.request(a, "POST", "/api/v1/users/", 409 if field == "username" else 201, json=body)
        t.check("duplicate leaves all original rows unchanged", await t.rows(label="after duplicate") == before)
        if field == "email":
            t.check("response conceals existing email", r.json() == {"message": SIGNUP}, r.json())
            t.check(
                "existing address notice handed to local adapter",
                len(t.emails) == 1 and t.emails[0]["to"] == u["email"],
                t.emails,
            )
        return
    if scenario in ("bad_login", "unknown_login", "email_login"):
        before = await t.rows(label="before credentials attempt")
        if scenario == "email_login":
            await t.login(a, u, identifier=u["email"])
            await t.profile(a, u)
        else:
            credentials = {
                "username": u["username"] if scenario == "bad_login" else "absent_acceptance_user",
                "password": "WrongPassword9!",
            }
            await t.request(a, "POST", "/api/v1/auth/login", 401, data=credentials)
            t.check("failed credentials issue no session", not a.cookies.get("session_id"))
            await t.request(a, "GET", "/api/v1/users/me", 401)
        t.check("credentials attempt preserves account", await t.rows(label="after credentials attempt") == before)
        return
    if scenario == "anonymous":
        before = await t.rows(label="before anonymous action")
        method = values["method"]
        path = "/api/v1/users/me" if method == "GET" else "/api/v1/users/" + u["username"]
        await t.request(a, method, path, 401, **({"json": {"name": "Unauthorized"}} if method == "PATCH" else {}))
        t.check("anonymous action changes no account", await t.rows(label="after anonymous action") == before)
        return

    await t.login(a, u)
    if scenario == "profile":
        v = await t.register(b, "other")
        own = await t.profile(a, u)
        t.check("owner can see own email", own.json().get("email") == u["email"])
        r = await t.request(a, "GET", "/api/v1/users/" + v["username"], 200)
        row = next(x for x in await t.rows(label="public profile source") if x["id"] == v["id"])
        t.check(
            "public target fields exact and private fields absent",
            r.json() == {k: row[k] for k in ("id", "name", "username", "profile_image_url")},
            r.json(),
        )
        await t.request(a, "GET", "/api/v1/users/absent_acceptance_user", 404)
        return
    if scenario in ("update", "rename_conflict", "empty_update", "invalid_update"):
        v = await t.register(b, "other")
        before = await t.rows(label="before profile update")
        body = (
            {"name": "Persisted Name", "profile_image_url": "https://example.com/new.png"}
            if scenario == "update"
            else {"username": v["username"], "name": "Should Not Persist"}
            if scenario == "rename_conflict"
            else {}
            if scenario == "empty_update"
            else values
        )
        expected = 409 if scenario == "rename_conflict" else 422 if scenario == "invalid_update" else 200
        r = await t.request(a, "PATCH", "/api/v1/users/" + u["username"], expected, json=body)
        after = await t.rows(label="after profile update")
        if scenario == "update":
            wanted = [{**x, **body} if x["id"] == u["id"] else x for x in before]
            t.check("only requested fields changed durably", strip_updated(after) == strip_updated(wanted), after)
            t.check("update confirmation", r.json() == {"message": "User updated successfully"}, r.json())
            c = t.client("A-new-login")
            await t.login(c, u)
            p = await t.profile(c, u)
            t.check("changes survive independent login", all(p.json().get(k) == v for k, v in body.items()), p.json())
        elif scenario == "empty_update":
            t.check("empty PATCH preserves business state", strip_updated(before) == strip_updated(after), after)
            await t.profile(a, u)
        else:
            t.check("rejected update has no partial persistence", after == before, after)
        return
    if scenario == "forbidden":
        v = await t.register(b, "other")
        before = await t.rows(label="before forbidden action")
        action = values["action"]
        method = "PATCH" if action == "patch-other" else "GET" if action == "admin-read" else "DELETE"
        suffix = "active-and-inactive/" if action == "admin-read" else "db/" if action == "anonymize-other" else ""
        await t.request(
            a,
            method,
            "/api/v1/users/" + suffix + v["username"],
            403,
            **({"json": {"name": "Unauthorized"}} if method == "PATCH" else {}),
        )
        t.check("forbidden action preserves both accounts", await t.rows(label="after forbidden action") == before)
        return
    if scenario == "csrf":
        if values["token"] == "foreign":
            v = await t.register(b, "other")
            foreign = await t.login(b, v)
            token = foreign["csrf_token"]
        else:
            token = "deliberately-invalid-token"
        before = await t.rows(label="before rejected CSRF mutation")
        if values["token"] == "missing":
            a.headers.pop("X-CSRF-Token")
        else:
            a.headers["X-CSRF-Token"] = token
        action = values["action"]
        method = "POST" if action == "LOGOUT" else action
        path = "/api/v1/auth/logout" if action == "LOGOUT" else "/api/v1/users/" + u["username"]
        await t.request(a, method, path, 403, **({"json": {"name": "Should Not Persist"}} if action == "PATCH" else {}))
        t.check("CSRF rejection preserves database", await t.rows(label="after rejected CSRF mutation") == before)
        await t.profile(a, u)
        return
    if scenario == "logout":
        before = await t.rows(label="before logout")
        cookie = a.cookies.get("session_id")
        r = await t.request(a, "POST", "/api/v1/auth/logout", 200)
        t.check(
            "logout confirmation and cookie cleared",
            r.json() == {"message": "Logged out successfully"} and not a.cookies.get("session_id"),
            r.json(),
        )
        await t.request(a, "GET", "/api/v1/users/me", 401)
        c = t.client("old-cookie-replay")
        c.cookies.set("session_id", cookie)
        await t.request(c, "GET", "/api/v1/users/me", 401)
        t.check("logout does not deactivate or modify account", await t.rows(label="after logout") == before)
        return
    if scenario == "logout_all":
        await t.login(b, u)
        await t.profile(a, u)
        await t.profile(b, u)
        old = [a.cookies.get("session_id"), b.cookies.get("session_id")]
        before = await t.rows(label="before logout-all")
        r = await t.request(a, "POST", "/api/v1/auth/logout-all", 200)
        t.check("both sessions revoked", r.json().get("revoked") == 2, r.json())
        for i, cookie in enumerate(old):
            c = t.client("replay-" + str(i))
            c.cookies.set("session_id", cookie)
            await t.request(c, "GET", "/api/v1/users/me", 401)
        t.check("logout-all preserves account", await t.rows(label="after logout-all") == before)
        return
    if scenario == "role_lifecycle":
        admin = await t.register(b, "admin")
        async with async_sessionmaker(t.engine)() as db:
            await db.execute(update(User).where(User.id == admin["id"]).values(is_superuser=True))
            await db.commit()
        t.observe(
            "controlled precondition only",
            {"test_admin_id": admin["id"], "bootstrap": "DB flag set before real login; no auth override"},
        )
        await t.login(b, admin)
        await t.profile(a, u)
        await t.request(a, "GET", "/api/v1/users/", 403)
        role = await t.request(
            b, "POST", "/api/v1/roles/", 201, json={"name": "acceptance_reader", "permissions": ["user.read"]}
        )
        rid = role.json()["id"]
        await t.request(b, "POST", f"/api/v1/roles/{rid}/users/{u['id']}", 201)
        assignments = await t.rows(UserRole, "committed grants")
        permissions = await t.rows(RolePermission, "committed role permissions")
        t.check(
            "role and assignment persisted",
            any(x["user_id"] == u["id"] and x["role_id"] == rid for x in assignments)
            and any(x["role_id"] == rid and x["permission_name"] == "user.read" for x in permissions),
        )
        r = await t.request(a, "GET", "/api/v1/users/", 200)
        t.check(
            "granted permission exposes expected accounts",
            {u["id"], admin["id"]} <= {x["id"] for x in r.json()["data"]},
            r.json(),
        )
        await t.request(b, "DELETE", f"/api/v1/roles/{rid}/users/{u['id']}", 200)
        t.check("assignment removed from database", await t.rows(UserRole, "committed grants after revoke") == [])
        await t.request(a, "GET", "/api/v1/users/", 403)
        return
    if scenario == "expiration":
        before = await t.rows(label="before idle wait")
        await t.profile(a, u)
        t.check("one-minute isolated idle configuration", get_settings().SESSION_TIMEOUT_MINUTES == 1)
        start = time.monotonic()
        await asyncio.sleep(31)
        await asyncio.sleep(31)
        t.observe("actual no-request idle duration seconds", time.monotonic() - start)
        await t.request(a, "GET", "/api/v1/users/me", 401)
        t.check("expiration preserves account", await t.rows(label="after idle expiration") == before)
        return
    if scenario == "deactivation":
        c = t.client("A-second-session")
        await t.login(c, u)
        v = await t.register(b, "other")
        await t.login(b, v)
        before = await t.rows(label="before deactivation")
        r = await t.request(a, "DELETE", "/api/v1/users/" + u["username"], 200)
        after = await t.rows(label="after deactivation")
        row = next(x for x in after if x["id"] == u["id"])
        t.check("deactivation confirmation", r.json() == {"message": "User account deactivated"}, r.json())
        t.check(
            "soft deletion durably retains identity",
            row["is_deleted"] is True and row["deleted_at"] is not None and row["username"] == u["username"],
            row,
        )
        t.check(
            "other account unchanged",
            next(x for x in after if x["id"] == v["id"]) == next(x for x in before if x["id"] == v["id"]),
        )
        await t.request(a, "GET", "/api/v1/users/me", 401)
        await t.request(c, "GET", "/api/v1/users/me", 401)
        fresh = t.client("A-fresh-login")
        await t.request(fresh, "POST", "/api/v1/auth/login", 401, data={"username": u["username"], "password": u["password"]})
        t.check("deactivated account gets no new session", not fresh.cookies.get("session_id"))
        await t.request(b, "GET", "/api/v1/users/" + u["username"], 404)
        await t.profile(b, v)
        return
    if scenario == "role_denied":
        before = await t.rows(label="before forbidden role creation")
        roles = await t.rows(Role, "roles before")
        await t.request(a, "POST", "/api/v1/roles/", 403, json={"name": "unauthorized_role", "permissions": ["user.read"]})
        t.check("no unauthorized role persisted", await t.rows(Role, "roles after") == roles)
        t.check("ordinary account unchanged", await t.rows(label="after forbidden role creation") == before)
        return
    raise AssertionError("Unhandled scenario " + scenario)


def strip_updated(rows):
    return [{k: v for k, v in row.items() if k != "updated_at"} for row in rows]
