# ruff: noqa: E501
"""Phase A contract tests. Copy to backend/tests/unit/interfaces/ to run.

Uses the repository's conftest and pytest configuration. No startup lifecycle,
database fixture, external service, login, or real user mutation is invoked.
Failures are left as failures: they represent contract discrepancies to review.
"""

import json
import os
import re
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest

if "PHASE_A_OUTPUT" not in os.environ:
    pytest.skip(
        "Step 6 suite is opt-in: set PHASE_A_OUTPUT to an output folder (see tests/STEP6-ACCEPTANCE.md)",
        allow_module_level=True,
    )
from httpx import ASGITransport, AsyncClient
from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]
from openapi_spec_validator import validate  # type: ignore[import-not-found]
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from src.interfaces.main import app
from src.modules.user.schemas import UserCreate, UserUpdate
from src.modules.user.service import UserService

OUT = Path(os.environ["PHASE_A_OUTPUT"])
SPEC = app.openapi()
CASES: list[dict[str, Any]] = []
pytestmark = pytest.mark.unit


def record(case, objective, procedure, expected, actual, passed):
    CASES.append(
        dict(
            id=case,
            objective=objective,
            procedure=procedure,
            expected=expected,
            actual=actual,
            status="PASS" if passed else "FAIL",
            evidence=f"pytest.xml; cases.json#{case}",
        )
    )
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "cases.json").write_text(json.dumps(CASES, indent=2), encoding="utf-8")
    assert passed, actual


def resolve(schema):
    if "$ref" in schema:
        node = SPEC
        for part in schema["$ref"][2:].split("/"):
            node = node[part.replace("~1", "/").replace("~0", "~")]
        return resolve(node)
    return schema


def errors(schema, value):
    # All refs in this spec are local. Keep components available at the root.
    full = {**schema, "components": SPEC["components"]}
    return [e.message for e in Draft202012Validator(full, format_checker=FormatChecker()).iter_errors(value)]


def test_A01_valid_openapi():
    (OUT / "openapi.json").write_text(json.dumps(SPEC, indent=2), encoding="utf-8")
    problem = None
    try:
        validate(SPEC)
    except Exception as exc:
        problem = str(exc)
    record(
        "A01",
        "Check that software tools can read the API description.",
        "Generate app.openapi() and validate its OpenAPI structure and references.",
        "Valid OpenAPI document.",
        problem or f"Valid OpenAPI {SPEC['openapi']}",
        problem is None,
    )


@pytest.mark.asyncio
async def test_A02_served_spec():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.get("/openapi.json")
    record(
        "A02",
        "Ensure clients receive the specification we inspected.",
        "GET /openapi.json and compare with app.openapi().",
        "200 and identical JSON.",
        {"status": r.status_code, "equal": r.json() == SPEC},
        r.status_code == 200 and r.json() == SPEC,
    )


def test_A03_core_operations():
    expected = {
        "/api/v1/users/": {"get", "post"},
        "/api/v1/users/me": {"get"},
        "/api/v1/users/{username}": {"get", "patch", "delete"},
        "/api/v1/auth/login": {"post"},
        "/api/v1/auth/logout": {"post"},
        "/api/v1/permissions": {"get"},
        "/api/v1/roles/": {"get", "post"},
    }
    missing = {
        p: sorted(ms - SPEC["paths"].get(p, {}).keys()) for p, ms in expected.items() if ms - SPEC["paths"].get(p, {}).keys()
    }
    record(
        "A03",
        "Check the core API addresses and actions.",
        "Compare required path/method pairs with OpenAPI.",
        "All core operations present.",
        missing or "All present.",
        not missing,
    )


def test_A04_registration_fields():
    s = SPEC["components"]["schemas"]["UserCreate"]
    actual = {"required": s.get("required"), "additionalProperties": s.get("additionalProperties")}
    record(
        "A04",
        "Explain what a registration form must send.",
        "Inspect UserCreate required fields and extra-field policy.",
        "name, username, email and password required; extra fields forbidden.",
        actual,
        set(s["required"]) == {"name", "username", "email", "password"} and s["additionalProperties"] is False,
    )


def test_A05_login_form():
    op = SPEC["paths"]["/api/v1/auth/login"]["post"]
    content = op["requestBody"]["content"]
    s = resolve(content["application/x-www-form-urlencoded"]["schema"])
    record(
        "A05",
        "Check how login credentials must be submitted.",
        "Inspect login media type and required form fields.",
        "Form-encoded username/password required, remember_me optional.",
        s,
        {"username", "password"} <= set(s["required"]) and "remember_me" not in s["required"],
    )


def test_A06_profile_privacy_schema():
    schemas = SPEC["components"]["schemas"]
    public = schemas["UserProfileRead"]["properties"]
    own = schemas["UserRead"]["properties"]
    record(
        "A06",
        "Check that response descriptions do not expose password fields or public email.",
        "Inspect UserRead and UserProfileRead fields.",
        "Neither includes passwords; public profile excludes email.",
        {"public_fields": list(public), "own_fields": list(own)},
        not {"password", "hashed_password"} & (public.keys() | own.keys()) and "email" not in public,
    )


@pytest.mark.parametrize("field", ["name", "username", "profile_image_url"])
def test_A07_update_null_contract(field):
    value = {field: None}
    schema_errors = errors({"$ref": "#/components/schemas/UserUpdate"}, value)
    try:
        UserUpdate.model_validate(value)
        accepted = True
    except ValidationError:
        accepted = False
    record(
        "A07-" + field,
        "Check whether optional also means null is allowed.",
        f"Validate {value!r} against OpenAPI and the real Pydantic model.",
        "Both validators agree.",
        {"OpenAPI_accepts": not schema_errors, "Pydantic_accepts": accepted},
        (not schema_errors) == accepted,
    )


@pytest.mark.parametrize(
    "label,value",
    [
        ("missing", {}),
        ("bad-email", {"name": "Test User", "username": "contract_user", "email": "invalid", "password": "TestPass123!"}),
        (
            "extra-field",
            {
                "name": "Test User",
                "username": "contract_user",
                "email": "test@example.com",
                "password": "TestPass123!",
                "is_superuser": True,
            },
        ),
    ],
)
@pytest.mark.asyncio
async def test_A08_invalid_signup(label, value, monkeypatch, caplog):
    # Observe the write boundary; authentication and validation stay real.
    create = AsyncMock(side_effect=AssertionError("Invalid input reached create"))
    monkeypatch.setattr(UserService, "create", create)
    try:
        UserCreate.model_validate(value)
        validation = []
    except ValidationError as exc:
        validation = [(list(e["loc"]), e["type"]) for e in exc.errors()]
    expected_types = {"missing": "missing", "bad-email": "value_error", "extra-field": "extra_forbidden"}
    expected_fields = {
        "missing": {"name", "username", "email", "password"},
        "bad-email": {"email"},
        "extra-field": {"is_superuser"},
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post("/api/v1/users/", json=value)
    body = r.json()
    checks = {
        "specific_model_error": {loc[0] for loc, kind in validation if kind == expected_types[label]} == expected_fields[label],
        "http_422": r.status_code == 422,
        "json_media": r.headers.get("content-type", "").startswith("application/json"),
        "exact_safe_error": set(body) == {"detail", "support_id"}
        and body.get("detail") == "Invalid request. Please check your input and try again.",
        "support_id": bool(re.fullmatch(r"[0-9a-f]{8}", str(body.get("support_id", "")))),
        "no_create_called": create.call_count == 0,
        "no_session_cookie": "session_id" not in r.cookies,
        "no_password_echo": value.get("password", "unlikely-secret-marker") not in r.text,
        "request_validation_logged": any(
            "Validation error" in rec.message and expected_types[label] in rec.message for rec in caplog.records
        ),
    }
    record(
        "A08-" + label,
        "Reject the specific invalid input before the account creation boundary.",
        f"Compare Pydantic error location/type, POST {label} input with a create spy, inspect HTTP error and log.",
        "Specific validation cause, safe JSON 422, support ID, no session and no creation call. D1 schema parity is tested separately in A09.",
        {"checks": checks, "status": r.status_code, "body": body, "model_errors": validation},
        all(checks.values()),
    )


@pytest.mark.parametrize(
    "path,kwargs",
    [
        ("/api/v1/users/", {"json": {}}),
        ("/api/v1/auth/login", {"data": {}}),
    ],
)
@pytest.mark.asyncio
async def test_A09_validation_response_schema(path, kwargs):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post(path, **kwargs)
    s = SPEC["paths"][path]["post"]["responses"]["422"]["content"]["application/json"]["schema"]
    problems = errors(s, r.json())
    record(
        "A09-" + ("signup" if "users" in path else "login"),
        "Check the documented shape of validation errors.",
        f"POST {path} without required fields, then validate the response body against OpenAPI.",
        "422 response matches its documented JSON schema.",
        {"status": r.status_code, "body": r.json(), "schema_errors": problems},
        r.status_code == 422 and not problems,
    )


PROTECTED = [
    ("get", "/api/v1/users/me", "/api/v1/users/me"),
    ("get", "/api/v1/users/", "/api/v1/users/"),
    ("get", "/api/v1/users/{username}", "/api/v1/users/contract_absent"),
    ("patch", "/api/v1/users/{username}", "/api/v1/users/contract_absent"),
    ("delete", "/api/v1/users/db/{username}", "/api/v1/users/db/contract_absent"),
    ("get", "/api/v1/permissions", "/api/v1/permissions"),
    ("get", "/api/v1/roles/", "/api/v1/roles/"),
    ("get", "/api/v1/auth/me", "/api/v1/auth/me"),
    ("get", "/api/v1/auth/sessions", "/api/v1/auth/sessions"),
]


@pytest.mark.parametrize("method,template,path", PROTECTED)
@pytest.mark.asyncio
async def test_A10_anonymous_rejected(method, template, path, monkeypatch):
    # A DB statement or user write must never run for these anonymous probes.
    execute = AsyncMock(side_effect=AssertionError("Anonymous request reached database"))
    update = AsyncMock(side_effect=AssertionError("Anonymous request reached update"))
    anonymize = AsyncMock(side_effect=AssertionError("Anonymous request reached anonymization"))
    monkeypatch.setattr(AsyncSession, "execute", execute)
    monkeypatch.setattr(UserService, "update", update)
    monkeypatch.setattr(UserService, "anonymize_user", anonymize)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        kwargs: dict[str, Any] = {"json": {"name": "Attempted Update"}} if method == "patch" else {}
        r = await c.request(method, path, **kwargs)
    body = r.json()
    checks = {
        "401": r.status_code == 401,
        "json_media": r.headers.get("content-type", "").startswith("application/json"),
        "error_only": set(body) == {"detail"} and isinstance(body.get("detail"), str) and bool(body["detail"]),
        "no_session_cookie": "session_id" not in r.cookies,
        "no_db_statement": execute.call_count == 0,
        "no_user_mutation": update.call_count == anonymize.call_count == 0,
    }
    record(
        f"A10-{method}-{template}",
        "Reject an anonymous caller before DB statements or protected user mutations.",
        f"Send {method.upper()} {path} with no credentials and observe DB/update/anonymize boundaries; auth is not overridden.",
        "401 JSON error only, no session, no DB statement and no protected user mutation.",
        {"checks": checks, "status": r.status_code, "body": body},
        all(checks.values()),
    )


@pytest.mark.parametrize("method,template,path", PROTECTED)
@pytest.mark.parametrize("criterion", ["security", "401"])
def test_A11_auth_documented(method, template, path, criterion):
    op = SPEC["paths"][template][method]
    requirements = op.get("security", SPEC.get("security", []))
    schemes = SPEC.get("components", {}).get("securitySchemes", {})

    # A nonempty list containing {} permits anonymous use and must fail.
    def recognized(scheme):
        return scheme.get("type") == "apiKey" and (
            (scheme.get("in") == "cookie" and scheme.get("name") == "session_id")
            or (scheme.get("in") == "header" and scheme.get("name", "").lower() == "x-api-key")
        )

    valid = bool(requirements) and all(
        bool(alt) and all(name in schemes and recognized(schemes[name]) and scopes == [] for name, scopes in alt.items())
        for alt in requirements
    )
    # Every tested route accepts a session on its own. An AND with another
    # credential would falsely require both transports.
    session_alone = any(
        len(alt) == 1
        and any(
            schemes.get(name, {}).get("in") == "cookie" and schemes.get(name, {}).get("name") == "session_id" for name in alt
        )
        for alt in requirements
    )
    response = op.get("responses", {}).get("401", {})
    documented_401 = isinstance(response.get("description"), str) and bool(response["description"].strip())
    actual = {
        "security": requirements,
        "all_references_valid_and_no_anonymous_alternative": valid,
        "session_alone_allowed": session_alone,
        "401_response": response,
    }
    record(
        f"A11-{criterion}-{method}-{template}",
        "Describe valid authentication requirements."
        if criterion == "security"
        else "Document authentication failure independently of security metadata.",
        f"Inspect {method.upper()} {template}; resolve schemes, reject anonymous/unknown/wrong-transport alternatives, or check a meaningful 401 response entry.",
        "Valid cookie/API-key references with standalone session alternative."
        if criterion == "security"
        else "Explicit 401 with a nonempty description.",
        actual,
        valid and session_alone if criterion == "security" else documented_401,
    )


@pytest.mark.asyncio
async def test_A12_anonymous_check_auth():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.get("/api/v1/auth/check-auth")
    s = SPEC["paths"]["/api/v1/auth/check-auth"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]
    record(
        "A12",
        "Check the public endpoint that reports whether you are signed in.",
        "GET /api/v1/auth/check-auth without credentials; validate response.",
        "200, authenticated=false, schema-valid body.",
        {"status": r.status_code, "body": r.json()},
        r.status_code == 200 and r.json().get("authenticated") is False and not errors(s, r.json()),
    )


def test_A13_pagination():
    params = {p["name"]: p for p in SPEC["paths"]["/api/v1/users/"]["get"]["parameters"]}
    actual = {n: params[n]["schema"] for n in ("page", "items_per_page")}
    record(
        "A13",
        "Check that clients know the allowed page sizes.",
        "Inspect user listing query parameter bounds.",
        "page >= 1; items_per_page 1..100; defaults 1 and 10.",
        actual,
        actual["page"]["minimum"] == 1
        and actual["page"]["default"] == 1
        and actual["items_per_page"]["minimum"] == 1
        and actual["items_per_page"]["maximum"] == 100
        and actual["items_per_page"]["default"] == 10,
    )


@pytest.mark.parametrize("field,kind", [("id", "integer"), ("username", "string"), ("csrf_token", "string")])
def test_A14_success_response_precision(field, kind):
    op = SPEC["paths"]["/api/v1/auth/login"]["post"]
    s = resolve(op["responses"]["200"]["content"]["application/json"]["schema"])
    valid_body = {"id": 7, "username": "contract_user", "csrf_token": "synthetic-token"}
    absent = {k: v for k, v in valid_body.items() if k != field}
    wrong = {**valid_body, field: "not-an-integer" if kind == "integer" else 17}
    checks = {
        "declared_property_type": resolve(s.get("properties", {}).get(field, {})).get("type") == kind,
        "required": field in s.get("required", []),
        "accepts_valid_shape": not errors(s, valid_body),
        "rejects_missing_field": bool(errors(s, absent)),
        "rejects_wrong_type": bool(errors(s, wrong)),
    }
    record(
        "A14-" + field,
        "Make the actual login response field usable by generated clients.",
        f"Inspect {field} type/required status and validate valid, missing-field and wrong-type examples. Field names come from pinned crudauth complete_login source.",
        f"Required {field}: {kind}; valid shape accepted; missing/wrong type rejected.",
        {"checks": checks, "schema": s},
        all(checks.values()),
    )
