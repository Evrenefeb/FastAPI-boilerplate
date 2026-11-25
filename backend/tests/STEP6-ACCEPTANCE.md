# Step 6 - Acceptance & Validation tests

Author: Nabeel Hindieh

This branch adds the Step 6 test code. No application code is changed.

| Part | File(s) | What it checks |
|---|---|---|
| Phase A - API contract (no database) | `tests/unit/interfaces/test_phase_a_contract.py` | OpenAPI spec vs real API behaviour (46 checks) |
| Phase A - API contract (database) | `tests/integration/test_phase_a_database_contract.py` | Signup, login, profile, update, delete, permission denial with a real database (6 checks) |
| Phase B/C - functional acceptance | `tests/integration/phase_b/` (`cases.py`, `conftest.py`, `test_acceptance.py`) | 47 acceptance cases for FRQ-3.6.1 to FRQ-3.6.9 |

## The tests are opt-in

These tests are **skipped by default**, so they do not change anyone else's test run.
They only run when their output folder variable is set:

- `PHASE_A_OUTPUT` for the Phase A tests
- `PHASE_B_OUTPUT` for the acceptance suite

The tests write their evidence files (JSON, logs) into that folder.

## Expected results

- Phase A without database: **25 passed, 21 failed**. The 21 failures are on purpose. They show the 4 open API documentation issues (D1-D4). Do not change the assertions to hide them.
- Phase A with database: 6 passed.
- Acceptance suite: 47 passed, in both normal and reverse order.

## Requirements

- Python 3.11 or newer, with the repo installed: `uv sync --all-packages --all-extras`
- For Phase A only: `uv pip install jsonschema openapi-spec-validator`
- Docker Desktop running (the database tests start a temporary `postgres:16-alpine` container). If Docker is not running, the database tests are skipped, not passed.

## How to run (PowerShell, from the `backend` folder)

```powershell
# Phase A (use a new empty folder each time)
$env:PHASE_A_OUTPUT = "$env:TEMP\step6\phase-a"
../.venv/Scripts/python.exe -m pytest tests/unit/interfaces/test_phase_a_contract.py tests/integration/test_phase_a_database_contract.py -rs

# Acceptance suite (takes a few minutes; one case waits 62 seconds for the idle timeout)
$env:PHASE_B_OUTPUT = "$env:TEMP\step6\acceptance-normal"
$env:ACCEPTANCE_ORDER = "normal"      # or "reverse"
$env:SESSION_TIMEOUT_MINUTES = "1"
$env:SESSION_BACKEND = "memory"
$env:RATE_LIMITER_BACKEND = "memory"
$env:CSRF_ENABLED = "true"
$env:SESSION_SECURE_COOKIES = "false"
$env:EMAIL_BACKEND = "console"
$env:SECRET_KEY = "acceptance_test_only_secret_key_32_bytes_minimum"
../.venv/Scripts/python.exe -m pytest tests/integration/phase_b/test_acceptance.py -vv -rs
```

Run the acceptance suite on its own (not together with other tests), because it sets a 1-minute session timeout.

## Note for Step 5 (CI)

To run this in GitHub Actions, the job needs Docker (available on `ubuntu-latest`) and the environment variables above. Phase A is expected to fail until D1-D4 are fixed or accepted, so it should not block the pipeline gate unless the team decides that.
