"""Acceptance evidence and verified disposable-database lifecycle."""
import json
import os
from pathlib import Path

import pytest
import pytest_asyncio
from sqlalchemy import inspect, select, func, text
from src.infrastructure.database.session import Base, build_engine

# Opt-in: without PHASE_B_OUTPUT the suite is skipped and these hooks do nothing.
ENABLED = 'PHASE_B_OUTPUT' in os.environ
OUT = Path(os.environ.get('PHASE_B_OUTPUT', '.'))
if ENABLED:
    OUT.mkdir(parents=True, exist_ok=True)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    if not ENABLED:
        return
    report = outcome.get_result()
    case = getattr(item, 'callspec', None)
    if case is None or 'case' not in case.params:
        return
    case = case.params['case']
    path = OUT / (case['id'] + '.json')
    data = json.loads(path.read_text(encoding='utf-8')) if path.exists() else {**case, 'requests': [], 'observations': [], 'checks': []}
    # Trace.save writes the workflow independently; retain setup in a sidecar.
    phase_path = OUT / (case['id'] + '.phases.json')
    phases = json.loads(phase_path.read_text()) if phase_path.exists() else {}
    phases[report.when] = {'outcome': report.outcome, 'duration_seconds': report.duration}
    phase_path.write_text(json.dumps(phases, indent=2), encoding='utf-8')
    data['pytest_phases'] = phases
    data.setdefault('pytest_phases', {})[report.when] = {'outcome': report.outcome, 'duration_seconds': report.duration}
    if report.failed or report.skipped:
        data['diagnostic'] = str(report.longrepr)
        data['status'] = 'Blocked' if report.skipped or report.when != 'call' else 'Fail'
    elif report.when == 'call':
        data['status'] = 'Pass'
    data['evidence_location'] = f"{case['id']}.json; pytest.xml; pytest.log"
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding='utf-8')


def pytest_collection_modifyitems(items):
    """Keep stable case identities while deliberately varying execution order."""
    if not ENABLED:
        return
    if os.environ.get('ACCEPTANCE_ORDER', 'normal') == 'reverse':
        items.reverse()
    (OUT/'collection.json').write_text(json.dumps([i.nodeid for i in items], indent=2), encoding='utf-8')


@pytest_asyncio.fixture
async def test_db_engine(test_db_url, pg_container, case):
    """Only the existing disposable container supplies the database URL."""
    engine = build_engine(test_db_url)
    record = {'case': case['id'], 'container_id': pg_container.get_wrapped_container().id}
    path = OUT/(case['id']+'.isolation.json')
    def save():
        path.write_text(json.dumps(record, indent=2), encoding='utf-8')
    try:
        async with engine.begin() as connection:
            record['tables_before_create'] = await connection.run_sync(lambda c: inspect(c).get_table_names())
            save()
            assert record['tables_before_create'] == [], 'Previous case left database tables behind'
            await connection.run_sync(Base.metadata.create_all)
            record['postgres_version'] = (await connection.execute(text('SELECT version()'))).scalar_one()
            record['initial_row_counts'] = {table.name: (await connection.execute(select(func.count()).select_from(table))).scalar_one() for table in Base.metadata.sorted_tables}
            save()
            assert all(n == 0 for n in record['initial_row_counts'].values()), 'Case did not start with empty tables'
        yield engine
    finally:
        try:
            async with engine.begin() as connection:
                await connection.run_sync(Base.metadata.drop_all)
                record['tables_after_drop'] = await connection.run_sync(lambda c: inspect(c).get_table_names())
                save()
                assert record['tables_after_drop'] == [], 'Database cleanup failed'
        finally:
            await engine.dispose()
            record['engine_disposed'] = True
            save()
