"""The connector runner against a real database, with fake connectors and a fake ingest
function (the injected-dependency contract), plus one run through the real Defender
connector over a MockTransport."""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncGenerator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import httpx
import pytest

from lighthouse.connectors.base import (
    Connector,
    ConnectorAuthError,
    ConnectorCredential,
    ConnectorError,
    ConnectorThrottledError,
    ConnectorTransientError,
    FetchResult,
    InMemoryCredentialProvider,
)
from lighthouse.connectors.defender_xdr import DefenderXdrConnector
from lighthouse.db import Pool, tenant_transaction
from lighthouse.ingest import run as runner
from lighthouse.ingest.run import (
    PARTIAL_RUN_NOTE,
    ConnectionRow,
    RunnerSettings,
    create_worker_pool,
    list_active_connections,
    run_once,
)
from lighthouse.ingest.schema import NormalizedAlert
from lighthouse.severity import Severity
from lighthouse.triage import FixtureModel, TriageModel
from tests import conftest
from tests.connector_helpers import (
    RecordingTransport,
    StaticTokens,
    TestCertificate,
    create_connection,
    ensure_worker_role,
    json_response,
    load_fixture,
    make_certificate,
    make_credential,
    set_alert_tenant,
    with_login,
)
from tests.helpers import Conn, create_tenant

SECRET_TITLE = "Customer text that must stay out of audit and logs"


@pytest.fixture(scope="module")
def cert() -> TestCertificate:
    return make_certificate()


@pytest.fixture
async def worker_pool(test_database: conftest.TestDatabase) -> AsyncGenerator[Pool]:
    from tests.connector_helpers import WORKER_LOGIN_ROLE  # noqa: PLC0415

    password = await ensure_worker_role(test_database.superuser_dsn)
    settings = RunnerSettings(
        database_url=with_login(test_database.app_dsn, WORKER_LOGIN_ROLE, password),  # pyright: ignore[reportArgumentType]
        ingest_max_concurrency=4,
    )
    pool = await create_worker_pool(settings)
    try:
        yield pool
    finally:
        await pool.close()


@pytest.fixture(autouse=True)
async def only_this_tests_connections(superuser: Conn) -> None:
    # The runner lists every active connection in the database; start each test clean.
    await superuser.execute("delete from lh.connections")


def _alert(alert_id: str, *, title: str = SECRET_TITLE) -> NormalizedAlert:
    return NormalizedAlert(
        source="defender_xdr",
        source_alert_id=alert_id,
        title=title,
        source_severity=Severity.MEDIUM,
        occurred_at=datetime(2026, 11, 10, 8, 0, tzinfo=UTC),
        category=None,
        evidence={"command_line": SECRET_TITLE},
    )


class FakeConnector:
    def __init__(
        self,
        result: FetchResult | None = None,
        *,
        error: Exception | None = None,
        delay: float = 0.0,
        gauge: Gauge | None = None,
    ) -> None:
        self.result = result
        self.error = error
        self.delay = delay
        self.gauge = gauge
        self.cursors: list[str | None] = []

    async def fetch(self, cursor: str | None) -> FetchResult:
        self.cursors.append(cursor)
        if self.gauge is not None:
            self.gauge.enter()
        try:
            if self.delay:
                await asyncio.sleep(self.delay)
        finally:
            if self.gauge is not None:
                self.gauge.leave()
        if self.error is not None:
            raise self.error
        assert self.result is not None
        return self.result


@dataclass
class Gauge:
    active: int = 0
    peak: int = 0

    def enter(self) -> None:
        self.active += 1
        self.peak = max(self.peak, self.active)

    def leave(self) -> None:
        self.active -= 1


@dataclass
class FakeIngest:
    """Stands in for pipeline.ingest_alert: writes the alert through the tenant's own
    transaction, so a wrong tenant would fail or land visibly in the wrong place."""

    fail_ids: set[str] = field(default_factory=set[str])
    calls: list[tuple[UUID, str, UUID | None]] = field(
        default_factory=list[tuple[UUID, str, UUID | None]]
    )

    async def __call__(
        self, pool: Pool, tenant_id: UUID, alert: NormalizedAlert, model: TriageModel, /
    ) -> object:
        assert isinstance(model, FixtureModel)
        async with tenant_transaction(pool, tenant_id) as conn:
            current = await conn.fetchval("select lh.current_tenant_id()")
            self.calls.append((tenant_id, alert.source_alert_id, current))
            if alert.source_alert_id in self.fail_ids:
                msg = f"simulated failure for {alert.title}"
                raise RuntimeError(msg)
            await conn.execute(
                """
                insert into lh.alerts
                  (tenant_id, source, source_alert_id, title, source_severity, severity)
                values (lh.current_tenant_id(), $1, $2, $3, $4, $4)
                on conflict (tenant_id, source, source_alert_id) do nothing
                """,
                alert.source,
                alert.source_alert_id,
                alert.title,
                alert.source_severity.value,
            )
        return None


@dataclass
class Setup:
    tenant: UUID
    connection: UUID
    directory: UUID
    ref: str


async def _setup(superuser: Conn, cert: TestCertificate, *, status: str = "active") -> Setup:
    tenant = await create_tenant(superuser)
    directory = UUID(int=tenant.int ^ 0xABCDEF)  # any directory id, distinct per tenant
    ref = f"vault:test-{tenant.hex[:12]}"
    connection = await create_connection(
        superuser, tenant, directory=directory, status=status, credential_ref=ref
    )
    del cert
    return Setup(tenant, connection, directory, ref)


def _credentials(cert: TestCertificate, *setups: Setup) -> InMemoryCredentialProvider:
    return InMemoryCredentialProvider(
        {s.ref: make_credential(cert, directory=s.directory) for s in setups}
    )


def _factory(connectors: dict[UUID, Connector]) -> runner.ConnectorFactory:
    def build(row: ConnectionRow, credential: ConnectorCredential) -> Connector:
        assert credential.entra_tenant_id == row.external_tenant_id
        return connectors[row.id]

    return build


async def _run(
    pool: Pool,
    credentials: InMemoryCredentialProvider,
    connectors: dict[UUID, Connector],
    ingest: FakeIngest,
    **kwargs: Any,
) -> dict[UUID, runner.ConnectionOutcome]:
    outcomes = await run_once(
        pool,
        credentials=credentials,
        connector_factory=_factory(connectors),
        ingest=ingest,
        model=FixtureModel(),
        **kwargs,
    )
    return {outcome.connection_id: outcome for outcome in outcomes}


async def _state(superuser: Conn, connection: UUID) -> dict[str, Any]:
    row = await superuser.fetchrow(
        """
        select c.status::text as status, c.last_error, c.last_success_at, k.cursor
          from lh.connections c
          left join lh.connector_cursors k on k.connection_id = c.id
         where c.id = $1
        """,
        connection,
    )
    assert row is not None
    return dict(row.items())


async def _audit(superuser: Conn, tenant: UUID) -> list[tuple[str, str | None, dict[str, Any]]]:
    rows = await superuser.fetch(
        "select action, target, detail from lh.audit_log where tenant_id = $1 order by id",
        tenant,
    )
    return [(row["action"], row["target"], json.loads(row["detail"])) for row in rows]


async def _seed_cursor(superuser: Conn, setup: Setup, cursor: str) -> None:
    await superuser.execute(
        "insert into lh.connector_cursors (connection_id, tenant_id, cursor) values ($1, $2, $3)",
        setup.connection,
        setup.tenant,
        cursor,
    )


# Isolation and cursor semantics ----------------------------------------------------------


async def test_one_failing_connection_does_not_stop_another(
    worker_pool: Pool, superuser: Conn, cert: TestCertificate
) -> None:
    good = await _setup(superuser, cert)
    bad = await _setup(superuser, cert)
    await _seed_cursor(superuser, good, "good-cursor-0")
    await _seed_cursor(superuser, bad, "bad-cursor-0")
    good_connector = FakeConnector(
        FetchResult(alerts=[_alert("a-1"), _alert("a-2")], next_cursor="good-cursor-1", skipped=3)
    )
    bad_connector = FakeConnector(error=ConnectorTransientError("Microsoft Graph error (HTTP 502)"))
    ingest = FakeIngest()

    outcomes = await _run(
        worker_pool,
        _credentials(cert, good, bad),
        {good.connection: good_connector, bad.connection: bad_connector},
        ingest,
    )

    assert outcomes[good.connection].status == "succeeded"
    assert outcomes[good.connection].ingested == 2
    assert outcomes[bad.connection].status == "failed"
    assert outcomes[bad.connection].error_kind == "transient"
    # Each connector got its own stored cursor.
    assert good_connector.cursors == ["good-cursor-0"]
    assert bad_connector.cursors == ["bad-cursor-0"]

    # The ingest function ran under the right tenant, inside that tenant's transaction.
    assert sorted(ingest.calls) == [
        (good.tenant, "a-1", good.tenant),
        (good.tenant, "a-2", good.tenant),
    ]
    stored = await superuser.fetch(
        "select tenant_id, source_alert_id from lh.alerts where source_alert_id in ('a-1', 'a-2')"
    )
    assert {(row["tenant_id"], row["source_alert_id"]) for row in stored} == {
        (good.tenant, "a-1"),
        (good.tenant, "a-2"),
    }

    good_state = await _state(superuser, good.connection)
    assert good_state["cursor"] == "good-cursor-1"
    assert good_state["last_error"] is None
    assert good_state["last_success_at"] is not None
    bad_state = await _state(superuser, bad.connection)
    assert bad_state["cursor"] == "bad-cursor-0"  # not advanced
    assert bad_state["last_error"] == "Microsoft Graph error (HTTP 502)"
    assert bad_state["last_success_at"] is None
    assert bad_state["status"] == "active"  # transient: stays on the schedule

    good_audit = await _audit(superuser, good.tenant)
    assert [action for action, _, _ in good_audit] == [
        "connector.run.started",
        "connector.run.succeeded",
    ]
    assert all(target == str(good.connection) for _, target, _ in good_audit)
    assert good_audit[1][2] == {
        "fetched": 2,
        "ingested": 2,
        "ingest_failures": 0,
        "skipped": 3,
        "pages": 0,
        "truncated": False,
    }
    bad_audit = await _audit(superuser, bad.tenant)
    assert [action for action, _, _ in bad_audit] == [
        "connector.run.started",
        "connector.run.failed",
    ]
    assert bad_audit[1][2]["error_kind"] == "transient"
    # Audit entries hold counts and labels only, never customer text.
    for _, _, detail in good_audit + bad_audit:
        assert SECRET_TITLE not in json.dumps(detail)


async def test_ingest_failure_keeps_cursor(
    worker_pool: Pool, superuser: Conn, cert: TestCertificate
) -> None:
    setup = await _setup(superuser, cert)
    await _seed_cursor(superuser, setup, "cursor-0")
    connector = FakeConnector(
        FetchResult(alerts=[_alert("b-1"), _alert("b-2"), _alert("b-3")], next_cursor="cursor-1")
    )
    ingest = FakeIngest(fail_ids={"b-2"})
    outcomes = await _run(
        worker_pool, _credentials(cert, setup), {setup.connection: connector}, ingest
    )
    outcome = outcomes[setup.connection]
    assert outcome.status == "failed"
    assert (outcome.ingested, outcome.ingest_failures) == (2, 1)
    # Every alert was still attempted: one bad alert does not stop the rest.
    assert [alert_id for _, alert_id, _ in ingest.calls] == ["b-1", "b-2", "b-3"]
    state = await _state(superuser, setup.connection)
    assert state["cursor"] == "cursor-0"
    assert state["last_error"] == "1 alert(s) could not be ingested; cursor not advanced"
    assert SECRET_TITLE not in state["last_error"]


async def test_first_run_stores_cursor(
    worker_pool: Pool, superuser: Conn, cert: TestCertificate
) -> None:
    setup = await _setup(superuser, cert)
    connector = FakeConnector(FetchResult(alerts=[], next_cursor="first"))
    await _run(worker_pool, _credentials(cert, setup), {setup.connection: connector}, FakeIngest())
    assert connector.cursors == [None]
    assert (await _state(superuser, setup.connection))["cursor"] == "first"


async def test_truncated_run_stores_cursor_and_notes_partial(
    worker_pool: Pool, superuser: Conn, cert: TestCertificate
) -> None:
    setup = await _setup(superuser, cert)
    connector = FakeConnector(
        FetchResult(alerts=[_alert("c-1")], next_cursor="same-since-half-window", truncated=True)
    )
    outcomes = await _run(
        worker_pool, _credentials(cert, setup), {setup.connection: connector}, FakeIngest()
    )
    assert outcomes[setup.connection].status == "succeeded"
    assert outcomes[setup.connection].truncated
    state = await _state(superuser, setup.connection)
    assert state["cursor"] == "same-since-half-window"
    assert state["last_error"] == PARTIAL_RUN_NOTE
    assert state["last_success_at"] is not None


# Failure kinds ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("error", "status", "kind"),
    [
        (ConnectorAuthError("the client assertion was rejected", aadsts_code=700027), "error", "auth"),
        (ConnectorThrottledError(30), "active", "throttled"),
        (ValueError(SECRET_TITLE), "active", "error"),
    ],
)
async def test_failure_kinds_recorded(  # noqa: PLR0913 - fixtures plus parameters
    worker_pool: Pool,
    superuser: Conn,
    cert: TestCertificate,
    error: Exception,
    status: str,
    kind: str,
) -> None:
    setup = await _setup(superuser, cert)
    outcomes = await _run(
        worker_pool,
        _credentials(cert, setup),
        {setup.connection: FakeConnector(error=error)},
        FakeIngest(),
    )
    assert outcomes[setup.connection].error_kind == kind
    state = await _state(superuser, setup.connection)
    assert state["status"] == status
    assert SECRET_TITLE not in state["last_error"]
    if isinstance(error, ConnectorError):
        assert state["last_error"] == error.message
    else:
        assert state["last_error"] == "internal error (ValueError)"


async def test_auth_error_takes_connection_off_the_schedule(
    worker_pool: Pool, superuser: Conn, cert: TestCertificate
) -> None:
    setup = await _setup(superuser, cert)
    connectors: dict[UUID, Connector] = {
        setup.connection: FakeConnector(error=ConnectorAuthError("consent revoked"))
    }
    await _run(worker_pool, _credentials(cert, setup), connectors, FakeIngest())
    assert await list_active_connections(worker_pool, limit=10) == []


async def test_time_budget_isolates_a_slow_connection(
    worker_pool: Pool, superuser: Conn, cert: TestCertificate
) -> None:
    slow = await _setup(superuser, cert)
    fast = await _setup(superuser, cert)
    await _seed_cursor(superuser, slow, "slow-0")
    connectors: dict[UUID, Connector] = {
        slow.connection: FakeConnector(FetchResult(alerts=[], next_cursor="slow-1"), delay=30),
        fast.connection: FakeConnector(FetchResult(alerts=[_alert("d-1")], next_cursor="fast-1")),
    }
    outcomes = await _run(
        worker_pool, _credentials(cert, slow, fast), connectors, FakeIngest(), budget_seconds=0.5
    )
    assert outcomes[fast.connection].status == "succeeded"
    assert outcomes[slow.connection].status == "failed"
    slow_state = await _state(superuser, slow.connection)
    assert slow_state["last_error"] == "time budget for this connection was exceeded"
    assert slow_state["cursor"] == "slow-0"


async def test_concurrency_is_bounded(
    worker_pool: Pool, superuser: Conn, cert: TestCertificate
) -> None:
    gauge = Gauge()
    setups = [await _setup(superuser, cert) for _ in range(4)]
    connectors: dict[UUID, Connector] = {
        s.connection: FakeConnector(FetchResult(alerts=[], next_cursor="x"), delay=0.05, gauge=gauge)
        for s in setups
    }
    outcomes = await _run(
        worker_pool, _credentials(cert, *setups), connectors, FakeIngest(), max_concurrency=2
    )
    assert len(outcomes) == 4
    assert gauge.peak <= 2


async def test_credential_for_another_directory_is_refused(
    worker_pool: Pool, superuser: Conn, cert: TestCertificate
) -> None:
    setup = await _setup(superuser, cert)
    # The provider holds a credential for some other customer's directory.
    credentials = InMemoryCredentialProvider({setup.ref: make_credential(cert)})
    connector = FakeConnector(FetchResult(alerts=[_alert("e-1")], next_cursor="x"))
    ingest = FakeIngest()
    outcomes = await _run(worker_pool, credentials, {setup.connection: connector}, ingest)
    assert outcomes[setup.connection].error_kind == "permanent"
    assert connector.cursors == []
    assert ingest.calls == []
    assert (await _state(superuser, setup.connection))["status"] == "error"


async def test_unknown_credential_ref(
    worker_pool: Pool, superuser: Conn, cert: TestCertificate
) -> None:
    setup = await _setup(superuser, cert)
    outcomes = await _run(
        worker_pool,
        InMemoryCredentialProvider({}),
        {setup.connection: FakeConnector(error=AssertionError("must not be called"))},
        FakeIngest(),
    )
    assert outcomes[setup.connection].error == "connector credential not found"


async def test_only_active_connections_are_listed(
    worker_pool: Pool, superuser: Conn, cert: TestCertificate
) -> None:
    active = await _setup(superuser, cert)
    for status in ("pending", "error", "disabled"):
        await _setup(superuser, cert, status=status)
    rows = await list_active_connections(worker_pool, limit=10)
    assert [row.id for row in rows] == [active.connection]
    assert rows[0].tenant_id == active.tenant
    assert rows[0].external_tenant_id == active.directory


async def test_logs_carry_ids_and_counts_only(
    worker_pool: Pool,
    superuser: Conn,
    cert: TestCertificate,
    caplog: pytest.LogCaptureFixture,
) -> None:
    setup = await _setup(superuser, cert)
    connector = FakeConnector(FetchResult(alerts=[_alert("f-1"), _alert("f-2")], next_cursor="x"))
    with caplog.at_level(logging.DEBUG, logger="lighthouse"):
        await _run(
            worker_pool,
            _credentials(cert, setup),
            {setup.connection: connector},
            FakeIngest(fail_ids={"f-2"}),
        )
    for record in caplog.records:
        rendered = runner._JsonFormatter().format(record)  # noqa: SLF001 - the CLI's formatter
        assert SECRET_TITLE not in rendered
    finished = [r for r in caplog.records if r.getMessage() == "connector run finished"]
    assert len(finished) == 1
    assert finished[0].__dict__["lh_connection_id"] == str(setup.connection)


# Real connector, fake network ------------------------------------------------------------


async def test_run_with_defender_connector(
    worker_pool: Pool, superuser: Conn, cert: TestCertificate
) -> None:
    setup = await _setup(superuser, cert)
    page = set_alert_tenant(load_fixture("incidents_page2.json"), setup.directory)
    transport = RecordingTransport(lambda _: json_response(200, page))
    ingest = FakeIngest()
    async with transport.client() as http:

        def factory(row: ConnectionRow, credential: ConnectorCredential) -> Connector:
            return DefenderXdrConnector(
                http=http,
                tokens=StaticTokens(),
                credential=credential,
                external_tenant_id=row.external_tenant_id,
            )

        outcomes = await run_once(
            worker_pool,
            credentials=_credentials(cert, setup),
            connector_factory=factory,
            ingest=ingest,
            model=FixtureModel(),
        )
    (outcome,) = outcomes
    assert outcome.status == "succeeded"
    assert outcome.ingested == 2
    assert {alert_id for _, alert_id, _ in ingest.calls} == {
        "da-synthetic-0004",
        "da-synthetic-0005",
    }
    cursor = (await _state(superuser, setup.connection))["cursor"]
    assert json.loads(cursor)["v"] == 1
    assert transport.hosts == ["graph.microsoft.com"]


# Command line ----------------------------------------------------------------------------


def test_main_refuses_without_a_credential_provider(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.ERROR):
        assert runner.main(["--once"]) == 2
    assert any("credential provider" in record.getMessage() for record in caplog.records)


def test_main_requires_once() -> None:
    with pytest.raises(SystemExit):
        runner.main([])


def test_run_once_rejects_nonsense_limits() -> None:
    async def go() -> None:
        await run_once(
            pool=None,  # pyright: ignore[reportArgumentType]
            credentials=InMemoryCredentialProvider({}),
            connector_factory=_factory({}),
            ingest=FakeIngest(),
            model=FixtureModel(),
            max_concurrency=0,
        )

    with pytest.raises(ValueError, match="must be positive"):
        asyncio.run(go())


def test_httpx_mock_transport_available() -> None:
    # Guard against a silent switch of transports: the runner tests must never hit the network.
    assert issubclass(httpx.MockTransport, httpx.AsyncBaseTransport)
