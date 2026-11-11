"""Test harness: a real PostgreSQL 16 with every migration applied.

Contract shared with CI: if `LH_TEST_DATABASE_URL` is set, it is a superuser URL to an
existing, empty server, and the tests create (and drop) their own database on it.
Otherwise a throwaway cluster is started from local binaries (`LH_TEST_PG_BIN`, default
`/usr/lib/postgresql/16/bin`) on a private unix socket and torn down afterwards.

The API under test connects as a dedicated login role that is *not* a superuser and holds
only membership in `lh_app`, which is the recommended production shape.
"""

from __future__ import annotations

import asyncio
import os
import secrets
import shutil
import subprocess
import tempfile
from collections.abc import AsyncGenerator, Iterator
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, urlsplit, urlunsplit

import asyncpg
import httpx
import pytest
from pydantic import SecretStr

from lighthouse.config import Settings
from lighthouse.db import Pool, create_pool
from lighthouse.main import create_app
from tests.helpers import TEST_AUDIENCE, TEST_ISSUER, TokenFactory

SERVER_DIR = Path(__file__).resolve().parent.parent
MIGRATIONS_DIR = SERVER_DIR.parent / "supabase" / "migrations"
DEFAULT_PG_BIN = "/usr/lib/postgresql/16/bin"
SOCKET_PORT = 54329
API_LOGIN_ROLE = "lh_api_test"
SUPABASE_API_ROLES = ("anon", "authenticated", "service_role")


@dataclass(frozen=True)
class PgServer:
    """Builds DSNs for one server, either a URL given by CI or a local unix socket."""

    base_url: str | None
    socket_dir: Path | None

    def dsn(self, database: str, login: tuple[str, str] | None = None) -> str:
        """DSN for `database`, as the superuser or, with `login`, as (user, password)."""
        if self.base_url is not None:
            parts = urlsplit(self.base_url)
            netloc = parts.netloc
            if login is not None:
                host = netloc.rsplit("@", 1)[-1]
                netloc = f"{quote(login[0], safe='')}:{quote(login[1], safe='')}@{host}"
            return urlunsplit((parts.scheme, netloc, "/" + database, parts.query, ""))
        assert self.socket_dir is not None
        user = "postgres" if login is None else login[0]
        # Trust auth on a private socket: the password is not needed here.
        return f"postgresql://{user}@/{database}?host={self.socket_dir}&port={SOCKET_PORT}"


@dataclass(frozen=True)
class TestDatabase:
    superuser_dsn: str
    app_dsn: str


def _run_pg(args: list[str], *, as_postgres: bool) -> None:
    command = ["runuser", "-u", "postgres", "--", *args] if as_postgres else args
    subprocess.run(command, check=True, capture_output=True, timeout=120)


def _pg_bin(name: str) -> str:
    bin_dir = Path(os.environ.get("LH_TEST_PG_BIN", DEFAULT_PG_BIN))
    candidate = bin_dir / name
    if candidate.exists():
        return str(candidate)
    found = shutil.which(name)
    if found is None:
        msg = f"{name} not found; install PostgreSQL 16 or set LH_TEST_DATABASE_URL"
        raise RuntimeError(msg)
    return found


@pytest.fixture(scope="session")
def pg_server() -> Iterator[PgServer]:
    url = os.environ.get("LH_TEST_DATABASE_URL")
    if url:
        yield PgServer(base_url=url, socket_dir=None)
        return

    # Postgres refuses to run as root; in a root sandbox run it as the `postgres` user.
    as_postgres = os.geteuid() == 0
    tmp = Path(tempfile.mkdtemp(prefix="lh-pg-"))
    if as_postgres:
        shutil.chown(tmp, "postgres", "postgres")
    data = tmp / "data"
    try:
        _run_pg(
            [
                _pg_bin("initdb"),
                "-D",
                str(data),
                "-U",
                "postgres",
                "--auth=trust",
                "-E",
                "UTF8",
                "--no-locale",
                "--no-sync",
            ],
            as_postgres=as_postgres,
        )
        # No TCP listener: the socket lives in a private temp directory, so trust auth
        # is reachable only from this machine and this test run.
        options = f"-k {tmp} -c listen_addresses='' -p {SOCKET_PORT} -c fsync=off"
        _run_pg(
            [_pg_bin("pg_ctl"), "-D", str(data), "-l", str(tmp / "log"), "-o", options, "-w", "start"],
            as_postgres=as_postgres,
        )
        yield PgServer(base_url=None, socket_dir=tmp)
    finally:
        if (data / "postmaster.pid").exists():
            _run_pg(
                [_pg_bin("pg_ctl"), "-D", str(data), "-m", "immediate", "-w", "stop"],
                as_postgres=as_postgres,
            )
        shutil.rmtree(tmp, ignore_errors=True)


def migration_files() -> list[Path]:
    files = sorted(MIGRATIONS_DIR.glob("*.sql"))
    assert files, f"no migrations found in {MIGRATIONS_DIR}"
    return files


async def apply_migrations(dsn: str) -> None:
    conn = await asyncpg.connect(dsn)
    try:
        for path in migration_files():
            async with conn.transaction():
                await conn.execute(path.read_text())
    finally:
        await conn.close()


async def _role_exists(conn: asyncpg.Connection[asyncpg.Record], name: str) -> bool:
    return bool(await conn.fetchval("select 1 from pg_roles where rolname = $1", name))


async def _setup_database(server: PgServer, name: str, scratch: str) -> str:
    """Create the test database and the API login role; return the role's password."""
    admin = await asyncpg.connect(server.dsn("postgres"))
    try:
        # First prove the migrations apply on a vanilla server where Supabase's API roles
        # do not exist (the conditional code paths). On a fresh server (CI, the throwaway
        # cluster) that is always the case; on a reused server the roles already exist
        # from an earlier run and this step has already been exercised there.
        roles_absent = not any([await _role_exists(admin, r) for r in SUPABASE_API_ROLES])
        if roles_absent:
            await admin.execute(f'create database "{scratch}"')
            try:
                await apply_migrations(server.dsn(scratch))
            finally:
                await admin.execute(f'drop database "{scratch}" with (force)')
            for role in SUPABASE_API_ROLES:
                await admin.execute(f"create role {role} nologin")

        await admin.execute(f'create database "{name}"')

        password = secrets.token_hex(24)
        if await _role_exists(admin, API_LOGIN_ROLE):
            await admin.execute(f"alter role {API_LOGIN_ROLE} login password '{password}'")
        else:
            await admin.execute(
                f"create role {API_LOGIN_ROLE} login nosuperuser nobypassrls "
                f"noinherit password '{password}'"
            )
    finally:
        await admin.close()

    db = await asyncpg.connect(server.dsn(name))
    try:
        # Simulate Supabase's worst case: default privileges that hand every new table,
        # schema and function to the Data API roles. The migration must take them back.
        await db.execute(
            "alter default privileges grant all on tables to anon, authenticated;"
            "alter default privileges grant all on sequences to anon, authenticated;"
            "alter default privileges grant all on functions to anon, authenticated;"
            "alter default privileges grant all on schemas to anon, authenticated;"
        )
    finally:
        await db.close()

    await apply_migrations(server.dsn(name))

    db = await asyncpg.connect(server.dsn(name))
    try:
        await db.execute(f"grant connect on database \"{name}\" to {API_LOGIN_ROLE}")
        await db.execute(f"grant lh_app to {API_LOGIN_ROLE}")
    finally:
        await db.close()
    return password


async def _drop_database(server: PgServer, name: str) -> None:
    admin = await asyncpg.connect(server.dsn("postgres"))
    try:
        await admin.execute(f'drop database if exists "{name}" with (force)')
    finally:
        await admin.close()


@pytest.fixture(scope="session")
def test_database(pg_server: PgServer) -> Iterator[TestDatabase]:
    suffix = secrets.token_hex(4)
    name = f"lh_test_{suffix}"
    scratch = f"lh_scratch_{suffix}"
    password = asyncio.run(_setup_database(pg_server, name, scratch))
    try:
        yield TestDatabase(
            superuser_dsn=pg_server.dsn(name),
            app_dsn=pg_server.dsn(name, login=(API_LOGIN_ROLE, password)),
        )
    finally:
        asyncio.run(_drop_database(pg_server, name))


@pytest.fixture
async def superuser(test_database: TestDatabase) -> AsyncGenerator[asyncpg.Connection[asyncpg.Record]]:
    """A superuser connection. Superusers bypass RLS: use it only to seed and to inspect."""
    conn = await asyncpg.connect(test_database.superuser_dsn)
    try:
        yield conn
    finally:
        await conn.close()


@pytest.fixture
async def app_conn(test_database: TestDatabase) -> AsyncGenerator[asyncpg.Connection[asyncpg.Record]]:
    """A connection as the API's login role (not a superuser, member of lh_app)."""
    conn = await asyncpg.connect(test_database.app_dsn)
    try:
        yield conn
    finally:
        await conn.close()


@pytest.fixture(scope="session")
def tokens() -> TokenFactory:
    return TokenFactory.generate()


@pytest.fixture
def settings(test_database: TestDatabase, tokens: TokenFactory) -> Settings:
    return Settings(
        database_url=SecretStr(test_database.app_dsn),
        jwt_issuer=TEST_ISSUER,
        jwt_audience=TEST_AUDIENCE,
        jwt_public_key=tokens.public_pem,
        db_pool_min_size=1,
        db_pool_max_size=4,
    )


@pytest.fixture
async def app_pool(settings: Settings) -> AsyncGenerator[Pool]:
    pool = await create_pool(settings)
    try:
        yield pool
    finally:
        await pool.close()


@pytest.fixture
async def client(settings: Settings) -> AsyncGenerator[httpx.AsyncClient]:
    app = create_app(settings)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as http,
    ):
        yield http
