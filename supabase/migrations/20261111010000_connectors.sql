-- LightHouse Enterprise, Phase 1: connector connections and ingestion cursors.
--
-- Follows the Phase 0 conventions (20261110000000_foundations.sql): tables in `lh`, RLS
-- enabled and forced, policies for `lh_app` keyed on `lh.current_tenant_id()`, nothing
-- for `anon`/`authenticated`. Must apply on vanilla PostgreSQL 16 and on Supabase.
--
-- Threats this file holds against:
-- 1. A request for tenant A reading or changing tenant B's connections or cursors.
-- 2. A connector credential (certificate private key, token, client secret) being stored
--    in a plain column, where every backup, log of a failed statement and read replica
--    would carry it. Only a *reference* to a secret held in Supabase Vault is stored.
-- 3. The background worker, which must see every tenant's connections to schedule them,
--    turning that cross-tenant view into a way to read tenants' security data.

-- ---------------------------------------------------------------------------------------
-- Types
-- ---------------------------------------------------------------------------------------

-- Append-only, like every enum here: values are matched by the server's code.
create type lh.connection_kind as enum ('defender_xdr');

create type lh.connection_status as enum ('pending', 'active', 'error', 'disabled');

-- ---------------------------------------------------------------------------------------
-- connections
-- ---------------------------------------------------------------------------------------

create table lh.connections (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references lh.tenants (id) on delete cascade,
  kind lh.connection_kind not null,
  -- The customer's Entra (directory) tenant id. Typed uuid so that nothing but a GUID can
  -- ever reach the token endpoint URL that is built from it.
  external_tenant_id uuid not null,
  status lh.connection_status not null default 'pending',
  -- A REFERENCE to the credential, never the credential. The secret itself (certificate
  -- private key, token) lives in Supabase Vault and is read only by the connector job.
  -- The grammar admits a short lowercase name such as a Vault secret's uuid and nothing
  -- that a key, certificate, JWT or client secret could fit into: no uppercase, no '+',
  -- '/', '=', '.', '~', whitespace or newlines, and at most 64 characters after the
  -- prefix. Pasting a secret here by mistake fails the insert instead of storing it.
  credential_ref text not null
    constraint connections_credential_ref_is_reference
    check (credential_ref ~ '^vault:[a-z0-9][a-z0-9_-]{0,63}$'),
  last_success_at timestamptz,
  -- Short, fixed messages written by the connector runner (error kind, HTTP status,
  -- AADSTS code). Never a response body, URL with a token, or customer text. The second
  -- check is a backstop against a base64-encoded JSON object (every JWT starts with one)
  -- reaching this column through a future bug.
  last_error text
    constraint connections_last_error_short check (char_length(last_error) <= 500)
    constraint connections_last_error_no_token check (last_error !~ 'eyJ[A-Za-z0-9_-]{8,}'),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint connections_unique unique (tenant_id, kind, external_tenant_id),
  -- Target of the composite foreign key from connector_cursors, which is what guarantees a
  -- cursor row carries the same tenant as its connection.
  constraint connections_id_tenant_unique unique (id, tenant_id)
);

alter table lh.connections enable row level security;
alter table lh.connections force row level security;

create policy connections_select on lh.connections
  for select to lh_app
  using (tenant_id = (select lh.current_tenant_id()));

create policy connections_update on lh.connections
  for update to lh_app
  using (tenant_id = (select lh.current_tenant_id()))
  with check (tenant_id = (select lh.current_tenant_id()));

-- Request handling may see a connection's state but not its credential_ref: there is no
-- reason for any API response to carry it. Connections are created by the onboarding
-- (admin consent) job, not through the API, in this phase, so there is no INSERT or
-- DELETE grant. The runner, working as lh_app inside the tenant's transaction, records
-- the outcome of each run; column-level UPDATE keeps it from touching anything else.
grant select (id, tenant_id, kind, external_tenant_id, status, last_success_at, last_error,
              created_at, updated_at)
  on lh.connections to lh_app;
grant update (status, last_success_at, last_error) on lh.connections to lh_app;

-- Identity columns are immutable for every role, the owner included: moving a connection
-- to another tenant, or re-pointing it at another directory, would send one customer's
-- security data into another tenant's queue. Changing a credential means a new
-- connection (or an operator migration), not an in-place edit.
create function lh.connections_before_update()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if new.id is distinct from old.id
     or new.tenant_id is distinct from old.tenant_id
     or new.kind is distinct from old.kind
     or new.external_tenant_id is distinct from old.external_tenant_id
     or new.created_at is distinct from old.created_at then
    raise exception 'connections: id, tenant_id, kind, external_tenant_id and created_at are immutable'
      using errcode = 'check_violation';
  end if;
  new.updated_at := pg_catalog.now();
  return new;
end
$$;

revoke all on function lh.connections_before_update() from public;

create trigger connections_before_update
  before update on lh.connections
  for each row execute function lh.connections_before_update();

-- ---------------------------------------------------------------------------------------
-- connector_cursors
-- ---------------------------------------------------------------------------------------

-- One row per connection: where the next incremental fetch starts. The cursor format is
-- owned by the connector (opaque here); it is capped so a bug cannot grow it unbounded.
create table lh.connector_cursors (
  connection_id uuid primary key,
  tenant_id uuid not null,
  cursor text not null check (char_length(cursor) between 1 and 2048),
  updated_at timestamptz not null default now(),
  -- Composite key: a cursor can only exist under its own connection's tenant, so RLS on
  -- tenant_id here is exactly as strong as RLS on the connection.
  constraint connector_cursors_connection_fk
    foreign key (connection_id, tenant_id)
    references lh.connections (id, tenant_id) on delete cascade
);

create index connector_cursors_tenant_idx on lh.connector_cursors (tenant_id);

alter table lh.connector_cursors enable row level security;
alter table lh.connector_cursors force row level security;

create policy connector_cursors_select on lh.connector_cursors
  for select to lh_app
  using (tenant_id = (select lh.current_tenant_id()));

create policy connector_cursors_insert on lh.connector_cursors
  for insert to lh_app
  with check (tenant_id = (select lh.current_tenant_id()));

create policy connector_cursors_update on lh.connector_cursors
  for update to lh_app
  using (tenant_id = (select lh.current_tenant_id()))
  with check (tenant_id = (select lh.current_tenant_id()));

grant select, insert, update on lh.connector_cursors to lh_app;

create function lh.connector_cursors_before_update()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if new.connection_id is distinct from old.connection_id
     or new.tenant_id is distinct from old.tenant_id then
    raise exception 'connector_cursors: connection_id and tenant_id are immutable'
      using errcode = 'check_violation';
  end if;
  new.updated_at := pg_catalog.now();
  return new;
end
$$;

revoke all on function lh.connector_cursors_before_update() from public;

create trigger connector_cursors_before_update
  before update on lh.connector_cursors
  for each row execute function lh.connector_cursors_before_update();

-- ---------------------------------------------------------------------------------------
-- Scheduling role for the ingestion worker
-- ---------------------------------------------------------------------------------------

-- The worker has to find every tenant's active connections before it can do anything per
-- tenant. Doing that with the Supabase `service_role` key, or as the table owner, would
-- give the scheduling step the power to read and write every row of every table: one
-- SQL injection or logic bug there and it reads every tenant's alerts. Instead it takes
-- this role, which can do exactly one thing: list connection metadata across tenants.
-- It has no grant on alerts, audit_log, tenants, memberships or cursors, no write grant
-- anywhere, cannot bypass RLS, and owns nothing. Everything the worker does *for* a
-- tenant (cursors, alerts, audit, run status) still goes through
-- `db.tenant_transaction` as `lh_app`, pinned to that one tenant.
do $$
begin
  if not exists (select 1 from pg_catalog.pg_roles where rolname = 'lh_ingest') then
    -- Defaults are NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION; see the
    -- note on lh_app in the foundations migration for why they are asserted, not spelled.
    create role lh_ingest nologin;
  end if;
end
$$;

do $$
declare
  r record;
begin
  select rolsuper, rolbypassrls, rolcanlogin into r
    from pg_catalog.pg_roles where rolname = 'lh_ingest';
  if r.rolsuper or r.rolbypassrls then
    raise exception 'role lh_ingest must not be SUPERUSER or BYPASSRLS';
  end if;
  if r.rolcanlogin then
    raise exception 'role lh_ingest must be NOLOGIN; connect as another role and SET ROLE';
  end if;
end
$$;

-- Same pattern as lh_app: SET without INHERIT, so the connection user can switch to the
-- role for one transaction but never silently runs with its grants.
do $$
begin
  if current_setting('server_version_num')::int >= 160000 then
    if not pg_catalog.pg_has_role(current_user, 'lh_ingest', 'SET') then
      execute format('grant lh_ingest to %I with inherit false, set true', current_user);
    end if;
  elsif not pg_catalog.pg_has_role(current_user, 'lh_ingest', 'MEMBER') then
    execute format('grant lh_ingest to %I', current_user);
  end if;
end
$$;

grant usage on schema lh to lh_ingest;

-- Only the columns scheduling needs. last_error and timestamps are not exposed: the
-- scheduler does not need them, and less readable means less to leak.
grant select (id, tenant_id, kind, external_tenant_id, status, credential_ref)
  on lh.connections to lh_ingest;

-- RLS stays forced; this policy is what lets lh_ingest see across tenants, and it applies
-- to this one table only. It is SELECT-only: lh_ingest has no write grant either.
create policy connections_ingest_select on lh.connections
  for select to lh_ingest
  using (true);

-- ---------------------------------------------------------------------------------------
-- Supabase API roles
-- ---------------------------------------------------------------------------------------

-- As in the foundations migration: default privileges on Supabase hand new tables,
-- sequences and functions to `anon`/`authenticated`. Take them back for what this file
-- created.
do $$
declare
  api_role text;
begin
  foreach api_role in array array['anon', 'authenticated'] loop
    if exists (select 1 from pg_catalog.pg_roles where rolname = api_role) then
      execute format('revoke all on all tables in schema lh from %I', api_role);
      execute format('revoke all on all sequences in schema lh from %I', api_role);
      execute format('revoke all on all functions in schema lh from %I', api_role);
      execute format('revoke all on schema lh from %I', api_role);
    end if;
  end loop;
end
$$;

-- Functions are executable by PUBLIC by default; the trigger functions above already
-- revoke that. lh_ingest is not granted lh.current_tenant_id(): it has no use for it.
