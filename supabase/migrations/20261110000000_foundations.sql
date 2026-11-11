-- LightHouse Enterprise, Phase 0 foundations.
--
-- Must apply cleanly both on Supabase-hosted Postgres (run as `postgres`, which is not a
-- superuser there) and on a vanilla PostgreSQL 16 (run as a superuser in tests and CI).
-- Supabase-only roles (`anon`, `authenticated`) are therefore only referenced after
-- checking that they exist.
--
-- Threat this file holds against: a request handled for tenant A reading or changing
-- tenant B's rows, including when application code forgets a `WHERE tenant_id = ...`.
-- Isolation is enforced here, by row-level security on every table, for a request role
-- (`lh_app`) that cannot bypass it and does not own the tables.

-- ---------------------------------------------------------------------------------------
-- Schema
-- ---------------------------------------------------------------------------------------

-- A dedicated schema rather than `public`: on Supabase, `public` is exposed through the
-- Data API and carries default grants to `anon`/`authenticated`. We never use the Data
-- API, so nothing of ours should live where it could be reached through it.
create schema if not exists lh;
revoke all on schema lh from public;

-- ---------------------------------------------------------------------------------------
-- Request role
-- ---------------------------------------------------------------------------------------

do $$
begin
  if not exists (select 1 from pg_catalog.pg_roles where rolname = 'lh_app') then
    -- Defaults are NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION. They are
    -- not spelled out because a non-superuser (Supabase `postgres`) may not name some of
    -- those attributes at all; the check below asserts them instead.
    create role lh_app nologin;
  end if;
end
$$;

-- If `lh_app` pre-existed with attributes that would defeat RLS, stop here rather than
-- silently building tenant isolation on a role that bypasses it.
do $$
declare
  r record;
begin
  select rolsuper, rolbypassrls, rolcanlogin into r
    from pg_catalog.pg_roles where rolname = 'lh_app';
  if r.rolsuper or r.rolbypassrls then
    raise exception 'role lh_app must not be SUPERUSER or BYPASSRLS';
  end if;
  if r.rolcanlogin then
    raise exception 'role lh_app must be NOLOGIN; connect as another role and SET ROLE';
  end if;
end
$$;

-- The connection user switches to `lh_app` with SET LOCAL ROLE inside each request
-- transaction, so it needs SET rights on the role. On PostgreSQL 16+, a CREATEROLE user
-- that created a role holds only ADMIN on it by default, so grant SET explicitly. INHERIT
-- is off so the connection user does not silently gain or depend on lh_app's grants.
-- If the server connects as a different user than the one running migrations, grant
-- `lh_app` to that user separately (see server/README.md).
do $$
begin
  if current_setting('server_version_num')::int >= 160000 then
    if not pg_catalog.pg_has_role(current_user, 'lh_app', 'SET') then
      execute format('grant lh_app to %I with inherit false, set true', current_user);
    end if;
  elsif not pg_catalog.pg_has_role(current_user, 'lh_app', 'MEMBER') then
    execute format('grant lh_app to %I', current_user);
  end if;
end
$$;

grant usage on schema lh to lh_app;

-- ---------------------------------------------------------------------------------------
-- Types
-- ---------------------------------------------------------------------------------------

-- Declaration order is the ordering Postgres uses for `<`/`>=` and `greatest()`, which is
-- what the severity floor below relies on. Never reorder; only append above `critical`
-- with care, and keep server/src/lighthouse/severity.py in the same order (a test checks).
create type lh.severity as enum ('info', 'low', 'medium', 'high', 'critical');

create type lh.member_role as enum ('viewer', 'analyst', 'responder', 'admin');

create type lh.alert_status as enum ('new', 'triaged', 'investigating', 'resolved', 'dismissed');

-- ---------------------------------------------------------------------------------------
-- Current tenant
-- ---------------------------------------------------------------------------------------

-- Returns the tenant set for this transaction, or NULL when the setting is absent, empty
-- or not a well-formed UUID. NULL makes every policy comparison NULL, so reads match no
-- rows and writes fail WITH CHECK: fail closed. The regex guard avoids a cast error, which
-- would turn a missing tenant into a 500 rather than an empty result. Operators and the
-- cast are schema-qualified so a crafted search_path cannot redirect them.
create function lh.current_tenant_id()
returns uuid
language sql
stable
parallel safe
as $$
  select case
    when pg_catalog.current_setting('app.tenant_id', true)
         operator(pg_catalog.~)
         '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$'
      then pg_catalog.current_setting('app.tenant_id', true)::pg_catalog.uuid
  end
$$;

revoke all on function lh.current_tenant_id() from public;
grant execute on function lh.current_tenant_id() to lh_app;

-- ---------------------------------------------------------------------------------------
-- tenants
-- ---------------------------------------------------------------------------------------

create table lh.tenants (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(name) between 1 and 200),
  created_at timestamptz not null default now()
);

alter table lh.tenants enable row level security;
alter table lh.tenants force row level security;

-- Tenants are created by an operator job, not by request handling: read-only for lh_app.
create policy tenants_select on lh.tenants
  for select to lh_app
  using (id = (select lh.current_tenant_id()));

grant select on lh.tenants to lh_app;

-- ---------------------------------------------------------------------------------------
-- memberships
-- ---------------------------------------------------------------------------------------

create table lh.memberships (
  tenant_id uuid not null references lh.tenants (id) on delete cascade,
  user_id uuid not null,
  role lh.member_role not null,
  created_at timestamptz not null default now(),
  primary key (tenant_id, user_id)
);

create index memberships_user_id_idx on lh.memberships (user_id);

alter table lh.memberships enable row level security;
alter table lh.memberships force row level security;

-- Membership management arrives with the admin console; until then lh_app only reads.
create policy memberships_select on lh.memberships
  for select to lh_app
  using (tenant_id = (select lh.current_tenant_id()));

grant select on lh.memberships to lh_app;

-- ---------------------------------------------------------------------------------------
-- alerts
-- ---------------------------------------------------------------------------------------

create table lh.alerts (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references lh.tenants (id) on delete cascade,
  source text not null check (char_length(source) between 1 and 64),
  source_alert_id text not null check (char_length(source_alert_id) between 1 and 512),
  title text not null check (char_length(title) between 1 and 1000),
  source_severity lh.severity not null,
  severity lh.severity not null,
  status lh.alert_status not null default 'new',
  summary text check (char_length(summary) <= 10000),
  recommended_action text check (char_length(recommended_action) <= 4000),
  -- Default true: an alert that has not been through triage is, by definition, unreviewed.
  needs_human_review boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  -- Severity floor (CLAUDE.md rule 5): the model may raise severity, never lower it below
  -- what the source reported. Enforced here so it survives any bug or prompt injection
  -- upstream. Relies on the declaration order of lh.severity.
  constraint alerts_severity_floor check (severity >= source_severity),
  -- tenant_id leads so one tenant's keys can never collide with, or reveal, another's.
  constraint alerts_source_unique unique (tenant_id, source, source_alert_id)
);

create index alerts_tenant_created_idx on lh.alerts (tenant_id, created_at desc, id desc);

alter table lh.alerts enable row level security;
alter table lh.alerts force row level security;

create policy alerts_select on lh.alerts
  for select to lh_app
  using (tenant_id = (select lh.current_tenant_id()));

create policy alerts_insert on lh.alerts
  for insert to lh_app
  with check (tenant_id = (select lh.current_tenant_id()));

-- USING picks which rows may be targeted; WITH CHECK stops a row being moved to another
-- tenant by the update itself.
create policy alerts_update on lh.alerts
  for update to lh_app
  using (tenant_id = (select lh.current_tenant_id()))
  with check (tenant_id = (select lh.current_tenant_id()));

create policy alerts_delete on lh.alerts
  for delete to lh_app
  using (tenant_id = (select lh.current_tenant_id()));

-- DELETE is granted because retention and deletion-on-request are tenant-scoped duties of
-- the service; RLS limits it to the request's own tenant.
grant select, insert, update, delete on lh.alerts to lh_app;

-- Identity columns never change after insert, and the source's own severity may only go
-- up. Without the second rule, an UPDATE could lower source_severity and severity together
-- and step around the floor. This applies to every role, including the owner.
create function lh.alerts_before_update()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if new.tenant_id is distinct from old.tenant_id
     or new.source is distinct from old.source
     or new.source_alert_id is distinct from old.source_alert_id
     or new.created_at is distinct from old.created_at then
    raise exception 'alerts: tenant_id, source, source_alert_id and created_at are immutable'
      using errcode = 'check_violation';
  end if;
  if new.source_severity < old.source_severity then
    raise exception 'alerts: source_severity may not be lowered'
      using errcode = 'check_violation';
  end if;
  new.updated_at := pg_catalog.now();
  return new;
end
$$;

revoke all on function lh.alerts_before_update() from public;

create trigger alerts_before_update
  before update on lh.alerts
  for each row execute function lh.alerts_before_update();

-- ---------------------------------------------------------------------------------------
-- audit_log
-- ---------------------------------------------------------------------------------------

-- No foreign key to tenants: the audit trail is evidence and must not be removed by, or
-- block, a cascade from tenant deletion. RLS WITH CHECK still pins inserts to the
-- request's tenant.
create table lh.audit_log (
  id bigint generated always as identity primary key,
  tenant_id uuid not null,
  actor text not null check (char_length(actor) between 1 and 200),
  action text not null check (char_length(action) between 1 and 200),
  target text check (char_length(target) <= 500),
  detail jsonb not null default '{}'::jsonb check (jsonb_typeof(detail) = 'object'),
  created_at timestamptz not null default now()
);

create index audit_log_tenant_created_idx on lh.audit_log (tenant_id, created_at desc, id desc);

alter table lh.audit_log enable row level security;
alter table lh.audit_log force row level security;

create policy audit_log_select on lh.audit_log
  for select to lh_app
  using (tenant_id = (select lh.current_tenant_id()));

create policy audit_log_insert on lh.audit_log
  for insert to lh_app
  with check (tenant_id = (select lh.current_tenant_id()));

-- Append-only for the request role: no UPDATE or DELETE grant and no policy for them.
grant select, insert on lh.audit_log to lh_app;

-- Defence in depth for every other role, the owner included: an audit trail anyone with
-- write access can edit is not evidence. A superuser can still disable the trigger, which
-- is itself a logged DDL event on Supabase.
create function lh.audit_log_append_only()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  raise exception 'audit_log is append-only'
    using errcode = 'insufficient_privilege';
end
$$;

revoke all on function lh.audit_log_append_only() from public;

create trigger audit_log_no_update_delete
  before update or delete on lh.audit_log
  for each row execute function lh.audit_log_append_only();

create trigger audit_log_no_truncate
  before truncate on lh.audit_log
  for each statement execute function lh.audit_log_append_only();

-- ---------------------------------------------------------------------------------------
-- Supabase API roles
-- ---------------------------------------------------------------------------------------

-- Our tables are never served through the Supabase Data API. Remove anything `anon` or
-- `authenticated` may have picked up (for example through default privileges) so that a
-- leaked publishable key cannot reach them even if `lh` is later exposed by mistake.
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
