-- LightHouse Enterprise, Phase 2: per-user rate limit for "Ask LightHouse" chat.
--
-- Applies after the Phase 0 and Phase 1 migrations. Same rules as before: everything in
-- `lh`, RLS enabled and forced, policies for `lh_app` keyed on lh.current_tenant_id(),
-- nothing for anon/authenticated, applies on Supabase (as non-superuser `postgres`) and on
-- vanilla PostgreSQL 16.
--
-- Threats this file holds against:
-- - a stolen console session (or a script) spending the Anthropic key without bound: each
--   user gets a fixed number of chat requests per minute, counted here so the limit holds
--   across every server replica, not per process;
-- - one tenant reading, resetting or exhausting another tenant's counters: RLS keyed on
--   the request's tenant, with the tenant leading the primary key;
-- - a request role that can raise its own limit: it can only add to its tenant's
--   counters and remove its tenant's old windows; the limit itself lives in server
--   configuration, not in the database.
--
-- The window is a fixed UTC minute. A burst straddling a minute boundary can therefore
-- reach twice the limit in about a minute; acceptable for a cost guard, and the daily
-- token budget (lh.model_usage) remains the hard ceiling per tenant.

create table lh.chat_rate_limits (
  tenant_id uuid not null,
  user_id uuid not null,
  window_start timestamptz not null,
  request_count integer not null default 1 check (request_count >= 1),
  -- tenant_id leads: the counter lookup and the RLS predicate use one index, and one
  -- tenant's keys never collide with another's.
  primary key (tenant_id, user_id, window_start)
);

-- No foreign key to tenants: these rows are short-lived counters, and a cascade from
-- tenant deletion is not needed to keep them from leaking (RLS does that).

alter table lh.chat_rate_limits enable row level security;
alter table lh.chat_rate_limits force row level security;

create policy chat_rate_limits_select on lh.chat_rate_limits
  for select to lh_app
  using (tenant_id = (select lh.current_tenant_id()));

create policy chat_rate_limits_insert on lh.chat_rate_limits
  for insert to lh_app
  with check (tenant_id = (select lh.current_tenant_id()));

-- INSERT ... ON CONFLICT DO UPDATE needs UPDATE (and SELECT) on the conflicting row.
-- WITH CHECK stops a row being moved to another tenant by the update itself.
create policy chat_rate_limits_update on lh.chat_rate_limits
  for update to lh_app
  using (tenant_id = (select lh.current_tenant_id()))
  with check (tenant_id = (select lh.current_tenant_id()));

-- The server removes the asking user's expired windows as it counts, which keeps the
-- table at about one row per recently active user without a scheduled job. Only windows
-- that have ended may be deleted: deleting the current one would reset the limit.
create policy chat_rate_limits_delete on lh.chat_rate_limits
  for delete to lh_app
  using (
    tenant_id = (select lh.current_tenant_id())
    and window_start < pg_catalog.date_trunc('minute', pg_catalog.now(), 'UTC')
  );

grant select, insert, update, delete on lh.chat_rate_limits to lh_app;

-- Counters only go up within a window, and identity columns never change: an UPDATE that
-- lowered a count (or moved it to another user or window) would reset the limit.
create function lh.chat_rate_limits_before_update()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if new.tenant_id is distinct from old.tenant_id
     or new.user_id is distinct from old.user_id
     or new.window_start is distinct from old.window_start then
    raise exception 'chat_rate_limits: tenant_id, user_id and window_start are immutable'
      using errcode = 'check_violation';
  end if;
  if new.request_count < old.request_count then
    raise exception 'chat_rate_limits: request_count may not be lowered'
      using errcode = 'check_violation';
  end if;
  return new;
end
$$;

revoke all on function lh.chat_rate_limits_before_update() from public;

create trigger chat_rate_limits_before_update
  before update on lh.chat_rate_limits
  for each row execute function lh.chat_rate_limits_before_update();

-- ---------------------------------------------------------------------------------------
-- Supabase API roles
-- ---------------------------------------------------------------------------------------

-- Default privileges on Supabase can hand new tables and functions to the Data API
-- roles. Take back anything this migration's objects picked up.
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
