-- LightHouse Enterprise, Phase 1: Claude triage results and model usage metering.
--
-- Applies after 20261110000000_foundations.sql and does not depend on any other Phase 1
-- migration. Same rules as the foundations: everything in `lh`, RLS enabled and forced,
-- policies for `lh_app` keyed on lh.current_tenant_id(), nothing for anon/authenticated,
-- applies on Supabase (as non-superuser `postgres`) and on vanilla PostgreSQL 16.
--
-- Threats this file holds against:
-- - alert text written by an attacker talking the model into a lower severity: the
--   existing `severity >= source_severity` constraint stays the backstop, and nothing
--   here relaxes it;
-- - an oversized projection stored per alert (cost and storage abuse): `evidence` has a
--   size cap here as well as in the application;
-- - a tenant reading another tenant's triage output or model spend: RLS on the new table,
--   and the new alert columns inherit lh.alerts' existing policies;
-- - usage records (the basis for quotas and billing) being edited after the fact by the
--   request role: `lh_app` may only insert and read them.

-- ---------------------------------------------------------------------------------------
-- alerts: normalised alert content and triage output
-- ---------------------------------------------------------------------------------------

alter table lh.alerts
  add column category text
    constraint alerts_category_length check (char_length(category) between 1 and 200),
  add column occurred_at timestamptz,
  -- The allow-listed, capped projection a connector produced; never the raw source
  -- record. The application caps it at 16 KiB canonical JSON; this is the backstop.
  add column evidence jsonb not null default '{}'::jsonb
    constraint alerts_evidence_object check (jsonb_typeof(evidence) = 'object')
    constraint alerts_evidence_size check (octet_length(evidence::text) <= 65536),
  -- SHA-256 hex of the normalised alert. Unchanged hash + already triaged = no model call.
  add column content_hash text
    constraint alerts_content_hash_format check (content_hash ~ '^[0-9a-f]{64}$'),
  add column confidence double precision
    constraint alerts_confidence_range check (confidence >= 0 and confidence <= 1),
  add column reasoning text
    constraint alerts_reasoning_length check (char_length(reasoning) <= 8000),
  -- Machine-readable reason an alert needs a person instead of (or despite) the model.
  -- Kept in step with lighthouse.triage.ReviewReason; a test compares the two.
  add column review_reason text
    constraint alerts_review_reason_known check (review_reason in (
      'model_disabled', 'model_unavailable', 'budget_exceeded', 'refusal', 'max_tokens',
      'schema_invalid', 'unexpected_stop', 'timeout', 'rate_limited', 'auth_error',
      'connection_error', 'api_error', 'internal_error'
    )),
  add column triage_model text
    constraint alerts_triage_model_length check (char_length(triage_model) between 1 and 128),
  -- When the model last produced a final answer (or a non-retryable failure) for the
  -- current content. NULL means "triage still owed": a later ingestion will try again.
  add column triaged_at timestamptz,
  -- A short-lived claim so two workers ingesting the same alert do not both call the
  -- model. The model call happens outside any transaction; the claim token is what the
  -- second (result) transaction checks before writing, so a stale result is discarded
  -- instead of overwriting newer content.
  add column triage_claim uuid,
  add column triage_claimed_at timestamptz,
  -- A stored review reason always means the alert needs a person. The reverse is not
  -- required: alerts that were never triaged need review without a recorded reason.
  add constraint alerts_review_reason_needs_review
    check (review_reason is null or needs_human_review),
  add constraint alerts_claim_pair
    check ((triage_claim is null) = (triage_claimed_at is null));

-- The existing lh.alerts_before_update trigger (identity columns immutable,
-- source_severity never lowered) and the alerts_severity_floor constraint apply to the new
-- columns unchanged: none of them is an identity column, and none can lower severity.

-- ---------------------------------------------------------------------------------------
-- model_usage: one row per model call, per tenant (CLAUDE.md rule 11, quotas, billing)
-- ---------------------------------------------------------------------------------------

-- No foreign key to tenants, as for audit_log: usage is billing evidence and must not be
-- removed by, or block, a cascade from tenant deletion.
create table lh.model_usage (
  id bigint generated always as identity primary key,
  tenant_id uuid not null,
  purpose text not null check (purpose ~ '^[a-z][a-z0-9_.]{0,63}$'),
  model text not null check (char_length(model) between 1 and 128),
  input_tokens bigint not null default 0 check (input_tokens >= 0),
  output_tokens bigint not null default 0 check (output_tokens >= 0),
  cache_read_tokens bigint not null default 0 check (cache_read_tokens >= 0),
  cache_creation_tokens bigint not null default 0 check (cache_creation_tokens >= 0),
  outcome text not null check (outcome ~ '^[a-z][a-z0-9_]{0,63}$'),
  created_at timestamptz not null default now()
);

-- Serves the per-tenant daily budget sum (tenant_id = current tenant, created_at >= start
-- of the UTC day) as an index-only scan, and the tenant's usage export.
create index model_usage_tenant_created_idx on lh.model_usage (tenant_id, created_at)
  include (input_tokens, output_tokens, cache_read_tokens, cache_creation_tokens);

alter table lh.model_usage enable row level security;
alter table lh.model_usage force row level security;

create policy model_usage_select on lh.model_usage
  for select to lh_app
  using (tenant_id = (select lh.current_tenant_id()));

create policy model_usage_insert on lh.model_usage
  for insert to lh_app
  with check (tenant_id = (select lh.current_tenant_id()));

-- Append-only for the request role: no UPDATE or DELETE grant and no policy for them.
grant select, insert on lh.model_usage to lh_app;

-- Usage rows are never edited by anyone, the owner included: an edited usage row would
-- let spend escape the budget. Deletion stays possible for an operator's retention job
-- (no trigger on DELETE), but not for lh_app, which has no grant for it.
create function lh.model_usage_no_update()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  raise exception 'model_usage rows cannot be changed'
    using errcode = 'insufficient_privilege';
end
$$;

revoke all on function lh.model_usage_no_update() from public;

create trigger model_usage_no_update
  before update on lh.model_usage
  for each row execute function lh.model_usage_no_update();

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
