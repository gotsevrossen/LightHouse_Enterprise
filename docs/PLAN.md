# LightHouse Enterprise — Plan

Status: proposal, written 2026-11-10, hosting revised the same day (Supabase plus one
managed container; Go agent confirmed). Nothing here is built yet.

## 1. Product

**Who it is for.** Organisations of roughly 200 to 5,000 people that already pay for
Microsoft security tooling (Microsoft 365 E3/E5, Defender, Entra, Intune, sometimes
Sentinel) and have a small security or IT team that cannot keep up with the alert volume.

**What it does.**

1. Connects to the security services the customer already licenses and pulls alerts,
   incidents, sign-in risk and device posture into one queue.
2. Has Claude triage every item: what happened, how bad, how confident, and one concrete
   next step, in plain English, with the technical evidence behind an analyst view.
3. Lets people ask questions about an alert, a user, a device or the whole estate.
4. Investigates and remediates on enrolled devices through an endpoint agent, inside
   limits the customer sets.

**What carries over from the original LightHouse:** plain-English first, one recommended
action per alert, sensor data treated as attacker-controlled, the severity floor, model
output validated before use, roles enforced on the server, and "needs human review" as the
safe fallback whenever the AI is unavailable.

**What is new:** hosted and multi-tenant, Claude through the Anthropic API on our server,
licensed enterprise data sources instead of open-source sensors, single sign-on, approvals
and audit, an endpoint agent that can act, and billing.

## 2. Architecture

### 2.1 Components

| Component | Responsibility | Technology |
| --- | --- | --- |
| Connectors | Pull from each source on a schedule or stream, normalise to one alert shape, track cursors | Python workers, queue-driven |
| Triage pipeline | Dedupe, build the fenced prompt, call Claude, validate, apply the severity floor, store | Python, Anthropic SDK |
| Investigation loop | Multi-step tool use for chat and endpoint work, with policy checks and approval pauses | Python, Anthropic SDK (manual loop, state in Postgres) |
| API | Tenants, users, alerts, chat, approvals, policy, audit, agent enrolment | FastAPI |
| Web console | Queue, alert detail, chat, device view, approvals, settings, audit export | React + TypeScript + Vite |
| Agent gateway | Outbound HTTPS long-polling from endpoint agents, action dispatch, result intake | Part of the FastAPI service; every request signed by the device's own key |
| Endpoint agent | Enrol, collect, execute typed actions, undo, report | Go service, one signed binary per platform |
| Data, sign-in, scheduling | Tenant-scoped storage with row-level security, append-only audit, SAML sign-in, queues and cron | Supabase (managed Postgres, Auth, Queues, Cron) |
| Secrets | Anthropic key and signing key; per-tenant connector credentials | Hosting platform's runtime secrets; Supabase Vault |

### 2.2 Where it runs

Nothing is hosted on the owner's laptop. The service is made of two managed pieces:

1. **Supabase** for the database, sign-in, queues, scheduled jobs and the encrypted
   credential store. This is the same platform Kiln uses, so the RLS-test pattern from
   Kiln carries over.
2. **One container on a managed host** for the Python service (API, connectors, triage,
   investigation loop, agent gateway). Render is the suggested start because deploys are a
   git push and secrets are managed for you; Fly.io, Google Cloud Run and Azure Container
   Apps run the same container, so the choice is reversible.

Why not Supabase alone, as in Kiln: Edge Functions are capped at 400 seconds of wall-clock
time and 256 MB on paid plans (150 seconds on free). A triage call fits; a multi-step
investigation that waits on an endpoint and on Claude does not, and neither does holding
connections open for agents. Splitting the work into many short functions is possible but
would make the security-critical loop harder to reason about and test.

Expected starting cost is small: a paid Supabase project and one small always-on container,
plus Claude usage, which will be the main variable cost. Check current prices before
committing; none are quoted here because they change.

For development the laptop needs nothing heavy: a separate cloud Supabase project serves as
the development database, tests use a fixture model instead of Claude, and the API can be
run as a single local process or developed entirely in cloud sessions.

What Supabase covers for enterprise buyers, and what to confirm: it states SOC 2 Type 2
compliance with the report available to Team and Enterprise customers, lets each project
be placed in a chosen region, and supports SAML single sign-on. Which plan each of those
requires was not confirmed from Supabase's own pricing pages; check before promising any
of them to a customer. Under its shared-responsibility model, RLS policies, access
management and application design remain ours.

### 2.3 Why the AI loop runs on the server, not on the device

The request was for the AI to "go through the laptop like Claude Cowork does". Cowork runs
the agent on the user's machine with the user's own account. That model does not work
here, because the Anthropic key must stay on our server (a key on thousands of customer
laptops is a leaked key), and because an enterprise needs every action checked against
policy and logged centrally.

So the loop is split:

1. The server calls Claude with a catalogue of endpoint tools.
2. When Claude asks for a tool, the server checks tenant policy and the action tier,
   pauses for approval if required, signs the action, and sends it to that device's agent.
3. The agent verifies the signature and its local policy cap, executes, and returns a
   structured result.
4. The server fences the result as untrusted evidence and continues the loop.

The effect for the customer is the same (the AI inspects the machine and fixes things),
but the model never holds a shell and the key never leaves our infrastructure. The Claude
Agent SDK and Managed Agents were both considered and rejected for this piece: the Agent
SDK would need credentials on the device, and Managed Agents runs tools in an
Anthropic-hosted sandbox rather than on the customer's machine.

### 2.4 Endpoint action catalogue (first cut)

| Tier | Actions | Runs when |
| --- | --- | --- |
| 0 Observe | Running processes and their signers, listening ports and connections, autoruns and scheduled tasks, installed software and patch level, local users and groups, firewall / disk-encryption / antivirus status, recent security events, hash and metadata of a named file | Automatically |
| 1 Contain | Stop a process, block an IP or domain in the host firewall, quarantine a file, disable an autorun or scheduled task, disable a local account, isolate the host (control-plane traffic still allowed) | Automatically only where tenant policy allows that action for that device group; otherwise on approval. Each has a recorded undo. |
| 2 Change | Install pending security updates, apply a hardening setting, remove software, turn on disk encryption | Only on a named person's approval |
| Never | Delete user data, wipe, read credentials or browser secrets, disable security tooling, touch protected processes, run arbitrary commands | Not implemented |

Guard rails that apply to every action: typed parameters validated on both ends, signed
envelope with nonce and expiry, local cap the server cannot raise, dry run, protected-target
list, per-tenant rate and blast-radius limits, tenant kill switch, full audit trail.

Where the customer has Defender for Endpoint, prefer its own response actions (isolate
machine, run antivirus scan, restrict app execution) through the Defender API over our
agent doing the same thing. Our agent covers what Defender does not and customers without
it.

### 2.5 Multi-tenancy and identity

- One Postgres database, `tenant_id` on every tenant-scoped row, row-level security
  enforced for the application role. Per-tenant encryption keys for connector credentials.
- Console sign-in through Supabase Auth with SAML single sign-on against the customer's
  identity provider (Entra first); SCIM provisioning later. Roles: Viewer, Analyst, Responder (may approve Tier 1), Admin (policy,
  connectors, may approve Tier 2).
- Access to a customer's Microsoft data through one multi-tenant Entra application that the
  customer's admin consents to. Application permissions, certificate or federated
  credential, no stored user passwords.

### 2.6 Using Claude

- Default model `claude-opus-5-5` from configuration, adaptive thinking, effort set per
  route. Whether high-volume triage should move to a cheaper model is a cost decision for
  the owner, taken on eval results (Phase 2 builds the eval).
- Triage uses structured outputs; the stable prefix (tools, system prompt) is cached; chat
  streams; backfills and re-triage go through the Batch API at half price.
- Refusals are expected for some security content and are handled as "needs human review"
  with server-side fallbacks enabled.
- Token usage is recorded per tenant per call. This is the basis for quotas and pricing.
- The client sits behind an interface, so a customer who must buy through Azure can be
  served by Claude on Microsoft Foundry with a configuration change.

## 3. Data sources

Phase 1 and 2 (Microsoft, read-only):

| Source | What we take | Access |
| --- | --- | --- |
| Microsoft Defender XDR | Incidents and alerts across endpoint, identity, email, cloud apps; advanced hunting queries | Microsoft Graph security API (`SecurityIncident.Read.All`, `SecurityAlert.Read.All`, `ThreatHunting.Read.All`) |
| Microsoft Entra ID | Sign-in and audit logs, risky users and risk detections, Conditional Access state | Graph (`AuditLog.Read.All`, `IdentityRiskyUser.Read.All`, `IdentityRiskEvent.Read.All`, `Policy.Read.All`) |
| Microsoft Intune | Device inventory, compliance, encryption and OS patch state | Graph (`DeviceManagementManagedDevices.Read.All`) |
| Microsoft Sentinel | Incidents and KQL over the customer's workspace | Azure Monitor / Log Analytics query API with a reader role |
| Microsoft 365 audit | Mailbox rules, sharing, admin activity | Office 365 Management Activity API or Purview audit search |

Opt-in write actions (separate consent, Phase 5): isolate a device and run a scan through
Defender for Endpoint, revoke a user's sessions, disable an account, confirm a user
compromised.

Later, behind the same connector interface: CrowdStrike, SentinelOne, Okta, Google
Workspace, AWS GuardDuty and Security Hub, Palo Alto and Fortinet firewalls, generic
syslog/CEF and webhook intake.

Permission names above are from memory of the current Graph model; confirm each against
Microsoft Learn (the `microsoft-docs` skill) when the connector is written.

## 4. Phases

Each phase ends with something that runs and a short list of checks that pass.

**Phase 0 — Foundations (1–2 weeks).** Repo layout (`server/`, `web/`, `agent/`, `infra/`,
`supabase/`, `evals/`), tooling (uv, ruff, pyright, pytest, vitest), CI with pinned actions
and secret scanning, Supabase projects for development and production, RLS and the
cross-tenant test harness, runtime secret wiring, audit log table, fixture model, first
container deploy. *Done when:* CI is green and a test proves tenant A cannot
read tenant B's rows through the API.

**Phase 1 — First connector and triage (2–3 weeks).** Entra app registration and admin
consent flow, Defender XDR incidents and alerts connector, normalised alert schema, dedupe,
triage with Claude (fenced prompt, structured output, severity floor, refusal handling),
usage metering. *Done when:* a test tenant's Defender alerts appear triaged, and injected
text in an alert cannot lower its severity.

**Phase 2 — Console and chat (2–3 weeks).** SAML sign-in, roles, alert queue and detail,
plain-English and analyst views, "Ask LightHouse" chat with streaming, triage eval set and
harness. *Done when:* an analyst can work the queue end to end and the eval gives a
baseline score to judge prompt and model changes against.

**Phase 3 — More Microsoft sources (2–3 weeks).** Entra sign-in risk, Intune posture,
Sentinel, Microsoft 365 audit. Cross-source correlation by user and device. Posture view
(unpatched, unencrypted, non-compliant devices; risky sign-ins). *Done when:* one incident
view joins evidence from at least three sources.

**Phase 4 — Endpoint agent, observe only (3–4 weeks).** Agent enrolment with per-device
keys, gateway, signed envelopes, Tier 0 catalogue on Windows first, server-side
investigation loop, device view in the console. No actions that change anything. *Done
when:* Claude can investigate a device through Tier 0 tools, and a forged or replayed
envelope is rejected by the agent in tests.

**Phase 5 — Containment and change (3–4 weeks).** Policy engine, approvals workflow,
Tier 1 with undo, Tier 2 on approval, Defender response actions, kill switch, blast-radius
limits, dry run. macOS and Linux agents. *Done when:* every action has a tested undo and
dry run, and an external reviewer has gone through the action path.

**Phase 6 — SaaS readiness (ongoing).** Billing (Stripe and/or Azure Marketplace SaaS
offer), tenant self-service onboarding, SCIM, data retention controls and export, status
page, backups and restore test, penetration test, SOC 2 Type I preparation, customer-facing
security documentation, third-party connectors.

Rough total to a sellable first version: four to five months of focused work. Phases 0–3
alone make a useful read-only product that can be shown to design partners.

## 5. Risks to take seriously

- **An AI that changes customers' machines can cause an outage.** One wrong isolation of a
  server is worse than a missed alert. This is why Phase 4 ships observe-only, Tier 1
  defaults to approval, and there are blast-radius limits and a kill switch.
- **We become a high-value target.** We hold read access to many companies' security data
  and a channel to their endpoints. Signing keys, the Supabase secret key, the agent update path and the gateway
  need the most careful design and an outside review before Phase 5 ships.
- **Prompt injection is the normal case.** Attackers control alert content. The severity
  floor, the fixed action catalogue and approvals are what make this safe; prompt wording
  is not.
- **Model cost at enterprise volume.** A large tenant can produce tens of thousands of
  events a day. Dedupe and correlation before the model, caching, batch for non-urgent
  work, and per-tenant quotas are needed from Phase 1.
- **Data handling commitments.** Customers will ask where data is processed, how long it is
  kept and whether it trains models. Anthropic's retention terms differ by model (some
  require 30-day retention), which constrains model choice for customers who need zero
  retention. Settle this before signing the first customer.
- **Microsoft overlap.** Security Copilot does part of this for E5 customers. The
  differentiators to protect: works across vendors, priced for mid-size companies, plain
  English for non-specialists, and the endpoint agent.

## 6. Open decisions

| # | Decision | Recommendation |
| --- | --- | --- |
| 1 | Endpoint agent language | **Decided: Go.** |
| 2 | May Tier 1 containment ever run without a person in the first release? | No. Ship approval-only, then let tenants opt specific actions in once there is field data. |
| 3 | Hosting | **Decided: Supabase plus one managed container.** Still open: which container host. Render to start; revisit Azure Container Apps if Marketplace selling or a customer requires Azure. |
| 4 | Billing channel | Azure Marketplace SaaS offer for enterprises (they can spend existing commitments), Stripe for direct. Price per protected user or device with a usage ceiling. |
| 5 | Data residency and retention | Start US-only with a stated retention period; add an EU region when a customer requires it. |
| 6 | High-volume triage model | Start on the default; decide on tiering after the Phase 2 eval shows what quality costs. |
| 7 | Product name and relationship to the original | Keep "LightHouse Enterprise"; separate repo and brand tier, shared design language. |
| 8 | Where the action-signing key lives by Phase 5 | A cloud key-management service that signs without releasing the key (Azure Key Vault, AWS KMS or Google Cloud KMS). The hosting platform's secret store is acceptable only while the agent is observe-only. |
