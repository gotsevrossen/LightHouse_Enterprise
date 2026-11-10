# Installed skills

Vendored into `.claude/skills/` on 2026-11-10 so every session and every `coder` subagent
has them without a marketplace install. 42 skills, about 2.6 MB. Licence texts are in
`third_party/skill-licenses/`.

Each skill was read for scope, and the set was scanned for embedded instructions aimed at
the agent, pipe-to-shell installers and unexpected network calls. Nothing was found beyond
what the skills document (the supply-chain auditor queries OSV, deps.dev, npm and PyPI by
design). Skills are still third-party text: `CLAUDE.md` overrides them.

## Sources

| Source | Commit | Licence | Trust |
| --- | --- | --- | --- |
| [anthropics/skills](https://github.com/anthropics/skills) | `2c5958e` | Apache-2.0 (these three) | First-party Anthropic |
| [microsoft/skills](https://github.com/microsoft/skills) | `9287b44` | MIT | First-party Microsoft |
| [microsoft/azure-skills](https://github.com/microsoft/azure-skills) | `9aa7f61` | MIT | First-party Microsoft |
| [supabase/agent-skills](https://github.com/supabase/agent-skills) | `c9be0e9` | MIT | First-party Supabase |
| [trailofbits/skills](https://github.com/trailofbits/skills) | `e4dd0bb` | CC BY-SA 4.0 | Established security firm |
| [vinayaklatthe/microsoft-security-skills](https://github.com/vinayaklatthe/microsoft-security-skills) | `02e37e1` | MIT | Community repo (personal account, Microsoft copyright notice). Guidance text only, one `SKILL.md` each, no scripts. Verify specifics against Microsoft Learn. |

CC BY-SA applies to the Trail of Bits skill files themselves (kept unmodified, with
attribution here). It does not extend to LightHouse code written with their help.

## What is installed and why

**Building the product**

| Skill | From | Used for |
| --- | --- | --- |
| `fastapi-router-py`, `pydantic-models-py` | microsoft/skills | API routes and boundary models |
| `supabase`, `supabase-postgres-best-practices` | supabase/agent-skills | Database, RLS, Auth, Vault, queues, migrations |
| `azure-identity-py`, `azure-monitor-query-py` | microsoft/skills | Authenticating to and querying a customer's Sentinel / Log Analytics workspace |
| `azure-eventhub-py` | microsoft/skills | Streamed log intake from customers who export to Event Hubs |
| `azure-keyvault-py` | microsoft/skills | Option for holding the action-signing key |
| `kql` | microsoft/skills | Correct hunting and Sentinel queries |
| `microsoft-docs` | microsoft/skills | Checking current Microsoft Learn docs instead of guessing |
| `entra-app-registration` | microsoft/azure-skills | Multi-tenant app, consent and permissions |
| `modern-python` | trailofbits | uv, ruff, pytest project setup |
| `mcp-builder` | anthropics | Exposing LightHouse data as an MCP server later |
| `frontend-design`, `webapp-testing` | anthropics | Console UI and Playwright checks |

**Security domain knowledge (connectors, triage prompts, endpoint actions)**

`defender-xdr`, `defender-for-endpoint`, `defender-for-identity`,
`defender-for-office-365`, `defender-tvm`, `sentinel`, `sentinel-detection-engineering`,
`unified-secops-platform`, `entra-id`, `entra-id-protection`, `entra-workload-identity`,
`conditional-access-mfa`, `intune-device-mgmt`, `purview-audit`,
`windows-11-security-baseline`, `macos-intune-baseline`, `compromise-recovery`,
`threat-modelling`, `api-security-design` (all from microsoft-security-skills).

**Verifying our own code (used by the orchestrator)**

| Skill | Used for |
| --- | --- |
| `differential-review` | Security review of each diff that touches a boundary |
| `sharp-edges` | Finding APIs and defaults that are easy to misuse |
| `semgrep`, `codeql`, `sarif-parsing` | Static analysis and reading its output |
| `fp-check` | Confirming a finding is real before acting on it |
| `supply-chain-risk-auditor` | Reviewing dependencies before adding them |
| `agentic-actions-auditor` | Auditing our GitHub Actions workflows |

Already available without vendoring: `claude-api` ships with Claude Code and must be loaded
before any code that calls Claude is written.

## Considered and not installed

- **`azure-servicebus-py`, `azure-monitor-opentelemetry-py`**: installed at first, removed
  when hosting moved from Azure to Supabase plus a container.

- **mukul975/Anthropic-Cybersecurity-Skills** (800+ skills): too large to load usefully,
  unreviewed breadth, and not from Anthropic despite the name.
- **Remaining microsoft-security-skills** (Purview DLP, PKI, IoT and others, 69 more):
  add individually when a connector needs one.
- **`azure-prepare` / `azure-deploy` / `azure-validate`** (microsoft/azure-skills): right
  for Phase 6 deployment work, over 1.5 MB together; install then.
- **Trail of Bits `insecure-defaults`**: ships as a plugin workflow, not a standalone
  skill; install through `/plugin marketplace add trailofbits/skills` if wanted.
- **Trail of Bits `property-based-testing`, `variant-analysis`, `yara-authoring`**: good
  candidates once there is parsing code and detection content to apply them to.
- **servosity/msp-skills, SCStelz/security-investigator**: single-author operational
  tools that act against a live tenant; not needed for building the product.

## Updating

Re-clone the source at a newer commit, diff the skill directory, read the changes, then
replace it and update the commit in the table above. Do not pull updates unread.
