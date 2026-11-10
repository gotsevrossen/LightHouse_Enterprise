# LightHouse Enterprise

A multi-tenant security copilot for medium and large organisations. It connects to the
security services a company already licenses (Microsoft Defender XDR, Sentinel, Entra ID,
Intune and others), has Claude triage and explain every alert in plain English, and can
investigate and contain threats on enrolled devices through an endpoint agent, within
limits the customer sets.

It is the enterprise sibling of [LightHouse](https://github.com/gotsevrossen/LightHouse),
the local-only security copilot for small businesses.

**Status: planning.** No application code yet.

- [`docs/PLAN.md`](docs/PLAN.md): product, architecture, phases, risks, open decisions
- [`CLAUDE.md`](CLAUDE.md): how Claude works in this repo, including the security rules
- [`docs/skills.md`](docs/skills.md): the agent skills vendored in `.claude/skills/`
