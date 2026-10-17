# Shared GitHub Actions

Reusable GitHub workflows for organization-owned and personal repositories.
Shared scripts stay here; each repository keeps its configuration and pins
the workflow to a reviewed commit.

## Available workflows

| Workflow | What it does | Get started |
| --- | --- | --- |
| Docusaurus maintenance | Fix security advisories, propose dependency upgrades, build the website, and open one PR for review. | [Setup guide](docs/docusaurus.md) |

## One maintenance PR per website

**Security fixes and routine upgrades, together in one PR.** Choose security-only
maintenance or limit routine upgrades to patch, minor, or major versions. Reruns
update the same PR, so each audit does not add another PR to review.

- **Combined review:** security fixes and routine upgrades in one maintenance PR. [Comparison](docs/docusaurus.md#why-use-this-workflow).
- **Build evidence:** a frozen install and production website build before review.
- **Clear decisions:** see what was fixed, which pins need review, and what is blocked.

The Docusaurus workflow follows your declared Node/pnpm versions within its
[tested combinations](docs/docusaurus.md#toolchain-selection). It requires a
standalone website project. Project pins and deployment remain under your control.
The built-in GitHub token works; a GitHub App is optional.
The [setup guide](docs/docusaurus.md#set-it-up) includes a pinned caller workflow,
local build checks, and steps for the first audit.

## Shared defaults for multiple installations

Integration version 4 lets many websites follow one authoritative JSON defaults
file in any public GitHub repository. Each site keeps local overrides and its
own build/deployment setup. Conflicting declarations fail preflight and update
one reusable configuration issue; nothing is migrated automatically.

See [shared defaults setup and fleet updates](docs/shared-defaults.md). The
[recommended defaults](defaults/docusaurus.json) select Node 24, pnpm 11.21.0,
and a minimum ten-day cooldown.

## Reference

- [Setup, first run, and updates](docs/docusaurus.md)
- [Maintenance policy](docusaurus/maintenance.md)
- [Caller template](docusaurus/caller.yml)
- [Integration contract](docusaurus/contract.json)

Currently supports GitHub.com. The Docusaurus implementation retains its
BSD 3-Clause license.
