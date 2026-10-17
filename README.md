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

## Default schedule and overrides

With **integration version 5**, websites that follow the
[recommended defaults](defaults/docusaurus.json) inherit this schedule:

```json
{
  "maintenance": {"mode": "security-and-maintenance"},
  "schedule": {
    "security": ["0 2 * * 1"],
    "upgrades": ["0 2 1 */3 *"]
  }
}
```

Security checks run every Monday at 02:00 UTC. Routine upgrades run at 02:00 UTC
on the first day of January, April, July, and October. Upgrade runs also check
security. All runs maintain the same dependency PR.

To change the default for your websites, edit `schedule` in your shared defaults
file. To override one website, set `schedule.security` or `schedule.upgrades` in
that website's `.github/docusaurus.json`. Each local list replaces the inherited
list of the same name; omitted lists continue to inherit.

For example, these local fields keep inherited security checks and make routine
upgrades manual-only:

```json
{
  "maintenance": {"mode": "security-only"},
  "schedule": {"upgrades": []}
}
```

Keep the caller workflow's `on.schedule` cron entries equal to the combined
resolved lists. A shared-defaults edit does not rewrite installed workflow files;
preflight reports a mismatch until their triggers are updated. The
[scheduling guide](docs/audit-schedules.md) covers caller setup, other cadences,
manual runs, and legacy configurations. Existing explicit local schedules keep
overriding shared defaults.

## Reference

- [Setup, first run, and updates](docs/docusaurus.md)
- [Maintenance policy](docusaurus/maintenance.md)
- [Caller template](docusaurus/caller.yml)
- [Integration contract](docusaurus/contract.json)

Currently supports GitHub.com. The Docusaurus implementation retains its
BSD 3-Clause license.
