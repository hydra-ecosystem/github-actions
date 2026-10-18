# Shared GitHub Actions

Reusable GitHub workflows for organization-owned and personal repositories.
Shared scripts stay here; each repository keeps its configuration and pins
the workflow to a reviewed commit.

## Available workflows

| Workflow | What it does | Get started |
| --- | --- | --- |
| Node maintenance | Fix security advisories, propose dependency upgrades, validate the project, and open one PR for review. | [Setup guide](docs/node-maintenance.md) |

## One maintenance PR per project

**Security fixes and routine upgrades, together in one PR.** Choose security-only
maintenance or limit routine upgrades to patch, minor, or major versions. Reruns
update the same PR, so each audit does not add another PR to review.

- **Combined review:** security fixes and routine upgrades in one maintenance PR. [Comparison](docs/node-maintenance.md#supported-projects).
- **Validation evidence:** a frozen install and selected project checks before review.
- **Clear decisions:** see what was fixed, which pins need review, and what is blocked.

The Node workflow follows your declared Node and npm/pnpm versions within its
[tested combinations](docs/node-maintenance.md#toolchain-selection). It requires a
standalone Node project. Project pins and deployment remain under your control.
The built-in GitHub token works; a GitHub App is optional.
Version 6 replaces the Docusaurus interface. Existing installations must follow
the [migration checklist and rollout order](docs/node-migration.md).
The [setup guide](docs/node-maintenance.md#set-it-up) includes a pinned caller workflow,
local validation checks, and steps for the first audit.

## Shared defaults for multiple installations

Integration version 6 lets many projects follow one authoritative JSON defaults
file in any public GitHub repository. Each project keeps local overrides and its
own validation/deployment setup. Conflicting declarations fail preflight and update
one reusable configuration issue; nothing is migrated automatically.

See [shared defaults setup and fleet updates](docs/shared-defaults.md). The
[recommended defaults](defaults/node-maintenance.json) select Node 24, pnpm 11.21.0 or npm 11.9.0,
and a minimum ten-day cooldown.

## Default schedule and overrides

With **integration version 6**, projects that follow the
[recommended defaults](defaults/node-maintenance.json) inherit this schedule:

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

To change the default for your projects, edit `schedule` in your shared defaults
file. To override one project, set `schedule.security` or `schedule.upgrades` in
that project's `.github/node-maintenance.json`. Each local list replaces the inherited
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
manual runs, and cron-list shorthand. Existing explicit local schedules keep
overriding shared defaults.

## Reference

- [Setup, first run, and updates](docs/node-maintenance.md)
- [Maintenance policy](node/maintenance.md)
- [Caller template](node/caller.yml)
- [Integration contract](node/contract.json)

Currently supports GitHub.com. The Node implementation retains its
BSD 3-Clause license.
