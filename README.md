# Shared GitHub Actions

Reusable GitHub workflows for organization-owned and personal repositories.
Each repository keeps its project configuration and pins the shared workflows
to a reviewed commit.

## Node dependency maintenance

Maintain dependencies for a standalone Node application, library, or website
using npm or pnpm. The workflow attempts compatible security fixes, optionally
proposes routine upgrades, and validates the result with a frozen install and
your project's checks.

All audit kinds maintain **one open dependency PR per repository**. Reruns update
that PR rather than opening a PR for each dependency. Reports show the proposed
versions, validation results, and any blocked findings. Nothing merges automatically.

**[Set up Node maintenance](docs/node-maintenance.md)** for supported versions,
complete npm and pnpm instructions, and your first audit.

## Choose your maintenance policy

| Setup | Automatic security checks | Automatic routine upgrades |
| --- | --- | --- |
| Basic setup in the guide | Weekly | Disabled; run upgrades manually |
| Follow this repository's shared defaults | Weekly | Every three months |

Both setups use a ten-day release cooldown. The basic setup follows your
supported project toolchain. The [shared defaults](defaults/node-maintenance.json)
require Node 24 and pnpm 11.21.0 or npm 11.9.0. Local settings can override
inherited defaults; conflicts with project declarations fail preflight and
update one reusable configuration issue.

For several installations, [share defaults from a public GitHub JSON file](docs/shared-defaults.md).
To change cadence, disable automatic upgrades, or run an audit on demand, use
the [scheduling guide](docs/audit-schedules.md). GitHub cron entries remain in
each repository's caller workflow and must match its resolved configuration.

## Documentation

- [Setup, first run, updates, and troubleshooting](docs/node-maintenance.md)
- [Schedules and manual audits](docs/audit-schedules.md)
- [Shared defaults for multiple installations](docs/shared-defaults.md)
- [Maintenance behavior, reports, and permissions](node/maintenance.md)
- [Migrate an earlier Docusaurus installation](docs/node-migration.md)
- [Caller template](node/caller.yml) and [integration contract](node/contract.json)

Supports GitHub.com. The Node implementation retains its BSD 3-Clause license.
