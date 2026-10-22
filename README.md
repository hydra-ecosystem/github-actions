# Shared GitHub Actions

Reusable workflows for organization-owned and personal repositories. Each
installation keeps its configuration and uses `@v1` for automatic compatible
workflow updates. Full commit SHA pinning remains available. Supports GitHub.com.

## Available workflows

| Workflow | Use it to | Get started |
| --- | --- | --- |
| Node dependency maintenance | Attempt compatible security fixes, optionally propose routine upgrades, validate the project, and maintain grouped dependency PRs. | [Setup guide](docs/node-maintenance.md) |
| Node maintenance setup check | Check a list of maintenance installations for broken setup or configuration drift, and maintain one central issue per list. | [Fleet setup guide](docs/node-fleet-setup.md) |

The workflows are independent. Install maintenance in each Node repository you
want to maintain. Run the fleet checker from one repository to monitor those
installations. Fleet checks do not audit dependencies, install packages, or run
project scripts. Nothing merges or repairs configuration automatically.

## Node dependency maintenance

Supports standalone Node applications, libraries, and websites using npm or pnpm.
A maintenance run validates its proposal with a frozen install and your project's
checks. With the released two-job caller, all audit kinds maintain
**one open dependency PR per repository**;
reruns update that PR rather than opening one PR per dependency. Reports show
proposed versions, validation, and blocked findings.

The [App-based setup](docs/node-maintenance.md#set-it-up) includes App installation
and coordinated workflows for separate security and routine-upgrade PRs. The
[coordinated caller](docs/node-coordination.md) validates dependency-file
pushes and refreshes existing proposals after either PR merges. This new caller
requires a workflow revision containing that interface; existing callers keep
their combined-PR behavior.

The shared maintenance App supplies GitHub controls. Maintainer-selected
follow-up repairs are one use of that integration; tests and changes run in the
repository's Actions. See [reviewing findings and requesting repairs](docs/node-maintenance.md#review-findings-and-request-follow-up-repairs).

| Maintenance setup | Automatic security checks | Automatic routine upgrades |
| --- | --- | --- |
| Basic setup in the guide | Weekly | Disabled; run upgrades manually |
| Follow this repository's shared defaults | Weekly | Every three months |

Both examples use a ten-day release cooldown. The basic setup follows your
supported project toolchain. The [shared defaults](defaults/node-maintenance.json)
require Node 24 and pnpm 11.21.0 or npm 11.9.0. Local overrides remain valid;
conflicting declarations fail preflight and update the repository's reusable
configuration issue. See the [setup guide](docs/node-maintenance.md) and
[scheduling guide](docs/audit-schedules.md).

## Manage several installations

Keep an authoritative [defaults file](docs/shared-defaults.md) in any public
GitHub repository. Optionally keep a [repository inventory](defaults/node-repositories.json)
beside it. The inventory names the expected defaults source and the repositories
that should follow it. You do not need to register either file here.

The [fleet checker](docs/node-fleet-setup.md) inspects each default branch, honors
local overrides, and reports failed or unverifiable setup in the host repository.
It keeps one issue per failure episode, closes it when every static check passes,
and creates a new issue after a later regression. This repository checks Hydra
and OmegaConf weekly on Mondays at 03:00 UTC. Keep private inventories and reports
in a private host; other hosts choose their own caller schedule. Checks run five
repositories at a time in one runner, with one combined report and issue.

## Documentation

- [Node maintenance: setup, first run, updates, and troubleshooting](docs/node-maintenance.md)
- [Fleet setup checks: inventory, caller, results, and limits](docs/node-fleet-setup.md)
- [Maintenance schedules and manual audits](docs/audit-schedules.md)
- [Separate proposal channels and automatic refresh](docs/node-coordination.md)
- [Maintenance App operators: host the App and Cloudflare service](docs/node-maintenance-operator.md)
- [Shared defaults for multiple installations](docs/shared-defaults.md)
- [Maintenance behavior, reports, and permissions](node/maintenance.md)
- [Migrate an earlier Docusaurus installation](docs/node-migration.md)
- [Workflow releases and immutable pins](docs/workflow-releases.md)
- [Maintenance caller template](node/caller.yml) and [integration contract](node/contract.json)

The Node implementation retains its BSD 3-Clause license.
