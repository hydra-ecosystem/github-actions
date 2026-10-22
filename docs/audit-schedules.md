# Node maintenance schedules and manual audits

Each installation keeps its policy in `.github/node-maintenance.json` and its
GitHub triggers in `.github/workflows/dependency-audit.yml`. **Update both when
you change cadence.** Shared defaults do not rewrite workflow files.

The [basic setup](node-maintenance.md#set-it-up) checks security weekly and leaves
routine upgrades manual. The [recommended shared defaults](../defaults/node-maintenance.json)
check security weekly and propose routine upgrades every three months. With the
released two-job caller, both kinds maintain the same dependency PR.

The opt-in [coordinated caller](node-coordination.md) uses these same schedules,
but keeps a separate PR for each channel. Its dependency-file push trigger
validates the default branch and refreshes only existing proposals; it does not
enable extra automatic upgrades.

## Weekly security, quarterly upgrades

For local policy, set these fields in `.github/node-maintenance.json`. Keep your
existing directory, validation script, and other project settings:

```json
{
  "maintenance": {
    "mode": "security-and-maintenance",
    "upgradeScope": "major"
  },
  "schedule": {
    "security": ["0 2 * * 1"],
    "upgrades": ["0 2 1 */3 *"]
  }
}
```

If you inherit the recommended shared defaults, these fields are already supplied;
leave them out locally unless you want to override them.

Security checks run every Monday at 02:00 UTC. Upgrade runs check security and
routine upgrades at 02:00 UTC on the first day of January, April, July, and
October. Both kinds obey the release cooldown and project constraints. Routine
upgrades also obey `maintenance.upgradeScope`.

In the [setup guide's caller](node-maintenance.md#4-add-the-workflow-files), use:

```yaml
'on':
  schedule:
  - cron: '0 2 * * 1'
  - cron: '0 2 1 */3 *'
  workflow_dispatch:
    inputs:
      audit-kind:
        description: Security fixes only, or security plus routine upgrades for this run.
        type: choice
        default: security
        options:
        - security
        - upgrades
```

Keep the remaining caller jobs, permissions, workflow references (`@v1` or matching
full commit SHAs), and audit input forwarding:

```yaml
with:
  audit-kind: ${{ inputs.audit-kind || 'auto' }}
```

## Change or disable a cadence

Each list accepts one or more five-field cron expressions. Replace a list to
change that cadence. For example, `"upgrades": ["0 2 1 * *"]` selects monthly
upgrades. Add the same expression to the caller's `on.schedule`.

To keep weekly security and make upgrades **manual-only**, merge these fields
into the local configuration:

```json
{
  "maintenance": {"mode": "security-only"},
  "schedule": {
    "security": ["0 2 * * 1"],
    "upgrades": []
  }
}
```

Remove the quarterly cron entry from the caller. Setting the mode alone is not
enough: a nonempty upgrades list requires `security-and-maintenance` mode.

For **manual-only audits of both kinds**, set:

```json
{"schedule": {"security": [], "upgrades": []}}
```

Remove `on.schedule` from the caller and keep `workflow_dispatch`.

When shared defaults are involved, local lists replace inherited lists per kind:

| Local setting | With an inherited cadence | Without an inherited cadence |
| --- | --- | --- |
| List omitted | Keeps the inherited list | Uses an empty list |
| `[]` | Disables that cadence | Disables that cadence |
| Nonempty list | Replaces that cadence | Defines that cadence |

An empty schedule object inherits both lists when available. Use explicit empty
lists to disable inherited cadences. These rules apply to the schedule object;
the older cron-list form is described below.

## Keep GitHub triggers aligned

The caller's `on.schedule` must contain the unique cron entries from **both
resolved lists**, including inherited values. Preflight checks this even for
manual dispatch. A mismatch fails before dependency changes and updates the
single configuration issue. Fix the caller or local overrides, then rerun.

If both lists contain the same expression, include it once in the caller; that
event runs a combined security and upgrade audit. Different expressions that
happen to fire at the same time can enqueue separate runs. They still maintain
the same PR.

GitHub selects work using the exact triggering cron expression. Runs can be
delayed; selection does not depend on the time the runner starts. See
[GitHub's scheduling reference](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#onschedule).

## Run an audit on demand

Open **Actions → Node dependency audit → Run workflow** on your repository's
default branch. Choose **security** for security fixes only, or **upgrades** for
security plus routine upgrades. The choice applies only to this run and does not
change automatic policy. The cooldown, upgrade scope, and validation still apply.

From a checkout of the repository, you can also use:

```sh
gh workflow run dependency-audit.yml --ref main -f audit-kind=security
gh workflow run dependency-audit.yml --ref main -f audit-kind=upgrades
```

Run the command for the kind you want. Replace `main` if your default branch has
another name. Other dispatch branches are rejected.

All kinds maintain the same `maintenance/dependency-audit` branch and open PR.
A run without qualifying dependency changes leaves an existing proposal untouched;
read the current run summary for its findings. After that PR is merged or closed,
a later qualifying proposal can open the next PR. See
[reports and PR behavior](../node/maintenance.md#reports-and-prs).

## Existing cron-list configurations

The runtime also accepts `"schedule": ["0 2 * * 1"]`. This form runs the same
configured maintenance mode on every cron event; it does not select a kind per
expression. Without an explicit or inherited mode, it uses
`security-and-maintenance`. A local cron list replaces an inherited schedule
object entirely.

Omitting `schedule` also retains that mode default and an internal January 30
cron fallback. It does not create a GitHub trigger. For new installations, use
the explicit schedule object above so cadence and manual-only policy are clear.
