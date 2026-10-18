# Security and upgrade schedules

Integration contract **version 6** supports separate automatic cadences and a
manual choice of audit work. The [recommended shared defaults](../defaults/node-maintenance.json)
check security weekly and propose routine upgrades quarterly. A security-only
run proposes dependency changes only
when before/after audit evidence confirms a security fix. Blocked findings and
reports remain available in the Actions run summary and artifacts.

## Weekly security, quarterly upgrades

Set these fields in the installation's `.github/node-maintenance.json`, keeping its
directory, toolchain, shared defaults source, and other settings:

```json
{
  "directory": "project",
  "toolchain": {},
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

This checks security every Monday at 02:00 UTC. Routine upgrades run at 02:00 UTC
on the first day of January, April, July, and October. An upgrade run also checks
security. The ten-day release delay and selected upgrade scope still apply.

For weekly security and **manual-only upgrades**, use
`"maintenance": {"mode": "security-only"}` and `"upgrades": []`. To run both
kinds of audit manually only, use `"schedule": {"security": [], "upgrades": []}`.
An omitted list in the schedule object is empty. Routine scheduled upgrades need
both an upgrades cadence and `maintenance.mode=security-and-maintenance`.

## Update the caller too

Choose a reviewed revision whose `node/contract.json` declares version 6 or
later. Start from that revision's [caller template](../node/caller.yml).
Replace both repository and revision markers with the shared repository name and
the same full commit SHA. Earlier Docusaurus workflow paths do not implement the Node interface;
follow the [migration checklist](node-migration.md).

Replace the template's schedule marker with the unique cron entries from both
lists. For the weekly/quarterly example:

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

Keep the template's audit input forwarding:

```yaml
with:
  audit-kind: ${{ inputs.audit-kind || 'auto' }}
```

GitHub reads cron entries from the caller workflow. Keep its entries identical
to the resolved JSON lists, including any inherited schedule; preflight rejects
a mismatch before dependency changes. If
both lists contain the same cron expression, include it once in the workflow;
that event runs one combined audit. Different expressions that happen to fire
at the same time can enqueue separate runs. They still update the same PR.
When both lists are empty, omit `on.schedule` from the workflow.

GitHub uses the exact triggering cron expression to select the work. Scheduling
can be delayed by GitHub; this policy does not infer cadence from the current
clock or require an external scheduler. See [GitHub's schedule and manual input
reference](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax).

## Run upgrades on demand

Open **Actions → Node dependency audit → Run workflow** on the default
branch. Choose **security** for security fixes only, or **upgrades** for security
plus routine upgrades. The choice applies to this run and does not change your
automatic policy. It still obeys `maintenance.upgradeScope`, cooldown, project
constraints, frozen install, and the selected project checks.

From the CLI:

```sh
gh workflow run dependency-audit.yml --ref main -f audit-kind=upgrades
```

Use your repository's default branch if it is not `main`.

## One maintained PR

All audit kinds use the same `maintenance/dependency-audit` branch and open PR.
An outdated proposal updates that PR. If the files, report, base branch, and
validation result are unchanged, a rerun creates no commit, push, or PR edit.
Run timestamps and workflow links alone do not count as changes. New report
findings update the same PR body without another dependency commit.
If validation now fails for the same files, the workflow
updates the report and marks the existing PR as a draft without another push.
A run with no qualifying changes creates no PR and leaves an
existing proposal intact; read that run's summary for current findings. After a
PR is merged or closed, a later qualifying proposal can open the next PR.

The report leads with proposed dependency changes and installation and project validation.
Routine-only headlines show the update count and validation status; security proposals
also show confirmed fix counts. Existing blocked, unchanged findings appear as
neutral background, with severities and constraints in expandable details.
Newly reported findings remain visible. Passing project checks alone does not establish
that a security finding was fixed. See [reports and PRs](../node/maintenance.md#reports-and-prs).

## Shared defaults and existing installations

`maintenance.mode`, `maintenance.upgradeScope` and schedule lists can come from
[shared defaults](shared-defaults.md); local fields override them. Each local
`schedule.security` or `schedule.upgrades` list replaces that inherited list;
an omitted list inherits, and `[]` disables that cadence. An empty object
inherits both lists. The recommended file selects weekly security and quarterly
upgrades. GitHub still requires matching cron entries in each consumer workflow.
A live schedule change can therefore require updates to those local triggers;
until then, preflight reports the mismatch in the reusable configuration issue.

A cron-list shorthand (`"schedule": ["..."]`) is also accepted. It uses one
configured maintenance mode rather than selecting separate kinds per cron.
Without an explicit mode it uses `security-and-maintenance`. Use the schedule
object shown above for separate cadences and the quieter security-only default.
Omitted schedules do not add GitHub triggers; define the schedule explicitly.

Public installation and execution use only the checked-in caller, actions,
and runtime. No private tooling is required.
