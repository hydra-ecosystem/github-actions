# Check Node maintenance setup across repositories

Run one workflow to check whether several Node maintenance installations still
have a valid setup. It reads configuration and workflow files as data. It never
installs dependencies, executes project code, audits vulnerabilities, opens
repair PRs, or changes the listed repositories.

Use this alongside [Node dependency maintenance](node-maintenance.md). The two
workflows have separate callers and schedules. A fleet check creates or updates
one central issue in the repository running the checker.

## 1. Keep an inventory beside your defaults

For example, keep these files in your configuration repository:

```text
defaults/node-maintenance.json
defaults/node-repositories.json
```

The inventory contains the expected defaults source and 1 to 25 distinct
`owner/repository` names:

```json
{
  "defaults": {
    "repository": "owner/settings",
    "path": "defaults/node-maintenance.json",
    "ref": "main"
  },
  "repositories": [
    "owner/application",
    "owner/library",
    "owner/website"
  ]
}
```

Change the source to your authoritative public defaults file. A listed
installation must inherit that repository/path/ref, either directly or through
another defaults source. Explicit local overrides remain valid and are checked
against that installation's project declarations. A repository that stops
following the expected source fails even if its current versions happen to match.

Use a branch ref for live defaults or a full commit SHA for fixed policy.
The inventory ref used to fetch this list is independent of the defaults ref
inside it. See [shared defaults](shared-defaults.md) for inheritance rules.

This repository's [inventory](../defaults/node-repositories.json) lists ten public
repositories: Hydra, OmegaConf, and eight personal Node projects. Repositories
that are not installed yet remain listed so their missing setup stays visible.
Other maintainers can keep their own inventories in their own repositories; no
registration here is required.

## 2. Choose where the checker and issue run

To check this repository's inventory, use **Actions → Node maintenance setup check → Run
workflow** after the workflow is merged. Its default inputs select
`defaults/node-repositories.json` on this repository's default branch. Set
`inventory-repository`, `inventory-path`, and `inventory-ref` to read another list.
An empty repository selects the host; an empty ref selects the inventory
repository's default branch.

To host the check elsewhere, add `.github/workflows/node-fleet-setup.yml` to that
repository's default branch:

```yaml
name: Node maintenance setup check
'on':
  schedule:
  - cron: '0 3 * * 1'
  workflow_dispatch:
permissions:
  contents: read
jobs:
  setup:
    permissions:
      contents: read
      actions: read
      issues: write
    uses: hydra-ecosystem/github-actions/.github/workflows/node-fleet-check.yml@REVIEWED_FULL_COMMIT_SHA
    with:
      inventory-repository: owner/settings
      inventory-path: defaults/node-repositories.json
      inventory-ref: main
```

Replace `REVIEWED_FULL_COMMIT_SHA` with a reviewed full SHA that contains
`node-fleet-check.yml`. Use your inventory location. Enable issues in the host
repository. Only the host needs issue-write permission; listed repositories do
not need a new workflow, extra write permission, or an issue opened in them.
Reports have the host repository's visibility. Keep private-repository inventories
and their checker in a host that will remain private if names, checked commits,
and diagnostics must stay private. A private inventory alone does not make
issues or run summaries in a public host private. Changing the host to public
also requires reviewing its inventory history and existing reports.

For public repositories, the built-in token is sufficient. To read private
listed repositories or a private inventory in another repository, add a host
Actions secret `NODE_FLEET_READ_TOKEN` with **Contents: read** and **Actions: read**
access to the required repositories, then add this to the calling job:

```yaml
secrets:
  read-token: ${{ secrets.NODE_FLEET_READ_TOKEN }}
```

The optional token goes only to the scanner. The reporter uses the host's
built-in token. Shared defaults sources remain public, as required by the
maintenance resolver. No private key or secret content is inspected.

## 3. Run and inspect results

Open **Actions → Node maintenance setup check → Run workflow** in the host. From a checkout
of that repository, you can also run:

```sh
gh workflow run node-fleet-setup.yml --ref main
```

Use your host's default branch name. For a direct run of this repository's
workflow, the filename is `node-fleet-check.yml` instead.

The run summary and `node-fleet-report` artifact contain one result per repository,
its exact checked default-branch commit, and an actionable diagnostic:

| Result | Meaning |
| --- | --- |
| `ok` | All supported static setup checks passed. |
| `failed` | Setup violates a checked requirement, such as mismatched Node policy or caller schedules. |
| `unverified` | A required observation was unavailable, such as inaccessible repository data, API limits, or an incomplete tree. It is not a pass. |

The scanner checks up to five repositories concurrently in one runner, while
keeping results in inventory order. Each repository has isolated temporary files.
Shared defaults and pinned repository snapshots are reused across checks.
The scan continues after an individual repository fails. Any failed or unverified
result fails the scanner job and opens or updates one **Node maintenance setup check** issue
in the host. The reporter still runs after scan failures. A fully passing scan
closes that issue; recurrence reopens it. Repeated failures update the body
without per-run comments. An invalid or unreadable inventory also reports against
that list when its repository/path identity is valid.

The issue starts with a results table and links to each repository. Exact commit
identities are in the expandable **Checked revisions** section.

Issue identity uses the inventory repository and path, so changing its contents
or ref keeps the same issue. Different paths have separate issues. Runs are
serialized in the host to avoid competing issue creation. Existing ambiguous
duplicate marked issues cause a reporting error instead of another issue.
Invalid inventory location inputs that cannot identify a safe list fail the
workflow without opening an issue.

## What the checker verifies

- Config exists at `.github/node-maintenance.json`; shared defaults resolve and
  include the inventory's expected source.
- The project is standalone, has a supported Node and exact npm/pnpm declaration,
  a compatible `engines.node` range, and an existing validation script.
- Lockfile format, mixed-lockfile restrictions, and pnpm release cooldown satisfy
  the resolved configuration.
- The maintenance caller pins audit and publisher workflows from one repository
  at the same full SHA. That revision declares Node integration version 6 and
  contains both reusable workflows and supports the resolved toolchain. It does
  not have to be the latest revision.
- Caller schedules match resolved policy, including bounds for the supported
  numeric, range, list, step, and month/day name forms. The original cron text
  is retained for event matching. Required job permissions, audit input
  forwarding, publisher dependency/validation forwarding, manual choices, and
  concurrency are present.
- The caller's audit and publisher jobs are unconditionally enabled. The
  checker does not evaluate arbitrary GitHub expressions; a conditional job is
  outside the supported caller contract and fails static setup.
  The audit has no prerequisite jobs; the publisher depends only on the audit.
- Pinned reusable workflows have callable jobs, and every required input and
  secret has an explicit caller mapping. Secret contents and effective
  publication access are not tested.
- The maintenance workflow is enabled in GitHub Actions.

Each repository is read at one immutable default-branch commit. Shared defaults
reads are cached for the scan. Remote files are never executed or imported, and
symlinks/submodules are rejected for checked files. Files are bounded: inventory
and ordinary configuration files are at most 64 KiB, lockfiles at most 2 MB;
truncated or oversized repository trees cannot receive a passing verdict.

A static pass is not an end-to-end audit run. Installed Node/package-manager
versions, credential contents, effective PR-creation permissions, dependency
health, and project builds are labeled **not tested**. Use a manual maintenance
run to exercise installation, project checks, and publication.

## Change the weekly schedule

This repository checks its inventory every Monday at 03:00 UTC (11:00 in
Singapore). The caller example above uses the same weekly schedule.
To change it, edit the `schedule` block in the host workflow:

```yaml
'on':
  schedule:
  - cron: '0 3 * * 1'
  workflow_dispatch:
```

Remove the `schedule` block to run only manually. Keep `workflow_dispatch` for
on-demand checks. A reusable workflow uses its caller's schedule; it does not
inherit this repository's cron. This schedule is independent of the security
and upgrade cadences in each maintenance installation; do not add the fleet
cron to those installations' maintenance configuration.
