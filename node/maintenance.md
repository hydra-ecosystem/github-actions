# Node dependency maintenance

Use the [setup guide](../docs/node-maintenance.md) to install the shared workflows.
The project owns its dependency versions, build prerequisites, deployment, and
pnpm policy. `.github/node-maintenance.json` selects the project directory, toolchain,
validation script, maintenance options, and schedule.

## Toolchain and validation

Node and the package manager follow the project declarations by default.
Supported combinations use Node 22 (at least 22.13.0) or 24 with npm 11.9.0,
or pnpm 11.20.0/11.21.0. Explicit constraints must agree with declarations.
See [toolchain selection](../docs/node-maintenance.md#toolchain-selection).

For pnpm, the recommended workspace policy uses a ten-day release delay, restricted dependency sources,
and explicit dependency-script approvals. Existing application constraints,
overrides, and exact security exceptions remain project configuration.

`validationScript` defaults to `build` and must name an existing, nonempty project
package script. Put prerequisites and checks in that script. Invalid configuration
or a missing script stops the run before dependency changes.

Integration version 6 supports [live shared defaults](../docs/shared-defaults.md)
from a JSON file in any public GitHub repository, including another project's
configuration. Toolchain, minimum cooldown and maintenance fields are
inherited. Explicit local fields override inherited fields. Each run resolves
references once and retains their full commit identities; source changes apply
to subsequent runs. It also inherits schedule lists, with per-kind local
overrides. Directory, validation script, deployment and credentials
remain local.

`minimumReleaseAgeDays` defaults to ten. For pnpm, preflight requires the standalone
workspace's `minimumReleaseAge` to be an integer at least that many days in
minutes. Stricter workspace settings and existing security exceptions remain
valid. Conflicting toolchain declarations or insufficient cooldown fail loudly;
the workflow does not rewrite them or automatically migrate a project.

## Maintenance behavior

Cron-list/omitted schedules default to `security-and-maintenance`. This attempts
compatible security fixes at all severities before routine stable upgrades, then performs a frozen
installation and the selected project checks. `security-only` skips routine
upgrade selection and resolution.

`maintenance.upgradeScope` limits routine **direct** upgrades to `patch`, `minor`
(including patches), or `major` (the default, including all levels). Restricted
scopes check the actual resolved proposal against the accepted security snapshot.
A violation restores that snapshot. Transitive changes can accompany an allowed
direct upgrade. Security-fix compatibility stays independent of the routine limit.
See [validation and maintenance options](../docs/node-maintenance.md#validation-and-maintenance-options).

The interface supports [separate security and upgrade schedules](../docs/audit-schedules.md).
The recommended shared defaults check security weekly and propose routine
upgrades quarterly. Without shared maintenance settings, a schedule object
defaults to `security-only`; automatic upgrades require an explicit opt-in.
Security-only runs discard dependency changes that
fix no confirmed findings. A manual `audit-kind=upgrades` run can request routine
upgrades without enabling them automatically. Cron lists keep their mode.

The cron-list shorthand defaults to January 30 at 02:00 UTC. Keep it in the project
configuration and mirror it in the caller workflow's cron trigger. The
**Node dependency audit** workflow also supports manual dispatch from the
consumer's default branch.

## Reports and PRs

The workflow opens or updates one PR whose title describes its dependency updates
and confirmed security fixes. For example, **Node: 9 routine dependency
updates, no security fixes** identifies a proposal with no confirmed security fix.
If audit evidence is unavailable, the title says **security fixes unconfirmed**.
Only the project manifest, lockfile, and required pnpm security exceptions enter
that PR. Reports remain in the PR body, run summary, and artifacts; they are not
committed.

All audit kinds share that PR and its stable branch. The publisher updates an
outdated proposal and does not push another commit for an identical proposal.
An outdated title is corrected without another dependency commit or report rewrite.
Publisher jobs are serialized for the repository. The headline gives the proposed
dependency update count and validation status. Routine-only proposals omit unrelated
security counts from the headline; security proposals include confirmed fix counts.
The body leads with the proposed dependency versions and validation results.
Existing findings that all have known blockers and unchanged audit evidence appear
as neutral background below validation. Their severities and constraints are
expandable. Findings that need review or verification retain those distinctions.
Run settings and full audit evidence are also expandable. Existing blocked fixes
have no red status dots; newly reported findings remain visible with red markers.

Reports retain unresolved findings, pin decisions, validation failures, changed
locked version sets, and candidate dependency-file SHA-256 hashes. Grouped logs
retain successful and failed command output, including warnings. Passing project checks
does not prove every vulnerability is resolved.

Failed installation/validation candidates are published as drafts when a candidate can be
retained, and the workflow fails after retaining the report. A successful rerun
leaves an existing draft for human review. A run with no dependency changes leaves
an existing PR branch and its report unchanged; the new report remains in the run
summary and artifacts.

The workflow does not change Dependabot settings or dismiss alerts. If a project
chooses update suppression or alert dismissal, scope it to the selected project's
lockfile and preserve other ecosystems. Verify those repository controls separately.

## Publication and credentials

The caller grants `issues: write` to the shared audit workflow for a
separate, serialized configuration-reporting job. The dependency-execution job
is explicitly read-only. The reporting job consumes only the current run's JSON
status artifact and never checks out project code or receives the App key.
It opens one marked bot-owned configuration issue, updates that issue on repeated
failures, closes it after successful preflight, and reopens the same closed issue
on recurrence. Ordinary dependency/validation failures do not create configuration
issues. Automatic migration remains a possible follow-up, not current behavior.

The audit has read access. The separate publisher can push the maintenance branch
and open its PR. It refuses publication if the default branch's repository inputs
changed since the audit; rerun from the current default branch in that case.

By default, publication uses `GITHUB_TOKEN`. PR workflows triggered by opening or
updating these PRs require approval by a user with write access; see
[GitHub's token behavior](https://docs.github.com/en/actions/concepts/security/github_token).
Normal commit messages keep consumer CI/deployment eligible to run under their
configured triggers and token rules. Nothing is merged automatically.

To avoid the built-in token's PR-workflow approval prompt, configure the
[optional GitHub App](../docs/node-maintenance.md#optional-publish-with-a-github-app).
It needs repository Contents and Pull requests read/write permissions and an
installation on each consumer repository. The publisher mints a short-lived token
limited to that repository and revokes it at job completion. The audit and project checks
never receive the key or publisher token. A configured App that cannot authenticate
fails publication without falling back to `GITHUB_TOKEN`. Neither authentication
mode waits for all consumer CI or merges the PR.

The consumer calls the shared audit and publisher at the same full commit SHA.
Runtime scripts and supporting files stay in the shared repository. Before an
update, compare the installed and proposed public contracts and caller templates,
then change both SHA pins together and verify a manual audit.

For npm, the engine enforces the resolved cooldown during security and routine
resolution using `--before`, and checks publication times when selecting routine
direct upgrades. npm has no release-age exception mechanism here; recent fixes
can remain blocked by the cooldown. pnpm retains its exact security exceptions.
