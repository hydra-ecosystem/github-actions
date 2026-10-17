# Docusaurus dependency maintenance

Use the [setup guide](../docs/docusaurus.md) to install the shared workflows.
The website owns its dependency versions, build prerequisites, deployment, and
pnpm policy. `.github/docusaurus.json` selects the website directory, toolchain,
build script, maintenance options, and schedule.

## Toolchain and build

When configuration includes `"toolchain": {}`, Node and pnpm follow the project
declarations. Supported combinations are Node 22 (at least 22.13.0) or 24 with
pnpm 11.20.0 or 11.21.0. Explicit toolchain options must agree with the project's
declarations. Existing configurations without a toolchain object retain Node 24
and pnpm 11.21.0. See [toolchain selection](../docs/docusaurus.md#toolchain-selection).

The recommended workspace policy uses a ten-day release delay, restricted dependency sources,
and explicit dependency-script approvals. Existing application constraints,
overrides, and exact security exceptions remain project configuration.

`buildScript` defaults to `build` and must name an existing, nonempty website
package script. Put prerequisites and checks in that script. Invalid configuration
or a missing script stops the run before dependency changes.

Integration version 4 supports [live shared defaults](../docs/shared-defaults.md)
from a JSON file in any public GitHub repository, including another website's
configuration. Only toolchain, minimum cooldown and maintenance fields are
inherited. Explicit local fields override inherited fields. Each run resolves
references once and retains their full commit identities; source changes apply
to subsequent runs. Directory, build script, schedule, deployment and credentials
remain local.

`minimumReleaseAgeDays` defaults to ten. Preflight requires the standalone
workspace's `minimumReleaseAge` to be an integer at least that many days in
minutes. Stricter workspace settings and existing security exceptions remain
valid. Conflicting toolchain declarations or insufficient cooldown fail loudly;
the workflow does not rewrite them or automatically migrate a project.

## Maintenance behavior

The default mode is `security-and-maintenance`. It attempts compatible security
fixes at all severities before routine stable upgrades, then performs a frozen
installation and the selected production build. `security-only` skips routine
upgrade selection and resolution.

`maintenance.upgradeScope` limits routine **direct** upgrades to `patch`, `minor`
(including patches), or `major` (the default, including all levels). Restricted
scopes check the actual resolved proposal against the accepted security snapshot.
A violation restores that snapshot. Transitive changes can accompany an allowed
direct upgrade. Security-fix compatibility stays independent of the routine limit.
See [build and maintenance options](../docs/docusaurus.md#build-and-maintenance-options).

The schedule defaults to January 30 at 02:00 UTC. Keep it in the project
configuration and mirror it in the caller workflow's cron trigger. The
**Docusaurus dependency audit** workflow also supports manual dispatch from the
consumer's default branch.

## Reports and PRs

The workflow opens or updates one PR titled **Docusaurus maintenance: security
audit and dependency upgrades**. Only the website manifest, lockfile, and required
pnpm security exceptions enter that PR. Reports remain in the PR body, run summary,
and artifacts; they are not committed.

Reports retain unresolved findings, pin decisions, validation failures, changed
locked version sets, and candidate dependency-file SHA-256 hashes. Grouped logs
retain successful and failed command output, including warnings. A passing build
does not prove every vulnerability is resolved.

Failed install/build candidates are published as drafts when a candidate can be
retained, and the workflow fails after retaining the report. A successful rerun
leaves an existing draft for human review. A run with no dependency changes leaves
an existing PR branch and its report unchanged; the new report remains in the run
summary and artifacts.

The workflow does not change Dependabot settings or dismiss alerts. If a project
chooses update suppression or alert dismissal, scope it to the selected website's
lockfile and preserve other ecosystems. Verify those repository controls separately.

## Publication and credentials

The version-4 caller grants `issues: write` to the shared audit workflow for a
separate, serialized configuration-reporting job. The dependency-execution job
is explicitly read-only. The reporting job consumes only the current run's JSON
status artifact and never checks out website code or receives the App key.
It opens one marked bot-owned configuration issue, updates that issue on repeated
failures, closes it after successful preflight, and reopens the same closed issue
on recurrence. Ordinary dependency/build failures do not create configuration
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
[optional GitHub App](../docs/docusaurus.md#optional-publish-with-a-github-app).
It needs repository Contents and Pull requests read/write permissions and an
installation on each consumer repository. The publisher mints a short-lived token
limited to that repository and revokes it at job completion. The audit and build
never receive the key or publisher token. A configured App that cannot authenticate
fails publication without falling back to `GITHUB_TOKEN`. Neither authentication
mode waits for all consumer CI or merges the PR.

The consumer calls the shared audit and publisher at the same full commit SHA.
Runtime scripts and supporting files stay in the shared repository. Before an
update, compare the installed and proposed public contracts and caller templates,
then change both SHA pins together and verify a manual audit.
