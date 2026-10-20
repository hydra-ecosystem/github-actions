# Node maintenance behavior

Use the [setup guide](../docs/node-maintenance.md) to install the workflows.
This reference explains how dependency proposals, validation, reports, and
publication work. The project owns its dependency declarations, validation
script, build prerequisites, deployment, and package-manager policy.

## Toolchain and validation

Preflight checks the selected standalone project, declared tools, supported
lockfile, validation script, and release cooldown before dependency changes.
Explicit or inherited toolchain constraints must agree with project declarations.
A mismatch fails the run; it does not rewrite files or migrate the project.
See [supported projects](../docs/node-maintenance.md#supported-projects) and
[toolchain selection](../docs/node-maintenance.md#toolchain-selection).

`validationScript` defaults to `build` and must name an existing, nonempty package
script. Each proposal is validated with a frozen install and that script. Put
required setup, tests, lint, or build commands in the script. Passing it proves
only that those selected checks passed, not that every vulnerability was fixed.

## Maintenance behavior

Security audits attempt compatible fixes at all severities. Security-only runs
retain changes only when before/after audit evidence confirms a security fix;
unrelated changes are discarded. The engine does not force incompatible upgrades
or remove project overrides automatically.

For npm, audits include production, development, optional, and peer dependencies,
even when `.npmrc`, user configuration, or the environment omits a dependency
type. Security repairs explicitly disable force mode, including inherited
`force=true` settings. These overrides apply to audit and repair commands;
project validation still uses the project's install settings.

For pnpm, audit commands override advisory-ignore lists without rewriting them.
This keeps registry evidence complete while preserving project policy. A
`localPatches` entry records a maintainer's assertion about an advisory, with
an optional comment. Affected packages and versions come from audit and lockfile
evidence. It does not prove patch application or security effectiveness, remove
raw findings, or count as a confirmed security fix. See
[declaring local patches](../docs/node-maintenance.md#local-security-patches).

Upgrade audits attempt security fixes first, then routine stable upgrades.
`maintenance.upgradeScope` limits routine **direct** upgrades to `patch`, `minor`
(including patches), or `major` (the default, including both). Restricted scopes
check the actual resolved proposal against the accepted security snapshot. A
violation restores that snapshot. Transitive changes can accompany an allowed
direct upgrade. Security-fix compatibility is independent of the routine limit.

The [scheduling guide](../docs/audit-schedules.md) explains automatic opt-in and
manual audit choices. A manual upgrades run requests routine work once without
changing automatic policy. See [shared defaults](../docs/shared-defaults.md) to
apply policy across several repositories.

## Release cooldown

`minimumReleaseAgeDays` is a nonnegative integer and defaults to ten.

For **pnpm**, the standalone workspace's `minimumReleaseAge` must be an integer
at least that many days in minutes (`days * 1440`). Stricter workspace policy is
preserved. The engine can retain exact security-related release-age exceptions
and reports them. Existing overrides and script approvals remain project policy.

For **npm**, the engine supplies a publication cutoff using `--before` during
security and routine resolution. Routine direct candidates also use release-time
metadata. There is no npm release-age exception mechanism in this version;
recent fixes can remain blocked until the cutoff permits them. Existing locked
versions are not downgraded just because they are younger than the cutoff.

## Reports and PRs

This section describes the legacy two-job caller. The opt-in
[coordinated caller](../docs/node-coordination.md) uses separate security and
upgrade branches and can close obsolete proposals after successful refreshes.

All audit kinds use the same `maintenance/dependency-audit` branch and open PR.
Only the project manifest, lockfile, and required pnpm security exceptions enter
that PR. Reports remain in the PR body, run summary, and artifacts; they are not
committed. After a PR is merged or closed, a later qualifying proposal can open
the next PR. Nothing merges automatically.

The title describes dependency updates and confirmed security fixes. For example,
**Node: 9 routine dependency updates, no security fixes** identifies routine work.
If initial or final audit evidence is unavailable or incomplete, the run fails
and skips publication. The report identifies the cause and retains the separate
frozen-install and project-check results. Its summary and report artifact remain
available after failure; passing project checks do not make the audit complete.
The report leads with a summary and validation results. Confirmed security fixes
appear in a table; the full dependency version list is expandable. Routine-only
headlines omit unrelated security counts. Existing blocked findings with unchanged
audit evidence appear as neutral background, with severity and constraints in
expandable details. New findings and evidence that needs review remain visible.
Security-fix rows link to one primary reported advisory, and count additional
advisories with a pointer to the full audit details. The full audit details
retain every advisory link, including the underlying advisory for an indirectly
affected package. When npm newly lists an unchanged
parent package through an existing advisory, and the affected package versions
and installed paths are unchanged, the report explains this in the details.
This also requires unchanged parent lock records and previously reported
advisory sources through its immediate dependencies.
It does not flag that entry as a newly introduced vulnerability. Other newly
reported findings remain visible for review; an audit difference alone does not
prove that the proposal introduced a vulnerability.

Routine-upgrade proposals also show a table of selected direct upgrades that
remain in the final proposal. Current and proposed values are the declared
`package.json` requirements. Development and optional dependencies are marked.
Transitive changes stay in the expandable full version list. Release-note links
open the GitHub releases page identified by published package metadata. If that
metadata is unavailable or names another host, the row links to the proposed
version's npm package details instead.

Reports retain unresolved findings, pin decisions, validation failures, changed
locked version sets, and candidate dependency-file SHA-256 hashes. Grouped logs
retain successful and failed command output, including warnings.

For declared local patches, reports also retain the advisory, inferred package/version,
optional maintainer comment, and verified official-fix availability in the
`node-audit-local-patches` artifact. A separate reporter updates one bot-owned
**Node local patches: official fixes available** issue when a newer stable fixed
release is verified. It never removes a patch or claims the release is compatible
with project constraints. Missing evidence cannot close that notification.
When a complete check clears the notification, the reporter preserves the issue
body, adds a resolution comment linking to the verification run, and closes it.
Further healthy runs leave the closed issue unchanged.

| Rerun result | Publisher behavior |
| --- | --- |
| Changed dependency proposal | Updates the existing PR and branch. |
| Same files, report, base branch, validation, and title | No commit, push, or PR edit. Run timestamps and workflow links alone do not count as changes. |
| Same proposal with new report findings | Updates the body without another dependency commit. |
| Same proposal with an outdated title | Corrects the title without rewriting the report or pushing a commit. |
| Retained proposal with failed installation or checks | Publishes or updates a draft and fails the workflow. |
| Initial or final security audit unavailable or incomplete | Fails the audit and skips publication; retains the diagnostic summary and report artifact. |
| Successful rerun of an existing draft | Leaves it as a draft for human review. |
| No qualifying dependency changes | Creates no PR and leaves an existing branch and report unchanged. Read the new run summary or artifacts. |

Publisher jobs are serialized per repository. Publication is refused if the
default branch's repository inputs changed since the audit; rerun from the current
default branch in that case.

The workflow does not change Dependabot settings or dismiss alerts. If you choose
to suppress other update PRs or dismiss alerts, scope those repository controls
to the selected project's lockfile and verify them separately.

## Configuration issues

Preflight failures update one marked, bot-owned **Node audit configuration** issue
per repository. Repeated failures update its body without per-run comments.
Successful configuration and runtime checks close it, even if a later dependency
command or validation script fails. A later configuration failure reopens the
same issue. Interrupted preflight does not close it.

Enable repository issues and grant the caller's audit job `issues: write`.
Ambiguous duplicate marked issues, disabled issues, or insufficient permission
produce a reporting error instead of another issue. Dependency or validation
failures do not create configuration issues. No automatic repair PR is generated.

## Publication and credentials

The dependency-execution job has only `contents: read` and checkout credentials
are not persisted. A separate serialized reporter has `issues: write` and
`contents: read` to reject stale coordinated reports,
reads the current run's configuration artifact, and never checks out project code.
The publisher has Contents and Pull requests write access. Only it can push the
maintenance branch and open the PR.

Publication uses `GITHUB_TOKEN` unless an optional App is configured. The App key
and publisher token never reach the dependency job or configuration reporter.
An App token is limited to the consumer repository and revoked at job completion.
A configured App that cannot authenticate stops publication without falling back
to the built-in token. See [credential setup and PR CI behavior](../docs/node-maintenance.md#optional-publish-with-a-github-app).

The workflow does not add CI-skip markers. Consumer CI follows its configured
triggers and token rules. Neither authentication mode waits for additional PR CI
or merges the PR. Consumers call both shared workflows at the same major release
tag, such as `@v1`, or the same full commit SHA. Change both references together
using the [update instructions](../docs/node-maintenance.md#update-or-migrate-an-installation).
