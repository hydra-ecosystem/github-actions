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

All audit kinds use the same `maintenance/dependency-audit` branch and open PR.
Only the project manifest, lockfile, and required pnpm security exceptions enter
that PR. Reports remain in the PR body, run summary, and artifacts; they are not
committed. After a PR is merged or closed, a later qualifying proposal can open
the next PR. Nothing merges automatically.

The title describes dependency updates and confirmed security fixes. For example,
**Node: 9 routine dependency updates, no security fixes** identifies routine work.
If audit evidence is unavailable, the title says **security fixes unconfirmed**.
The report leads with proposed versions and validation results. Routine-only
headlines omit unrelated security counts. Existing blocked findings with unchanged
audit evidence appear as neutral background, with severity and constraints in
expandable details. New findings and evidence that needs review remain visible.

Reports retain unresolved findings, pin decisions, validation failures, changed
locked version sets, and candidate dependency-file SHA-256 hashes. Grouped logs
retain successful and failed command output, including warnings.

| Rerun result | Publisher behavior |
| --- | --- |
| Changed dependency proposal | Updates the existing PR and branch. |
| Same files, report, base branch, validation, and title | No commit, push, or PR edit. Run timestamps and workflow links alone do not count as changes. |
| Same proposal with new report findings | Updates the body without another dependency commit. |
| Same proposal with an outdated title | Corrects the title without rewriting the report or pushing a commit. |
| Retained proposal with failed installation or checks | Publishes or updates a draft and fails the workflow. |
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
are not persisted. A separate serialized reporter has only `issues: write`,
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
or merges the PR. Consumers call both shared workflows at the same full commit
SHA; update both pins together using the [update instructions](../docs/node-maintenance.md#update-or-migrate-an-installation).
