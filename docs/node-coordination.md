# Separate security and routine-upgrade proposals

The coordinated caller keeps at most one open **security** PR and one open
**upgrades** PR. Each groups all qualifying changes for that channel. A security
run cannot overwrite the upgrades proposal. Upgrade runs still attempt security
fixes first, so the two proposals can overlap.

Both start from the current default branch. Nothing merges automatically.
Existing drafts remain drafts after successful refreshes.

## Install or adopt the coordinated caller

Keep the project configuration and prerequisites from the
[setup guide](node-maintenance.md). This is an opt-in caller change; existing
two-job callers retain their combined-PR behavior.

The coordinated caller is available in `@v1`. Use that tag to receive
compatible updates, or select a reviewed full commit SHA containing
`.github/workflows/node-maintenance.yml` for an immutable installation.
Do not point this caller at an older revision that lacks the workflow.

1. Merge or close any existing PR from `maintenance/dependency-audit`. Review
   that proposal before discarding it. The coordinator refuses to proceed while
   a legacy combined proposal is open; it does not silently replace it.
2. Copy [node/coordinated-caller.yml](../node/coordinated-caller.yml) from the
   selected revision to `.github/workflows/dependency-audit.yml` in your repository.
   Replace `__CENTRAL_REPOSITORY__` with `hydra-ecosystem/github-actions`,
   `__CENTRAL_REVISION__` with the selected revision, and `__DEFAULT_BRANCH__`
   with your actual default branch, such as `main`.
3. Replace `schedule: []` with the unique entries from your resolved schedule.
   For weekly security and quarterly upgrades, use:

   ```yaml
   schedule:
   - cron: '0 2 * * 1'
   - cron: '0 2 1 */3 *'
   ```

   For manual-only routine upgrades, omit the quarterly entry. For no scheduled
   work, remove `schedule`. Keep the manual input and push trigger in all cases.
4. Keep the existing PR-creation permission or optional publisher App configuration.
   Replace the previous caller rather than installing a second scheduled file.
   Keep the `dependency-audit` concurrency group with `cancel-in-progress: false`
   and `queue: max` so a new request does not cancel a pending push check.
5. Merge the caller into the default branch. Dispatch **security**, then
   **upgrades** when wanted. Inspect the run summaries and the resulting proposals.
   A run with no qualifying changes creates no PR.

The configuration remains `.github/node-maintenance.json`; no new policy fields
or branch-protection settings are required. Both caller styles are accepted by
the fleet checker at a revision supporting this interface. Older fleet-checker
releases must be updated before they can recognize a coordinated caller.

## What runs and when

| Trigger | Work |
| --- | --- |
| Security schedule or manual security request | Audit and validate a security proposal; create or update `maintenance/node-security`. |
| Upgrades schedule or manual upgrades request | Audit and validate security fixes plus routine upgrades; create or update `maintenance/node-upgrades`. |
| Matching default-branch push | Validate committed dependencies and refresh whichever channel PRs remain open. Never create a PR from a push refresh. |

The push trigger watches only these paths:

```yaml
paths:
- '**/pnpm-lock.yaml'
- '**/package-lock.json'
- '.github/node-maintenance.json'
```

Stable lockfile patterns follow a project when its directory changes without
requiring the action to rewrite its own caller. A read-only precheck ignores
lockfile changes outside the selected project. A configuration change always
checks the newly selected project. Unrelated source and documentation pushes do
not trigger maintenance. Other project CI remains responsible for those changes.

Every relevant push runs a frozen install, complete audit, and `validationScript`
against committed dependencies, even if no proposal remains open. This validation
does not run dependency repairs or propose upgrades. Failures make the Actions
run fail; details and reports remain in its summary and artifacts. Dependency
failures do not create configuration issues or repair `main` automatically.

## Refreshes and merge order

If security merges first, the routine proposal is regenerated from the new
default branch. If upgrades merge first, an unneeded security proposal closes.
When a complete, successful run finds no remaining changes in a channel, it
comments and closes that PR while preserving its description. Failed validation
or incomplete proposal resolution cannot close it.

Runs are serialized, and each run snapshots the latest default branch when its
plan starts. All its jobs use that commit. Artifacts are isolated by channel;
project code runs without publisher credentials. Publication checks the default
branch again and refuses stale results. A refresh also checks the original PR
identity and open state, so closing or merging it during an audit cannot cause
that refresh to create a replacement.

Pending triggers queue instead of replacing each other. GitHub permits up to
100 pending runs with `queue: max`; beyond that, additional runs are canceled.
Each run checks the latest default branch rather than its older event revision.
A stale run fails rather than claiming its result applies to newer code. Rerun
manually if a newer change did not match the push paths.

There is no mandatory merge gate: someone can merge both PRs before a refresh
finishes. The push run detects installation or project-check failures afterward;
it cannot prevent broken code from landing. For prevention, optionally configure
required PR CI and require branches to be up to date. Those repository rules
affect all PRs targeting that branch. The maintenance report itself is not a
required PR status check.

The [legacy caller](../node/caller.yml) remains supported and does not gain push
triggers or separate proposal channels by moving its workflow tag.
