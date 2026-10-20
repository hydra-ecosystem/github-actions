# Migrate from Docusaurus maintenance

Integration version 6 replaces the Docusaurus-specific interface with standalone
Node maintenance. Use this checklist for an installation pinned to the earlier
workflows. New installations should use the [setup guide](node-maintenance.md).
There is no compatibility layer for the old paths or `buildScript` option.

## Rollout order

The new shared revision removes `defaults/docusaurus.json`. A workflow SHA pin
does not freeze a separate defaults source whose ref is `main`. An old caller
that follows the removed path can therefore fail before its workflow is updated.

For an installation you cannot migrate immediately, pin its old defaults source
to an immutable commit that still contains the old file. Then migrate the caller
and configuration together using the checklist below. If the source path is
already missing, that pin also restores access while you prepare the migration.
Existing installations without shared defaults do not have this source-path issue.

When adopting the new defaults path, choose a ref containing the new file and
review its values. Preserve local policy unless you intend to change it. These
are manual steps; the shared repository does not rewrite consumer installations.

## Consumer checklist

1. Choose `v1` for compatible updates, or a reviewed version-6 commit for immutable pinning. Read `node/contract.json` and use
   `node/caller.yml` from that same revision.
2. Rename `.github/docusaurus.json` to `.github/node-maintenance.json`.
3. Rename `buildScript` to `validationScript` if present. Keep `"build"` for an
   existing Docusaurus production build. Preserve the directory and maintenance
   policy.
4. Change shared defaults paths, if used, from `defaults/docusaurus.json` to
   `defaults/node-maintenance.json`. Use a ref containing the new file. Review
   inherited values and local overrides; following the recommended defaults
   enables quarterly routine upgrades as well as weekly security checks.
5. Replace both caller workflow references with `node-audit.yml` and
   `node-publish.yml` at the same `v1` tag or reviewed full SHA. Use
   `.github/workflows/dependency-audit.yml` as the caller filename. Match its cron
   entries to the resolved [schedule](audit-schedules.md), and include the current
   caller's permissions and manual `audit-kind` input forwarding.
6. If an App is configured, store and forward its variable and secret as
   `NODE_AUDIT_APP_CLIENT_ID` and `NODE_AUDIT_APP_PRIVATE_KEY` before changing the
   caller. Unset values use `GITHUB_TOKEN`; its PR-creation setting must be enabled.
7. [Verify the project locally](node-maintenance.md#1-verify-the-project-locally):
   Node declaration, exact supported `packageManager`, standalone scope, lockfile,
   pnpm policy if used, and validation script. Omitted `toolchain` now follows
   project declarations rather than selecting the old fixed toolchain. Explicit
   or inherited constraints must agree with those declarations.
8. Update references to the renamed configuration in project documentation,
   workflow path filters, and existing checks. Remove an old caller with another
   filename so it cannot schedule duplicate work. Keep deployment behavior intact.
9. Merge the update and dispatch **security** from the default branch. Inspect
   resolved tools, configuration status, frozen installation, project validation,
   and the report. Dispatch **upgrades** separately when routine work is wanted.
10. After resolving configuration failures, inspect and close any old bot-owned
    **Docusaurus configuration** issue. The new reporter uses a new marker and
    does not adopt that issue.

The maintenance branch remains `maintenance/dependency-audit`, so a qualifying
proposal updates an existing open maintenance PR. Its title changes to `Node: …`.
A run with no dependency changes retains the existing PR and report; a successful
rerun leaves an existing draft for human review. No package-manager migration is
required for this interface change.
